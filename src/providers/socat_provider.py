"""SocatProvider: reenvio de puertos en Linux/Docker via socat (F1-F8, M6).

Alternativa Linux a NetshProvider (Windows). Usa socat en segundo plano:

  socat TCP-LISTEN:<listen_port>,fork,reuseaddr TCP:<ip>:<wsl_port>

- Cada forward es un proceso socat con pidfile en data_dir/pidfiles/socat-<id>.pid
- Sin UAC/admin en Linux (solo necesita permisos para bindear el puerto).
- Funciona dentro y fuera de Docker (con socat instalado).

Si socat no esta instalado, add_forward devuelve error claro.
"""

from __future__ import annotations

import os
import re
import signal
import socket
import subprocess
import time
from pathlib import Path
from typing import Iterable

from src.core.config import Forward
from src.providers.base import CommandResult, PortEntry

_SOCAT_RE = re.compile(r"socat.*TCP-LISTEN:(\d+)")

# Directorio para pidfiles (persistente si hay volumen, temporal si no)
def _pid_dir() -> Path:
    # XDG_DATA_HOME o /data (Docker) o /tmp
    base = os.environ.get("XDG_DATA_HOME") or os.environ.get("XDG_CONFIG_HOME") or "/tmp"
    # Si estamos en Docker con /data montado, usar /data
    if Path("/data").exists():
        base = "/data"
    d = Path(base) / "PortForwarder" / "pidfiles"
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError:
        d = Path("/tmp/port-forwarder-pids")
        d.mkdir(parents=True, exist_ok=True)
    return d


class SocatProvider:
    """Reenvio Linux via socat. Misma interfaz que NetshProvider."""

    def __init__(self, socat_exe: str | None = None) -> None:
        import shutil

        self.socat_exe = socat_exe or shutil.which("socat") or "socat"
        self._pid_dir = _pid_dir()

    # -- helpers -------------------------------------------------------------

    def _pid_file(self, fid: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", fid)
        return self._pid_dir / f"socat-{safe}.pid"

    def _is_running(self, pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False

    def _find_socat_pids(self, listen_port: int | None = None) -> list[int]:
        """PIDs de socat escuchando en listen_port (o todos si None)."""
        pids: list[int] = []
        # Buscar pidfiles primero (rapido y fiable)
        for pf in self._pid_dir.glob("socat-*.pid"):
            try:
                pid = int(pf.read_text().strip())
                if not self._is_running(pid):
                    pf.unlink(missing_ok=True)
                    continue
                if listen_port is not None:
                    # Verificar que este pid escucha en el puerto
                    if not self._pid_listens_on(pid, listen_port):
                        continue
                pids.append(pid)
            except (ValueError, OSError):
                continue
        return pids

    def _pid_listens_on(self, pid: int, port: int) -> bool:
        """Comprueba si el proceso pid escucha en el puerto (via /proc o ss)."""
        # Intentar via /proc/net/tcp si existe
        try:
            import shutil

            if shutil.which("ss"):
                proc = subprocess.run(
                    ["ss", "-tlnp"], capture_output=True, text=True, timeout=5
                )
                for line in proc.stdout.splitlines():
                    if f":{port} " in line and str(pid) in line:
                        return True
        except Exception:
            pass
        # Fallback: asumir que si el pid existe y hay pidfile para el puerto, es el correcto
        return True

    # -- operaciones ---------------------------------------------------------

    def add_forward(self, forward: Forward, ip: str) -> CommandResult:
        """Lanza socat en segundo plano. ip se obtiene al momento (8.2)."""
        if not ip:
            return CommandResult(
                ok=False,
                error=f"IP vacia para '{forward.wsl_distro or forward.id}'",
            )
        # Verificar socat instalado
        import shutil

        if not shutil.which(self.socat_exe) and not Path(self.socat_exe).exists():
            return CommandResult(
                ok=False,
                error="socat no instalado. Instala con: apt-get install socat",
            )
        # Si ya existe un forward en ese puerto, eliminarlo primero
        existing = self.list_forwards()
        for f in existing:
            if f.listen_port == forward.listen_port:
                self.remove_forward(f)

        pid_file = self._pid_file(forward.id)
        # socat TCP-LISTEN:port,fork,reuseaddr TCP:ip:wsl_port
        cmd = [
            self.socat_exe,
            f"TCP-LISTEN:{forward.listen_port},fork,reuseaddr",
            f"TCP:{ip}:{forward.wsl_port}",
        ]
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            # Esperar un momento y verificar que sigue vivo (bind ok)
            time.sleep(0.5)
            if proc.poll() is not None and proc.returncode != 0:
                return CommandResult(
                    ok=False,
                    error=f"socat fallo (exit {proc.returncode}): no pudo bindear :{forward.listen_port}",
                )
            # Guardar pid
            pid_file.write_text(str(proc.pid))
            return CommandResult(ok=True, output=f"forward {forward.id} socat pid {proc.pid} -> {ip}")
        except FileNotFoundError as e:
            return CommandResult(ok=False, error=f"socat no encontrado: {e}")
        except OSError as e:
            return CommandResult(ok=False, error=str(e))

    def remove_forward(self, forward: Forward) -> CommandResult:
        pid_file = self._pid_file(forward.id)
        # Intentar matar por pidfile
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
                try:
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(0.3)
                    if self._is_running(pid):
                        os.kill(pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    pass
            except (ValueError, OSError):
                pass
            try:
                pid_file.unlink(missing_ok=True)
            except OSError:
                pass
            return CommandResult(ok=True, output=f"forward {forward.id} socat detenido")
        # Sin pidfile, buscar por puerto
        pids = self._find_socat_pids(forward.listen_port)
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        return CommandResult(ok=True, output=f"forward {forward.id} limpiado")

    def list_forwards(self) -> list[Forward]:
        """Lista forwards activos (pidfiles validos)."""
        forwards: list[Forward] = []
        for pf in self._pid_dir.glob("socat-*.pid"):
            try:
                pid = int(pf.read_text().strip())
            except (ValueError, OSError):
                continue
            if not self._is_running(pid):
                try:
                    pf.unlink(missing_ok=True)
                except OSError:
                    pass
                continue
            # fid desde nombre del pidfile
            fid = pf.stem.removeprefix("socat-")
            # Intentar extraer puerto del cmdline via /proc
            listen_port = 0
            listen_address = "0.0.0.0"
            try:
                cmdline = Path(f"/proc/{pid}/cmdline").read_text(errors="replace")
                # cmdline es \x00 separado: socat\x00TCP-LISTEN:8080,fork...\x00TCP:1.2.3.4:80\x00
                parts = cmdline.split("\x00")
                for p in parts:
                    if "TCP-LISTEN:" in p:
                        m = re.search(r"TCP-LISTEN:(\d+)", p)
                        if m:
                            listen_port = int(m.group(1))
                    if "TCP:" in p and "TCP-LISTEN" not in p:
                        m = re.search(r"TCP:[^:]+:(\d+)", p)
                        if m:
                            wsl_port = int(m.group(1))
                        # ip no trivial de extraer del cmdline socat
            except OSError:
                pass
            if listen_port:
                try:
                    forwards.append(
                        Forward(
                            id=fid,
                            listen_address=listen_address,
                            listen_port=listen_port,
                            wsl_distro="",
                            wsl_port=listen_port,  # aproximacion
                            auto_apply=False,
                        )
                    )
                except ValueError:
                    continue
        return forwards

    def clear_all(self) -> list[CommandResult]:
        """Detiene todos los socat forwards."""
        results: list[CommandResult] = []
        for f in self.list_forwards():
            results.append(self.remove_forward(f))
        # Limpiar pidfiles huerfanos
        for pf in self._pid_dir.glob("socat-*.pid"):
            try:
                pid = int(pf.read_text().strip())
                if not self._is_running(pid):
                    pf.unlink(missing_ok=True)
            except (ValueError, OSError):
                try:
                    pf.unlink(missing_ok=True)
                except OSError:
                    pass
        # Asegurar que no quedan socat huerfanos sin pidfile
        try:
            subprocess.run(
                ["pkill", "-f", "socat.*TCP-LISTEN"], capture_output=True, timeout=5
            )
        except Exception:
            pass
        results.append(CommandResult(ok=True, output="socat forwards limpiados"))
        return results

    def detect_conflicts(self, port: int) -> list[int]:
        """PIDs con listeners activos en :port (ss o netstat)."""
        try:
            # Preferir ss (Linux moderno)
            proc = subprocess.run(
                ["ss", "-tlnp"], capture_output=True, text=True, timeout=10
            )
            output = proc.stdout
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc = subprocess.run(
                    ["netstat", "-tlnp"], capture_output=True, text=True, timeout=10
                )
                output = proc.stdout
            except (OSError, subprocess.TimeoutExpired):
                return []
        pids: set[int] = set()
        for line in output.splitlines():
            if f":{port} " not in line and f":{port}\t" not in line:
                continue
            if "LISTEN" not in line:
                continue
            m = re.search(r"pid=(\d+)", line)
            if not m:
                m = re.search(r"(\d+)\s*$", line.strip())
            if m:
                try:
                    pids.add(int(m.group(1)))
                except ValueError:
                    pass
        return sorted(pids)

    def test_connection(self, port: int, timeout: float = 3.0) -> bool:
        """Test TCP a 127.0.0.1:port — no requiere privilegios."""
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=timeout):
                return True
        except OSError:
            return False

    def port_map(self) -> list[PortEntry]:
        """Mapa de puertos real (M6): lo que socat declara hoy."""
        from src.providers.base import PortEntry

        return [
            PortEntry(
                listen_address=f.listen_address,
                listen_port=f.listen_port,
                connect_address="",
                connect_port=f.wsl_port,
            )
            for f in self.list_forwards()
        ]

    def declared_forwards(self, declared: Iterable[Forward]) -> list[PortEntry]:
        """Cruza el estado real (socat) con la config deseada (drift, M6)."""
        from src.providers.base import PortEntry

        real = {f.listen_port: f for f in self.list_forwards()}
        declared_by_port = {f.listen_port: f for f in declared}
        entries: list[PortEntry] = []

        for port, rf in real.items():
            df = declared_by_port.get(port)
            ok = df is not None and df.wsl_port == rf.wsl_port
            entries.append(PortEntry(
                listen_address=rf.listen_address,
                listen_port=port,
                connect_address="",
                connect_port=rf.wsl_port,
                declared=df is not None,
                forward_id=df.id if df else None,
                state="ok" if ok else ("extra" if df is None else "broken"),
            ))
        for port, df in declared_by_port.items():
            if port not in real:
                entries.append(PortEntry(
                    listen_address=df.listen_address,
                    listen_port=port,
                    connect_address="",
                    connect_port=df.wsl_port,
                    declared=True,
                    forward_id=df.id,
                    state="missing",
                ))
        entries.sort(key=lambda e: e.listen_port)
        return entries
