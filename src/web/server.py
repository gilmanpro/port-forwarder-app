"""Servidor del panel web (seccion 10.5) + API JSON estilo /api/v1.

Endpoints:
  GET  /                      -> dashboard HTML
  GET  /api/v1/state          -> estado completo (supervisor + metricas)
  GET  /api/v1/events         -> journal reciente (SQLite)
  GET  /api/v1/alerts         -> alertas abiertas/recientes
  GET  /api/v1/health         -> health check (M3)
  GET  /api/v1/vps            -> VPS registrados
  GET  /api/v1/distros        -> lista distros WSL
  GET  /api/v1/distro/<name>/export -> exportar distro (descarga tar)
  POST /api/v1/distro/import  -> importar distro (subida tar)
  POST /api/v1/forwards/apply -> reaplicar forwards (F2)
  POST /api/v1/forwards/clear -> limpiar todos (F3, destructivo)
  POST /api/v1/forwards/add   -> crear forward (F1)
  POST /api/v1/forwards/remove/<id> -> eliminar forward
  POST /api/v1/tunnels/<id>/start|stop|restart
  POST /api/v1/tunnels/add    -> crear tunnel (T1)
  POST /api/v1/tunnels/remove/<id> -> eliminar tunnel
  POST /api/v1/vps/add        -> registrar VPS (T3)
  POST /api/v1/vps/remove/<id> -> eliminar VPS
  POST /api/v1/maintenance/on|off

Auth OBLIGATORIA: el panel exige 'Authorization: Bearer <token>' en /api/*
(el token se configura en Ajustes de la GUI o con 'secrets set web_panel_token').
Sin token el panel no arranca (lo controla el supervisor / 'web start').
"""

from __future__ import annotations

import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler
from typing import Any
from urllib.parse import parse_qs, urlparse

from src.core.config import Bind, ConfigStore, Forward, HealthCheck, Tunnel, TunnelHealthGate, Vps
from src.core.event_bus import bus
from src.core.metrics_store import MetricsStore
from src.core.supervisor import Supervisor
from src.utils.http_server import BoundedThreadingHTTPServer

log = logging.getLogger("port-forwarder.web")

DEFAULT_PORT = 8794
DEFAULT_BIND = "127.0.0.1"


def _json(data: Any) -> tuple[bytes, int]:
    body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
    return body, 200


class PanelHandler(BaseHTTPRequestHandler):
    panel: "WebPanel"  # inyectado por WebPanel.start (clase dinámica)

    # -- helpers -------------------------------------------------------------

    def _send(self, body: bytes | str, status: int = 200, ctype: str = "application/json") -> None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # Defensa H2/M1: headers de seguridad en todas las respuestas.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        self.end_headers()
        if body:
            self.wfile.write(body)

    # -- CSRF (H1): las mutaciones exigen Origin/Referer del mismo host. ----

    def _same_origin(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
        except ValueError:
            return False
        origin_netloc = parsed.netloc
        host = self.headers.get("Host", "")
        if not origin_netloc or not host:
            return False
        return origin_netloc.lower() == host.lower()

    def _csrf_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if origin:
            return self._same_origin(origin)
        referer = self.headers.get("Referer")
        if referer:
            return self._same_origin(referer)
        # Sin Origin ni Referer no es un navegador (curl/script/API):
        # no hay riesgo de CSRF, permitir (la auth Bearer sigue obligatoria).
        return True

    def _authed(self) -> bool:
        token = self.panel.token
        if not token:
            return True
        auth = self.headers.get("Authorization", "")
        return auth == f"Bearer {token}"

    def _deny(self, status: int = 401, msg: str = "no autorizado") -> None:
        self._send(json.dumps({"ok": False, "error": msg},
                              ensure_ascii=False).encode("utf-8"), status)

    def log_message(self, fmt: str, *args: Any) -> None:
        log.debug(fmt, *args)

    # -- rutas ----------------------------------------------------------------

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/":
            self._send(self.panel.dashboard_html, 200, "text/html")
            return
        if not path.startswith("/api/"):
            self._deny(404, "no encontrado")
            return
        if not self._authed():
            self._deny()
            return
        try:
            if path == "/api/v1/state":
                self._send(*_json(self.panel.state()))
            elif path == "/api/v1/events":
                limit = int(parse_qs(parsed.query).get("limit", ["50"])[0])
                self._send(*_json(self.panel.events(limit)))
            elif path == "/api/v1/alerts":
                self._send(*_json(self.panel.alerts()))
            elif path == "/api/v1/health":
                self._send(*_json(self.panel.health()))
            elif path == "/api/v1/vps":
                self._send(*_json(self.panel.vps_list()))
            elif path == "/api/v1/distros":
                self._send(*_json(self.panel.distros_list()))
            elif path.startswith("/api/v1/distro/") and path.endswith("/export"):
                parts = [p for p in path.split("/") if p]
                if len(parts) == 5 and parts[3] != "import":
                    self._handle_export(parts[3])
                else:
                    self._deny(404, "no encontrado")
            else:
                self._deny(404, "no encontrado")
        except Exception as e:
            log.exception("GET %s fallo", path)
            body, _ = _json({"ok": False, "error": str(e)})
            self._send(body, 500)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if not path.startswith("/api/"):
            self._deny(404, "no encontrado")
            return
        if not self._csrf_ok():
            self._deny(403, "origen no permitido (CSRF)")
            return
        if not self._authed():
            self._deny()
            return

        # Import distro (multipart upload)
        if path == "/api/v1/distro/import":
            self._handle_import()
            return

        body: dict[str, Any] = {}
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 0:
                raw = self.rfile.read(length)
                if raw.strip():
                    body = json.loads(raw.decode("utf-8"))
        except (ValueError, json.JSONDecodeError):
            self._deny(400, "body JSON invalido")
            return
        try:
            result = self.panel.action(path, body)
            self._send(*_json(result))
        except Exception as e:
            log.exception("POST %s fallo", path)
            body, _ = _json({"ok": False, "error": str(e)})
            self._send(body, 500)

    def _handle_export(self, name: str) -> None:
        """Stream wsl --export as a tar download."""
        import subprocess
        import tempfile
        import os

        # Pre-check: si WSL no responde en 3s, devolver error rapido
        try:
            probe = subprocess.run(
                ["wsl.exe", "--list", "--verbose"],
                capture_output=True, timeout=3,
                creationflags=0x08000000,
            )
            if probe.returncode != 0:
                self._send(*_json({"ok": False, "error": "WSL no responde"}))
                return
        except subprocess.TimeoutExpired:
            self._send(*_json({"ok": False, "error": "WSL no responde (timeout)"}))
            return
        except Exception as e:
            self._send(*_json({"ok": False, "error": str(e)}))
            return

        tmp = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
        tmp_path = tmp.name
        tmp.close()

        try:
            proc = subprocess.run(
                ["wsl.exe", "--export", name, tmp_path],
                capture_output=True, timeout=600,
                creationflags=0x08000000
            )
            if proc.returncode != 0:
                error = proc.stderr.decode("utf-8", errors="replace").strip()
                if not error:
                    error = proc.stdout.decode("utf-8", errors="replace").strip()
                self._send(*_json({"ok": False, "error": f"export fallo: {error}"}))
                return

            file_size = os.path.getsize(tmp_path)
            self.send_response(200)
            self.send_header("Content-Type", "application/x-tar")
            self.send_header("Content-Disposition", f'attachment; filename="{name}.tar"')
            self.send_header("Content-Length", str(file_size))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

            with open(tmp_path, "rb") as f:
                while chunk := f.read(65536):
                    self.wfile.write(chunk)

        except subprocess.TimeoutExpired:
            self._send(*_json({"ok": False, "error": "export timeout (600s)"}))
        except Exception as e:
            self._send(*_json({"ok": False, "error": str(e)}))
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def _handle_import(self) -> None:
        """Handle multipart tar upload and wsl --import."""
        import subprocess
        import tempfile
        import os

        # Pre-check: si WSL no responde en 3s, devolver error rapido
        try:
            probe = subprocess.run(
                ["wsl.exe", "--list", "--verbose"],
                capture_output=True, timeout=3,
                creationflags=0x08000000,
            )
            if probe.returncode != 0:
                self._send(*_json({"ok": False, "error": "WSL no responde"}))
                return
        except subprocess.TimeoutExpired:
            self._send(*_json({"ok": False, "error": "WSL no responde (timeout)"}))
            return
        except Exception as e:
            self._send(*_json({"ok": False, "error": str(e)}))
            return

        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self._send(*_json({"ok": False, "error": "Content-Type debe ser multipart/form-data"}))
            return

        boundary = None
        for part in content_type.split(";"):
            part = part.strip()
            if part.startswith("boundary="):
                boundary = part[9:].strip().strip('"')
                break
        if not boundary:
            self._send(*_json({"ok": False, "error": "boundary no encontrado"}))
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            self._send(*_json({"ok": False, "error": "Content-Length requerido"}))
            return
        if content_length > 10 * 1024 * 1024 * 1024:  # 10GB max
            self._send(*_json({"ok": False, "error": "archivo demasiado grande (max 10GB)"}))
            return

        raw = self.rfile.read(content_length)
        boundary_bytes = f"--{boundary}".encode()
        parts = raw.split(boundary_bytes)

        name = None
        install_dir = None
        tar_data = None

        for part in parts:
            if b"Content-Disposition" not in part:
                continue
            header_end = part.find(b"\r\n\r\n")
            if header_end == -1:
                continue
            headers_raw = part[:header_end].decode("utf-8", errors="replace")
            body_raw = part[header_end + 4:]
            if body_raw.endswith(b"\r\n"):
                body_raw = body_raw[:-2]

            if 'name="name"' in headers_raw:
                name = body_raw.decode("utf-8", errors="replace").strip()
            elif 'name="install_dir"' in headers_raw:
                install_dir = body_raw.decode("utf-8", errors="replace").strip()
            elif 'name="file"' in headers_raw:
                tar_data = body_raw

        if not name:
            self._send(*_json({"ok": False, "error": "name requerido"}))
            return
        if not tar_data:
            self._send(*_json({"ok": False, "error": "file (tar) requerido"}))
            return
        if not install_dir:
            install_dir = os.path.join(os.environ.get("LOCALAPPDATA", ""), "WSL", name)

        tmp = tempfile.NamedTemporaryFile(suffix=".tar", delete=False)
        tmp_path = tmp.name
        tmp.write(tar_data)
        tmp.close()

        try:
            proc = subprocess.run(
                ["wsl.exe", "--import", name, install_dir, tmp_path],
                capture_output=True, timeout=600,
                creationflags=0x08000000
            )
            if proc.returncode != 0:
                error = proc.stderr.decode("utf-8", errors="replace").strip()
                if not error:
                    error = proc.stdout.decode("utf-8", errors="replace").strip()
                self._send(*_json({"ok": False, "error": f"import fallo: {error}"}))
                return

            self._send(*_json({"ok": True, "message": f"distro '{name}' importada"}))

        except subprocess.TimeoutExpired:
            self._send(*_json({"ok": False, "error": "import timeout (600s)"}))
        except Exception as e:
            self._send(*_json({"ok": False, "error": str(e)}))
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


class WebPanel:
    """Servidor web + supervisor asociado (mismos providers que CLI/GUI)."""

    def __init__(
        self,
        supervisor: Supervisor,
        port: int = DEFAULT_PORT,
        bind: str = DEFAULT_BIND,
        token: str = "",
        metrics: MetricsStore | None = None,
        dashboard_html: str | None = None,
    ) -> None:
        self.supervisor = supervisor
        self.port = port
        self.bind = bind
        self.token = token
        self.metrics = metrics or supervisor.metrics
        self.dashboard_html = dashboard_html or DASHBOARD_HTML
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.running = False

    # -- ciclo de vida ---------------------------------------------------------

    def start(self) -> None:
        if self.running:
            return
        handler = type("PanelHandlerT", (PanelHandler,), {"panel": self})
        try:
            self._httpd = BoundedThreadingHTTPServer((self.bind, self.port), handler)
        except OSError as e:
            raise RuntimeError(
                f"no se pudo abrir {self.bind}:{self.port} ({e}). "
                "Revisa que el puerto este libre o cambia ui.web_panel_port."
            ) from e
        if self.port == 0:  # puerto efimero (tests)
            self.port = self._httpd.server_address[1]
        self.running = True
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="web-panel", daemon=True
        )
        self._thread.start()
        log.info("panel web en http://%s:%s", self.bind, self.port)

    def stop(self) -> None:
        self.running = False
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        log.info("panel web detenido")

    def status(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "url": f"http://{self.bind}:{self.port}",
            "bind": self.bind,
            "port": self.port,
            "auth_required": bool(self.token),
            "supervisor_running": self.supervisor.running,
        }

    # -- datos -------------------------------------------------------------------

    @staticmethod
    def _parse_bind(text: Any, what: str) -> Bind:
        if not isinstance(text, str) or ":" not in text:
            raise ValueError(f"{what} debe ser host:puerto (ej. 0.0.0.0:80)")
        host, port = text.rsplit(":", 1)
        try:
            port = int(port)
        except ValueError:
            raise ValueError(f"{what}: puerto invalido '{port}'")
        if not host:
            raise ValueError(f"{what}: falta el host")
        return Bind(host=host, port=port)

    def state(self) -> dict[str, Any]:
        st = self.supervisor.status()
        uptime: dict[str, Any] = {}
        traffic: dict[str, Any] = {}
        for t in st["tunnels"]:
            uptime[t["id"]] = self.metrics.tunnel_uptime_summary(t["id"])
            tun = self.supervisor.store.get_tunnel(t["id"])
            if tun is not None:
                try:
                    tf = self.supervisor.ssh.traffic_snapshot(tun)
                    if tf:
                        traffic[t["id"]] = tf
                except Exception:  # noqa: BLE001
                    pass
        return {
            "ok": True,
            "status": st,
            "uptime": uptime,
            "traffic": traffic,
            "alerts": self.metrics.list_alerts(state="open", limit=20),
            "ts": time.time(),
        }

    def events(self, limit: int = 50) -> dict[str, Any]:
        return {"ok": True, "events": self.metrics.list_events(limit=limit)}

    def alerts(self) -> dict[str, Any]:
        return {"ok": True, "alerts": self.metrics.list_alerts(limit=50)}

    def health(self) -> dict[str, Any]:
        from src.providers.ssh_tunnel_provider import SshTunnelProvider

        store = self.supervisor.store
        ssh = SshTunnelProvider(ssh_exe=store.cfg.windows.ssh_exe or None,
                                autossh_exe=store.cfg.windows.autossh_exe or None)
        data: dict[str, Any] = {"forwards": [], "tunnels": [], "vps": []}
        for f in store.cfg.forwards:
            ok = self.supervisor.netsh.test_connection(f.listen_port, 2.0)
            data["forwards"].append({"id": f.id, "listen_port": f.listen_port,
                                     "reachable": ok})
        for t in store.cfg.tunnels:
            alive = self.supervisor.ssh.is_alive(t)
            data["tunnels"].append({"id": t.id, "alive": alive})
            vps = store.get_vps(t.vps_id)
            if vps:
                data["vps"].append({"id": vps.id, "host": vps.host,
                                    "latency_ms": ssh.latency(t, vps)})
        return {"ok": True, "health": data}

    def vps_list(self) -> dict[str, Any]:
        return {
            "ok": True,
            "vps": [
                {"id": v.id, "host": v.host, "user": v.user, "port": v.port}
                for v in self.supervisor.store.cfg.vps_list
            ],
        }

    def distros_list(self) -> dict[str, Any]:
        """Lista distros WSL via wsl.exe -l -v (timeout corto, sin IP: no cuelga)."""
        distros = []
        try:
            import subprocess
            proc = subprocess.run(
                ["wsl.exe", "--list", "--verbose"],
                capture_output=True, text=True, timeout=3,
                creationflags=0x08000000,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if not line or "NAME" in line.upper() or "---" in line:
                        continue
                    parts = [p for p in line.split() if p]
                    if len(parts) >= 3:
                        name, state, ver = parts[0], parts[1], parts[2]
                    elif len(parts) == 2:
                        name, state, ver = parts[0], parts[1], "?"
                    else:
                        continue
                    distros.append({
                        "name": name, "state": state,
                        "version": ver, "ip": None,
                        "running": state.lower() == "running",
                    })
        except Exception:
            pass
        return {"ok": True, "distros": distros}

    # -- acciones -------------------------------------------------------------------

    def action(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        """Ejecuta una accion POST; registra en SQLite (journal, 13.2)."""
        body = body or {}
        store = self.supervisor.store
        parts = [p for p in path.split("/") if p]
        if parts[:3] == ["api", "v1", "forwards"]:
            if len(parts) == 3 or parts[3] == "apply":
                self.supervisor.run_once()
                return {"ok": True, "message": "forwards reaplicados"}
            if parts[3] == "clear":
                results = self.supervisor.netsh.clear_all()
                failed = [r for r in results if not r.ok]
                return {"ok": not failed,
                        "message": "forwards limpiados" if not failed
                        else "hubo fallos al limpiar"}
            if parts[3] == "add":
                fwd = Forward(
                    id=str(body.get("id", "")).strip(),
                    listen_port=int(body.get("listen_port") or 0),
                    wsl_distro=str(body.get("distro", "")).strip(),
                    wsl_port=int(body.get("wsl_port") or 0),
                    protocol=str(body.get("protocol", "tcp")),
                    auto_apply=bool(body.get("auto_apply", True)),
                    health_check=HealthCheck(enabled=bool(body.get("health_check", True))),
                )
                if not fwd.id or fwd.listen_port <= 0 or fwd.wsl_port <= 0:
                    return {"ok": False, "error": "id, listen_port y wsl_port son obligatorios"}
                store.add_forward(fwd)
                self.metrics.record_event("web_forward_add", forward_id=fwd.id)
                return {"ok": True, "message": f"forward '{fwd.id}' creado"}
            if parts[3] == "remove" and len(parts) == 5:
                store.remove_forward(parts[4])
                self.metrics.record_event("web_forward_remove", forward_id=parts[4])
                return {"ok": True, "message": f"forward '{parts[4]}' eliminado"}
        if parts[:3] == ["api", "v1", "tunnels"]:
            if len(parts) == 4 and parts[3] == "add":
                remotes = body.get("remotes") or []
                if isinstance(remotes, str):
                    remotes = [r.strip() for r in remotes.split(",") if r.strip()]
                if not isinstance(remotes, list) or not remotes:
                    return {"ok": False, "error": "remotes requerido (lista host:puerto)"}
                tun = Tunnel(
                    id=str(body.get("id", "")).strip(),
                    vps_id=str(body.get("vps_id", "")).strip(),
                    local_bind=self._parse_bind(body.get("local"), "local"),
                    remote_binds=[self._parse_bind(r, "remote") for r in remotes],
                    auto_start=bool(body.get("auto_start", True)),
                    health_gate=TunnelHealthGate(enabled=bool(body.get("health_gate", True))),
                )
                if not tun.id or not tun.vps_id:
                    return {"ok": False, "error": "id y vps_id son obligatorios"}
                if store.get_vps(tun.vps_id) is None:
                    return {"ok": False, "error": f"vps '{tun.vps_id}' no existe"}
                store.add_tunnel(tun)
                self.metrics.record_event("web_tunnel_add", tunnel_id=tun.id)
                if tun.auto_start:
                    try:
                        self.supervisor.ssh.start(tun, store.get_vps(tun.vps_id))
                    except Exception as e:  # noqa: BLE001
                        return {"ok": True, "warning": str(e),
                                "message": f"tunnel '{tun.id}' creado pero no arranco"}
                return {"ok": True, "message": f"tunnel '{tun.id}' creado"}
            if len(parts) == 5 and parts[3] == "remove":
                tun = store.get_tunnel(parts[4])
                if tun is None:
                    return {"ok": False, "error": f"tunnel '{parts[4]}' no existe"}
                try:
                    self.supervisor.ssh.stop(tun)
                except Exception:  # noqa: BLE001
                    pass
                store.remove_tunnel(parts[4])
                self.metrics.record_event("web_tunnel_remove", tunnel_id=parts[4])
                return {"ok": True, "message": f"tunnel '{parts[4]}' eliminado"}
            if len(parts) == 5:
                tun_id, op = parts[3], parts[4]
                tun = store.get_tunnel(tun_id)
                if not tun:
                    return {"ok": False, "error": f"tunnel '{tun_id}' no existe"}
                vps = store.get_vps(tun.vps_id)
                if op == "start":
                    if not self.supervisor.ssh.is_alive(tun):
                        self.supervisor.ssh.start(tun, vps)
                    return {"ok": True, "message": f"{tun_id} iniciado"}
                if op == "stop":
                    self.supervisor.ssh.stop(tun)
                    return {"ok": True, "message": f"{tun_id} detenido"}
                if op == "restart":
                    self.supervisor.ssh.restart(tun, vps)
                    return {"ok": True, "message": f"{tun_id} reiniciado"}
        if parts[:3] == ["api", "v1", "vps"]:
            if len(parts) == 4 and parts[3] == "add":
                vps = Vps(
                    id=str(body.get("id", "")).strip(),
                    host=str(body.get("host", "")).strip(),
                    user=str(body.get("user", "")).strip(),
                    port=int(body.get("port") or 22),
                    identity_file=str(body.get("identity_file", "")).strip(),
                    password=str(body.get("password", "")),
                )
                if not vps.id or not vps.host or not vps.user:
                    return {"ok": False, "error": "id, host y user son obligatorios"}
                store.add_vps(vps)
                self.metrics.record_event("web_vps_add", vps=vps.id)
                return {"ok": True, "message": f"vps '{vps.id}' registrado"}
            if len(parts) == 5 and parts[3] == "remove":
                store.remove_vps(parts[4])
                self.metrics.record_event("web_vps_remove", vps=parts[4])
                return {"ok": True, "message": f"vps '{parts[4]}' eliminado"}
        if parts[:3] == ["api", "v1", "maintenance"] and len(parts) == 4:
            mode = parts[3]
            if mode == "on":
                store.cfg.maintenance.active = True
                store.save()
                return {"ok": True, "message": "mantenimiento ON"}
            if mode == "off":
                store.cfg.maintenance.active = False
                store.save()
                self.supervisor.run_once()
                return {"ok": True, "message": "mantenimiento OFF"}
        return {"ok": False, "error": f"accion desconocida: {path}"}


def start_panel(
    supervisor: Supervisor,
    port: int = DEFAULT_PORT,
    bind: str = DEFAULT_BIND,
    token: str = "",
) -> WebPanel:
    """Helper: construye y arranca el panel."""
    panel = WebPanel(supervisor, port=port, bind=bind, token=token)
    panel.start()
    return panel


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Port Forwarding Manager</title>
<style>
  :root { --bg:#0f1419; --card:#1a212b; --line:#2b3644; --text:#d7e0ea;
          --muted:#7d8ca1; --ok:#34c759; --warn:#ff9f0a; --err:#ff453a; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:system-ui,Segoe UI,sans-serif; background:var(--bg);
         color:var(--text); padding:16px; }
  h1 { font-size:20px; margin:0 0 4px; }
  .sub { color:var(--muted); font-size:13px; margin-bottom:16px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(340px,1fr));
          gap:14px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px;
          padding:14px; }
  .card h2 { font-size:14px; margin:0 0 10px; color:var(--muted);
             text-transform:uppercase; letter-spacing:.06em; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); }
  th { color:var(--muted); font-weight:600; }
  .badge { display:inline-block; padding:2px 8px; border-radius:20px; font-size:12px; }
  .ok { background:#12351f; color:var(--ok); }
  .warn { background:#3a2d0f; color:var(--warn); }
  .err { background:#3a1513; color:var(--err); }
  .muted { color:var(--muted); }
  button { background:#2563eb; border:0; color:#fff; padding:6px 12px;
           border-radius:6px; cursor:pointer; font-size:13px; }
  button:hover { filter:brightness(1.15); }
  button.danger { background:#b91c1c; }
  input, select { padding:5px 8px; border-radius:6px; border:1px solid var(--line);
                  background:var(--bg); color:var(--text); font-size:12px; }
  .form { display:flex; gap:6px; flex-wrap:wrap; margin-top:8px; align-items:center; }
  .form label { color:var(--muted); font-size:12px; }
  .actions { display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; }
  .uptime { height:6px; background:var(--line); border-radius:3px; overflow:hidden; }
  .uptime > i { display:block; height:100%; background:var(--ok); }
  #events { font-family:ui-monospace,Consolas,monospace; font-size:12px;
            max-height:220px; overflow-y:auto; }
  #events div { padding:3px 0; border-bottom:1px dashed var(--line); }
  #toast { position:fixed; bottom:16px; right:16px; background:#12335f; padding:10px 14px;
           border-radius:8px; font-size:13px; opacity:0; transition:opacity .3s; }
</style>
</head>
<body>
<h1>Port Forwarding Manager</h1>
<div class="sub" id="sub">conectando…</div>

<div class="grid">
  <div class="card">
    <h2>Forwards (Windows → WSL)</h2>
    <table><thead><tr><th>ID</th><th>Puerto</th><th>Distro</th><th>WSL</th><th>Estado</th></tr></thead>
    <tbody id="fwd-body"></tbody></table>
    <div class="actions">
      <button onclick="post('/api/v1/forwards/apply')">Reaplicar todos</button>
      <button class="danger" onclick="if(confirm('Limpiar TODOS los portproxies?'))post('/api/v1/forwards/clear')">Limpiar todo</button>
    </div>
  </div>

  <div class="card">
    <h2>Tunnels (hacia VPS)</h2>
    <table><thead><tr><th>ID</th><th>VPS</th><th>Local</th><th>Remoto</th><th>Estado</th><th>Acciones</th></tr></thead>
    <tbody id="tun-body"></tbody></table>
  </div>

  <div class="card">
    <h2>Crear / registrar</h2>
    <div class="form"><label>Forward:</label>
      <input id="f-id" placeholder="fwd-id" style="width:110px">
      <input id="f-listen" placeholder="listen" style="width:70px">
      <input id="f-distro" placeholder="distro" style="width:90px">
      <input id="f-wsl" placeholder="wsl" style="width:60px">
      <button onclick="addForward()">+ Forward</button></div>
    <div class="form"><label>Tunnel:</label>
      <input id="t-id" placeholder="tun-id" style="width:110px">
      <select id="t-vps"></select>
      <input id="t-local" placeholder="127.0.0.1:3000" style="width:120px">
      <input id="t-remote" placeholder="0.0.0.0:80,443" style="width:120px">
      <button onclick="addTunnel()">+ Tunnel</button></div>
    <div class="form"><label>VPS:</label>
      <input id="v-id" placeholder="vps-id" style="width:110px">
      <input id="v-host" placeholder="host" style="width:140px">
      <input id="v-user" placeholder="user" style="width:80px">
      <input id="v-pass" placeholder="pass (opcional)" type="password" style="width:110px">
      <button onclick="addVps()">+ VPS</button></div>
  </div>

  <div class="card">
    <h2>VPS registrados</h2>
    <table><thead><tr><th>ID</th><th>Host</th><th>User</th><th>Acciones</th></tr></thead>
    <tbody id="vps-body"></tbody></table>
  </div>

  <div class="card">
    <h2>Uptime (24h/30d)</h2>
    <div id="uptime"></div>
  </div>

  <div class="card">
    <h2>Alertas</h2>
    <table><thead><tr><th>Severidad</th><th>Mensaje</th></tr></thead>
    <tbody id="alert-body"></tbody></table>
  </div>

  <div class="card" style="grid-column:1/-1">
    <h2>Eventos (journal)</h2>
    <div id="events">…</div>
  </div>
</div>
<div id="toast"></div>

<script>
let TOKEN = localStorage.getItem('pf_token') || '';
if (!TOKEN) askToken();

// Escape XSS (H2): toda interpolacion a innerHTML pasa por esc().
function esc(v){ const d=document.createElement('div');
  d.textContent = (v===null||v===undefined) ? '' : String(v);
  return d.innerHTML; }

function askToken() {
  const t = prompt('Token del panel web:');
  if (t) { TOKEN = t; localStorage.setItem('pf_token', t); }
  else TOKEN = '';
}
async function api(path, opts={}) {
  const headers = Object.assign({'Content-Type':'application/json'}, opts.headers||{});
  if (TOKEN) headers['Authorization'] = 'Bearer ' + TOKEN;
  const r = await fetch(path, Object.assign({headers}, opts));
  if (r.status === 401) { TOKEN=''; localStorage.removeItem('pf_token'); askToken(); }
  return r.json();
}
function badge(s) {
  const cls = (s==='ok'||s==='running'||s==='up') ? 'ok' :
              (s==='paused'||s==='waiting') ? 'warn' : 'err';
  return '<span class="badge '+cls+'">'+esc(s)+'</span>';
}
function toast(msg){ const t=document.getElementById('toast'); t.textContent=msg;
  t.style.opacity=1; setTimeout(()=>t.style.opacity=0, 2500); }
async function post(path){ const d = await api(path, {method:'POST'});
  toast(d.message || d.error || 'ok'); refresh(); }

function renderForwards(list){
  const b = document.getElementById('fwd-body'); b.innerHTML='';
  if(!list.length){ b.innerHTML='<tr><td colspan=6 class=muted>sin forwards</td></tr>'; return; }
  for(const f of list){
    const tr=document.createElement('tr');
    tr.innerHTML='<td>'+esc(f.id)+'</td><td>:'+esc(f.listen_port)+'</td><td>'+esc(f.wsl_distro||'—')+
      '</td><td>:'+esc(f.wsl_port)+'</td><td>'+badge(f.state)+'</td>'+
      '<td><button class="danger" onclick="post(\'/api/v1/forwards/remove/'+esc(f.id)+'\')">del</button></td>';
    b.appendChild(tr);
  }
}
function renderTunnels(list){
  const b = document.getElementById('tun-body'); b.innerHTML='';
  if(!list.length){ b.innerHTML='<tr><td colspan=7 class=muted>sin tunnels</td></tr>'; return; }
  for(const t of list){
    const tr=document.createElement('tr');
    tr.innerHTML='<td>'+esc(t.id)+'</td><td>'+esc(t.vps_id||'—')+'</td><td>'+esc(t.local)+
      '</td><td>'+esc(t.remote.join(', '))+'</td><td>'+badge(t.state)+'</td>'+
      '<td><button onclick="post(\'/api/v1/tunnels/'+esc(t.id)+'/start\')">start</button> '+
      '<button onclick="post(\'/api/v1/tunnels/'+esc(t.id)+'/stop\')">stop</button> '+
      '<button onclick="post(\'/api/v1/tunnels/'+esc(t.id)+'/restart\')">restart</button> '+
      '<button class="danger" onclick="post(\'/api/v1/tunnels/'+esc(t.id)+'/remove\')">del</button></td>';
    b.appendChild(tr);
  }
}
function renderVps(list){
  const b = document.getElementById('vps-body'); b.innerHTML='';
  const sel = document.getElementById('t-vps'); sel.innerHTML='';
  if(!list.length){ b.innerHTML='<tr><td colspan=4 class=muted>sin VPS registrados</td></tr>'; }
  for(const v of list){
    const tr=document.createElement('tr');
    tr.innerHTML='<td>'+esc(v.id)+'</td><td>'+esc(v.host)+'</td><td>'+esc(v.user)+'</td>'+
      '<td><button class="danger" onclick="post(\'/api/v1/vps/remove/'+esc(v.id)+'\')">del</button></td>';
    b.appendChild(tr);
    const o=document.createElement('option'); o.value=v.id; o.textContent=v.id+' ('+v.host+')'; sel.appendChild(o);
  }
}
function val(id){ const el=document.getElementById(id); return el ? el.value.trim() : ''; }
async function postJson(path, body){
  const d = await api(path, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  toast(d.message || d.error || 'ok'); refresh();
}
function addForward(){ postJson('/api/v1/forwards/add', {id:val('f-id'), listen_port:+val('f-listen')||0, distro:val('f-distro'), wsl_port:+val('f-wsl')||0, auto_apply:true}); }
function addTunnel(){ const remotes=val('t-remote').split(',').map(s=>s.trim()).filter(Boolean); postJson('/api/v1/tunnels/add', {id:val('t-id'), vps_id:val('t-vps'), local:val('t-local'), remotes, auto_start:true}); }
function addVps(){ postJson('/api/v1/vps/add', {id:val('v-id'), host:val('v-host'), user:val('v-user'), password:val('v-pass')}); }
function renderUptime(u){
  const d = document.getElementById('uptime'); d.innerHTML='';
  for(const [id,v] of Object.entries(u)){
    const pct = Math.round(v.uptime_fraction*100);
    const div=document.createElement('div');
    div.style.marginBottom='8px';
    div.innerHTML='<div style="display:flex;justify-content:space-between;font-size:12px">'+
      '<span>'+esc(id)+'</span><span class=muted>'+esc(pct)+'% · up '+esc(Math.round(v.up_seconds/60))+' min</span></div>'+
      '<div class="uptime"><i style="width:'+esc(pct)+'%"></i></div>';
    d.appendChild(div);
  }
  if(!Object.keys(u).length) d.innerHTML='<span class=muted>sin datos de uptime</span>';
}
function renderAlerts(list){
  const b = document.getElementById('alert-body'); b.innerHTML='';
  if(!list.length){ b.innerHTML='<tr><td colspan=2 class=muted>sin alertas</td></tr>'; return; }
  for(const a of list){
    const tr=document.createElement('tr');
    tr.innerHTML='<td>'+badge(a.severity==='error'?'down':a.severity)+'</td><td>'+esc(a.message)+'</td>';
    b.appendChild(tr);
  }
}
function renderEvents(list){
  const d = document.getElementById('events'); d.innerHTML='';
  for(const e of list.slice().reverse()){
    const div=document.createElement('div');
    const when=new Date(e.ts*1000).toLocaleTimeString();
    div.textContent=when+'  '+e.type+(e.detail?'  '+e.detail:'');
    d.appendChild(div);
  }
}
async function refresh(){
  try{
    const d = await api('/api/v1/state');
    if(!d.ok && d.error) throw new Error(d.error);
    document.getElementById('sub').textContent =
      'supervisor '+(d.status.running?'activo':'inactivo')+
      ' · maintenance '+(d.status.maintenance?'ON':'OFF')+
      ' · admin '+(d.status.admin?'SI':'NO')+
      ' · ' + new Date(d.ts*1000).toLocaleTimeString();
    renderForwards(d.status.forwards);
    renderTunnels(d.status.tunnels);
    renderUptime(d.uptime||{});
    renderAlerts(d.alerts||[]);
    const v = await api('/api/v1/vps');
    renderVps(v.vps||[]);
  }catch(e){ document.getElementById('sub').textContent='error: '+e.message; }
}
async function refreshEvents(){ try{ const d=await api('/api/v1/events?limit=50'); renderEvents(d.events||[]); }catch(e){} }
refresh(); refreshEvents();
setInterval(refresh, 3000);
setInterval(refreshEvents, 5000);
</script>
</body>
</html>
"""
