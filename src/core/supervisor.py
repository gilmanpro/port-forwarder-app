"""Supervisor: un solo loop que mantiene el estado deseado (seccion 12.3).

Cada N segundos (ui.supervisor_interval_seconds):
1. Obtiene IPs de las distros en uso; si cambiaron -> reaplica forwards.
2. Tunnels: is_alive() -> si muerto y auto_start -> restart con backoff
   exponencial (5s * 2^n, cap 300s).
3. Health checks de forwards (TCP al listen_port): tras K fallos -> Paused
   (ServiceDown), reintento cada 60s; al recuperarse -> reaplica y OK.
4. Escribe metricas/eventos en SQLite; evalua umbrales -> alertas.
5. Emite "state-changed" por el bus.
6. Modo maintenance: pausa todo (F15/A8).

El supervisor es headless-friendly: `port-forwarder supervise` corre esto
sin GUI; la GUI se suscribe al bus para pintar el estado.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable

from src.core import event_bus
from src.core.config import AppConfig, ConfigStore, Forward, Tunnel
from src.core.metrics_store import MetricsStore
from src.core.notifier import notify
from src.providers import (
    cloudflare_provider,
    netsh_provider,
    socat_provider,
    ssh_tunnel_provider,
    tailscale_provider,
    wsl_ip_provider,
)
from src.utils import subprocess_async as sp

BACKOFF_INITIAL = 5.0
BACKOFF_MAX = 300.0
PAUSED_RETRY_SECONDS = 60.0

STATE_OK = "ok"
STATE_PAUSED = "paused"
STATE_DOWN = "down"
STATE_WAITING = "waiting"
STATE_RUNNING = "running"
STATE_STOPPED = "stopped"


class Supervisor:
    def __init__(
        self,
        store: ConfigStore,
        netsh: netsh_provider.NetshProvider | None = None,
        wsl: wsl_ip_provider.WslIpProvider | None = None,
        ssh: ssh_tunnel_provider.SshTunnelProvider | None = None,
        tailscale: tailscale_provider.TailscaleProvider | None = None,
        cloudflare: cloudflare_provider.CloudflareProvider | None = None,
        metrics: MetricsStore | None = None,
        interval: float | None = None,
        clock: Callable[[], float] = time.monotonic,
        web_panel_external: bool = False,
    ) -> None:
        self.store = store
        # Forward provider segun plataforma: netsh (Windows) o socat (Linux/Docker)
        if netsh is not None:
            self.netsh = netsh
        else:
            import sys as _sys

            if _sys.platform == "win32":
                self.netsh = netsh_provider.NetshProvider()
            else:
                self.netsh = socat_provider.SocatProvider()
        self.wsl = wsl or wsl_ip_provider.WslIpProvider()
        self.ssh = ssh or ssh_tunnel_provider.SshTunnelProvider()
        self.tailscale = tailscale or tailscale_provider.TailscaleProvider()
        self.cloudflare = cloudflare or cloudflare_provider.CloudflareProvider()
        self.metrics = metrics or MetricsStore()
        self.interval = interval or float(
            store.cfg.ui.supervisor_interval_seconds
        )
        self.clock = clock
        # True si el panel web lo gestiona un proceso externo (cli web start)
        self._web_external = web_panel_external

        self._stop_ev = threading.Event()
        self._thread: threading.Thread | None = None

        # Estado interno por forward / tunnel
        self.forward_state: dict[str, str] = {}      # id -> ok|paused|down|missing
        self.forward_fails: dict[str, int] = {}      # id -> conteo consecutivo
        self.forward_next_retry: dict[str, float] = {}
        self.tunnel_state: dict[str, str] = {}       # id -> running|down|stopped|waiting
        self.tunnel_backoff: dict[str, dict[str, Any]] = {}
        self.tunnel_down_since: dict[str, float] = {}
        self.known_ips: dict[str, str] = {}          # distro -> ip (ultima vista)
        self.last_cycle: float = 0.0
        self.running = False
        self.maintenance = bool(store.cfg.maintenance.active)
        self._cfg_mtime = self._config_mtime()

    # -- arranque / parada -----------------------------------------------------

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self._stop_ev.clear()
        self._sync_web_panel()
        self._thread = threading.Thread(
            target=self._loop, name="supervisor", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self.running = False
        self._stop_ev.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self.interval + 5)

    def run_forever(self) -> None:
        """Ejecuta el loop en el hilo actual (modo headless 'supervise')."""
        self.running = True
        try:
            self._loop()
        finally:
            self.running = False

    # -- loop -------------------------------------------------------------------

    def _loop(self) -> None:
        self.metrics.record_event("supervisor_start", interval=self.interval)
        while self.running and not self._stop_ev.is_set():
            try:
                self._maybe_reload_config()
                self.run_once()
                self._sample_traffic()
            except Exception:
                import logging

                logging.getLogger("port-forwarder.supervisor").exception(
                    "error en ciclo del supervisor"
                )
            self.last_cycle = self.clock()
            self._stop_ev.wait(self.interval)

    def _sample_traffic(self) -> None:
        """Acumula el trafico (bytes) de los tunnels vivos cada ciclo."""
        if not hasattr(self.ssh, "traffic"):
            return
        for t in self.store.cfg.tunnels:
            try:
                if self.ssh.is_alive(t):
                    self.ssh.traffic(t, self.store.get_vps(t.vps_id))
            except Exception:  # noqa: BLE001 - no debe romper el loop
                continue

    # -- config externa ---------------------------------------------------------

    def _config_mtime(self) -> float:
        """mtime del config.json en disco (0 si no se puede leer)."""
        try:
            return self.store.path.stat().st_mtime
        except OSError:
            return 0.0

    def _maybe_reload_config(self) -> None:
        """Recarga config.json si cambio en disco (la GUI/CLI pueden editarlo
        desde otro proceso, p.ej. crear tunnels desde la ventana)."""
        m = self._config_mtime()
        if m == self._cfg_mtime:
            return
        self._cfg_mtime = m
        try:
            self.store.reload()
            self.metrics.record_event("config_reloaded")
        except Exception:  # noqa: BLE001 - config invalida: seguir con la anterior
            return
        self._sync_web_panel()

    def _web_panel_token(self) -> str:
        """Token del panel web: primero SecretsStore (DPAPI), fallback a config."""
        try:
            from src.utils import secrets as sec

            store = sec.SecretsStore()
            if store.check("web_panel_token"):
                return store.get("web_panel_token")
        except Exception:  # noqa: BLE001 - secrets invalidos: seguir con config
            pass
        return self.store.cfg.ui.web_panel_token

    def _sync_web_panel(self) -> None:
        """Arranca/para el panel web segun la config (Ajustes de la GUI).

        La clave (ui.web_panel_token) es OBLIGATORIA: sin ella el panel
        no se arranca. Si cambia clave/puerto/bind, se reinicia.
        Con web_panel_external=True el panel lo gestiona otro proceso
        (cli web start) y aqui solo se valida que siga respondiendo.
        """
        import logging

        log = logging.getLogger("port-forwarder.supervisor")
        if self._web_external:
            return
        cfg = self.store.cfg
        token = self._web_panel_token()
        desired = cfg.ui.web_panel_enabled and bool(token)

        web = getattr(self, "_web", None)
        if desired and web is not None:
            if (web.port == cfg.ui.web_panel_port
                    and web.bind == cfg.ui.web_panel_bind
                    and web.token == token):
                return
            self._stop_web(web)
            web = None
        if not desired:
            if web is not None:
                self._stop_web(web)
                self._web = None
            return
        try:
            from src.web.server import WebPanel

            panel = WebPanel(
                self,
                port=cfg.ui.web_panel_port,
                bind=cfg.ui.web_panel_bind,
                token=token,
                metrics=self.metrics,
            )
            panel.start()
            self._web = panel
            self.metrics.record_event(
                "web_panel_started",
                bind=cfg.ui.web_panel_bind, port=cfg.ui.web_panel_port,
            )
        except Exception as e:  # noqa: BLE001 - puerto ocupado, etc.
            log.error("panel web no arranco: %s", e)
            self.metrics.record_alert(
                "web_panel", f"panel web no arranco: {e}", severity="warning"
            )

    @staticmethod
    def _stop_web(web) -> None:
        try:
            web.stop()
        except Exception:  # noqa: BLE001
            pass

    def run_once(self) -> dict[str, Any]:
        """Un ciclo completo; devuelve un resumen. Usado por CLI 'supervise' y tests."""
        cfg = self.store.cfg
        summary: dict[str, Any] = {
            "maintenance": self.maintenance,
            "forwards": {},
            "tunnels": {},
        }

        if self.maintenance:
            # F15/A8: todo pausado; tunnels vivos se detienen.
            self._enter_maintenance(summary)
            event_bus.bus.emit("state-changed", **summary)
            return summary

        self._check_forwards(cfg, summary)
        self._check_tunnels(cfg, summary)
        self._emit_state(summary)
        return summary

    # -- forwards ---------------------------------------------------------------

    def _check_forwards(self, cfg: AppConfig, summary: dict[str, Any]) -> None:
        auto = [f for f in cfg.forwards if f.auto_apply]
        distros = {f.wsl_distro for f in auto if f.wsl_distro}
        ips = self.wsl.get_all_ips(list(distros))

        for distro, ip in ips.items():
            if ip and self.known_ips.get(distro) != ip:
                self.metrics.record_event(
                    "wsl_ip_changed", distro=distro, ip=ip,
                    previous=self.known_ips.get(distro),
                )
                self.known_ips[distro] = ip

        for f in auto:
            ip = ips.get(f.wsl_distro)
            self._reconcile_forward(f, ip, cfg)
            summary["forwards"][f.id] = {
                "state": self.forward_state.get(f.id, "unknown"),
                "ip": ip,
                "wsl_port": f.wsl_port,
            }

    def _reconcile_forward(self, f: Forward, ip: str | None, cfg: AppConfig) -> None:
        """Asegura que el forward existe en netsh con la IP actual."""
        state = self.forward_state.get(f.id, "missing")
        now = self.clock()

        # Health gate (F7): solo aplica a forwards ya aplicados (state OK).
        # Un forward nunca aplicado no debe quedar bloqueado por el gate.
        if f.health_check.enabled and state == STATE_OK:
            alive = self.netsh.test_connection(f.listen_port, timeout=2.0)
            if not alive:
                fails = self.forward_fails.get(f.id, 0) + 1
                self.forward_fails[f.id] = fails
                if fails >= f.health_check.fail_count_before_pause:
                    self.forward_state[f.id] = STATE_PAUSED
                    self.forward_next_retry[f.id] = now + PAUSED_RETRY_SECONDS
                    self.metrics.record_alert(
                        "forward_down",
                        f"Forward {f.id} (:{f.listen_port}) sin servicio: pausado",
                        severity="warning",
                    )
                    notify("Forward pausado",
                           f"{f.id}: sin servicio en :{f.listen_port}")
                    event_bus.bus.emit("forward-paused", forward_id=f.id)
                    return
            else:
                self.forward_fails[f.id] = 0

        # Pausado: solo reintentar cada PAUSED_RETRY_SECONDS.
        if state == STATE_PAUSED:
            if now < self.forward_next_retry.get(f.id, 0):
                return
            if f.health_check.enabled and \
                    not self.netsh.test_connection(f.listen_port, timeout=2.0):
                self.forward_next_retry[f.id] = now + PAUSED_RETRY_SECONDS
                return
            # Se recupero: volver a OK y reaplicar por si acaso.
            self.forward_state[f.id] = STATE_OK
            self.forward_fails[f.id] = 0
            self.metrics.resolve_open_alerts("forward_down")
            self.metrics.record_event("forward_recovered", forward_id=f.id)
            notify("Forward recuperado", f"{f.id} vuelve a responder")

        if not ip:
            self.forward_state.setdefault(f.id, STATE_DOWN)
            return

        existing = self.netsh.list_forwards()
        present = [x for x in existing if x.listen_port == f.listen_port]
        needs_apply = True
        if present:
            p = present[0]
            needs_apply = (
                p.wsl_port != f.wsl_port
                or p.listen_address != f.listen_address
            )

        if needs_apply:
            if present:
                self.netsh.remove_forward(f)
            result = self.netsh.add_forward(f, ip)
            self.metrics.record_forward_event(
                f.id, "apply", result.ok, result.error or result.output
            )
            if result.ok:
                self.forward_state[f.id] = STATE_OK
                self.metrics.record_event(
                    "forward_applied", forward_id=f.id, ip=ip,
                    listen_port=f.listen_port,
                )
                event_bus.bus.emit(
                    "forward-applied", forward_id=f.id, ip=ip,
                    listen_port=f.listen_port,
                )
            else:
                self.forward_state[f.id] = STATE_DOWN
                self.metrics.record_alert(
                    "forward_apply_failed",
                    f"Forward {f.id}: {result.error}",
                    severity="error",
                )
        else:
            self.forward_state[f.id] = STATE_OK

    # -- tunnels -----------------------------------------------------------------

    def _provider_for(self, t: Tunnel):
        """Provider segun el tipo de tunnel (T7/T8: tailscale/cloudflare)."""
        if t.type == "ssh":
            return self.ssh
        if t.type == "tailscale":
            return self.tailscale
        if t.type == "cloudflare":
            return self.cloudflare
        return None

    @staticmethod
    def _start(provider, t: Tunnel, vps):
        if t.type == "ssh":
            provider.start(t, vps)
        else:
            provider.start(t)

    def _check_tunnels(self, cfg: AppConfig, summary: dict[str, Any]) -> None:
        for t in cfg.tunnels:
            if not t.enabled:
                self.tunnel_state[t.id] = STATE_STOPPED
                summary["tunnels"][t.id] = {"state": STATE_STOPPED}
                continue
            provider = self._provider_for(t)
            if provider is None:
                self.tunnel_state[t.id] = STATE_DOWN
                summary["tunnels"][t.id] = {
                    "state": STATE_DOWN, "error": "tipo no soportado"
                }
                continue
            vps = self.store.get_vps(t.vps_id) if t.type == "ssh" else None
            if t.type == "ssh" and vps is None:
                self.tunnel_state[t.id] = STATE_DOWN
                summary["tunnels"][t.id] = {
                    "state": STATE_DOWN, "error": "vps missing"
                }
                continue

            alive = provider.is_alive(t)
            if alive:
                self._tunnel_up(t)
                summary["tunnels"][t.id] = {"state": STATE_RUNNING}
                continue

            # Muerto: backoff y restart si auto_start.
            self._tunnel_down(t)
            if not t.auto_start:
                summary["tunnels"][t.id] = {"state": STATE_STOPPED}
                continue
            info = self.tunnel_backoff.setdefault(
                t.id, {"attempts": 0, "next_retry": 0.0, "down_since": self.clock()}
            )
            now = self.clock()
            # Alerta por tiempo caido (M4): solo se dispara una vez.
            cfg_alerts = self.store.cfg.alerts
            down_for = now - self.tunnel_down_since.get(t.id, now)
            if cfg_alerts.tunnel_down_minutes and \
                    down_for >= cfg_alerts.tunnel_down_minutes * 60:
                self.metrics.record_alert(
                    "tunnel_down",
                    f"Tunnel {t.id} caido mas de "
                    f"{cfg_alerts.tunnel_down_minutes} min",
                    severity="warning",
                )
                self.tunnel_down_since[t.id] = now  # no repetir cada ciclo
            if now < info["next_retry"]:
                summary["tunnels"][t.id] = {
                    "state": STATE_DOWN,
                    "next_retry_in": round(info["next_retry"] - now, 1),
                }
                continue

            # Health gate T5 (solo ssh): sin servicio local no abrimos tunnel.
            if t.type == "ssh" and t.health_gate.enabled and \
                    not self.ssh._gate_ok(t):
                self.tunnel_state[t.id] = STATE_WAITING
                summary["tunnels"][t.id] = {"state": STATE_WAITING}
                info["next_retry"] = now + PAUSED_RETRY_SECONDS
                continue

            try:
                self._start(provider, t, vps)
                info["attempts"] = 0
                info["next_retry"] = now + BACKOFF_INITIAL
                self.tunnel_state[t.id] = STATE_RUNNING
                self.metrics.record_event(
                    "tunnel_started", tunnel_id=t.id, vps=t.vps_id,
                    attempts=info["attempts"],
                )
                notify("Tunnel reiniciado",
                       f"{t.id} ({t.type})")
                event_bus.bus.emit("tunnel-restarted", tunnel_id=t.id)
                summary["tunnels"][t.id] = {"state": STATE_RUNNING,
                                            "restarted": True}
            except Exception as e:
                # Cualquier error del provider no debe tumbar el loop (12.3).
                info["attempts"] += 1
                wait = min(BACKOFF_INITIAL * (2 ** info["attempts"]), BACKOFF_MAX)
                info["next_retry"] = now + wait
                self.tunnel_state[t.id] = STATE_DOWN
                self.metrics.record_alert(
                    "tunnel_down",
                    f"Tunnel {t.id}: {e} (reintento en {int(wait)}s)",
                    severity="error",
                )
                summary["tunnels"][t.id] = {
                    "state": STATE_DOWN, "error": str(e), "next_retry_in": wait,
                }

    def _tunnel_up(self, t: Tunnel) -> None:
        if self.tunnel_state.get(t.id) == STATE_RUNNING:
            return
        down_since = self.tunnel_down_since.pop(t.id, None)
        self.metrics.record_event("tunnel_up", tunnel_id=t.id)
        if down_since is not None:
            self.metrics.resolve_open_alerts("tunnel_down")
        self.tunnel_backoff.pop(t.id, None)
        self.tunnel_state[t.id] = STATE_RUNNING
        event_bus.bus.emit("tunnel-up", tunnel_id=t.id)

    def _tunnel_down(self, t: Tunnel) -> None:
        if self.tunnel_state.get(t.id) == STATE_DOWN:
            return
        self.tunnel_down_since.setdefault(t.id, self.clock())
        self.tunnel_state[t.id] = STATE_DOWN
        self.metrics.record_event("tunnel_down_event", tunnel_id=t.id)
        event_bus.bus.emit("tunnel-down", tunnel_id=t.id)

    # -- maintenance ---------------------------------------------------------------

    def _enter_maintenance(self, summary: dict[str, Any]) -> None:
        for t in self.store.cfg.tunnels:
            provider = self._provider_for(t)
            if provider is not None and provider.is_alive(t):
                provider.stop(t)
            self.tunnel_state[t.id] = STATE_STOPPED
            summary["tunnels"][t.id] = {"state": STATE_STOPPED,
                                        "reason": "maintenance"}

    def _emit_state(self, summary: dict[str, Any]) -> None:
        event_bus.bus.emit("state-changed", **summary)

    # -- consulta ------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Snapshot completo para 'status --json' y la GUI."""
        cfg = self.store.cfg
        forwards = []
        for f in cfg.forwards:
            forwards.append({
                "id": f.id,
                "listen_port": f.listen_port,
                "wsl_distro": f.wsl_distro,
                "wsl_port": f.wsl_port,
                "protocol": f.protocol,
                "auto_apply": f.auto_apply,
                "state": self.forward_state.get(
                    f.id,
                    "ok" if self.netsh.test_connection(f.listen_port, 1.0)
                    else "unknown",
                ),
                "ip": self.known_ips.get(f.wsl_distro),
            })
        tunnels = []
        for t in cfg.tunnels:
            provider = self._provider_for(t)
            alive = provider.is_alive(t) if provider else False
            tunnels.append({
                "id": t.id,
                "type": t.type,
                "vps_id": t.vps_id,
                "local": t.ssh_dest if t.type == "ssh" else t.local_url,
                "remote": [f"{b.host}:{b.port}" for b in t.remote_binds],
                "auto_start": t.auto_start,
                "state": self.tunnel_state.get(
                    t.id, "running" if alive else "stopped"
                ),
            })
        return {
            "running": self.running,
            "maintenance": self.maintenance,
            "interval_seconds": self.interval,
            "last_cycle_ts": self.last_cycle,
            "admin": sp.is_admin(),
            "forwards": forwards,
            "tunnels": tunnels,
        }
