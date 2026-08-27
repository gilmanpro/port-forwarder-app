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

# Rate limiting para login (igual que MCP): 5 intentos fallidos -> bloqueo 15 min
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW = 300  # ventana de conteo (5 min)
LOGIN_BLOCK_TIME = 900  # bloqueo tras exceder (15 min)


class RateLimiter:
    """Contador por IP con ventana deslizante y bloqueo temporal (thread-safe)."""

    def __init__(self, max_attempts: int = LOGIN_MAX_ATTEMPTS,
                 window: float = LOGIN_WINDOW, block_time: float = LOGIN_BLOCK_TIME) -> None:
        self.max_attempts = max_attempts
        self.window = window
        self.block_time = block_time
        self._attempts: dict[str, list[float]] = {}
        self._blocked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def is_blocked(self, key: str) -> tuple[bool, float]:
        now = time.time()
        with self._lock:
            until = self._blocked_until.get(key, 0)
            if now < until:
                return True, until - now
            # limpiar bloqueo expirado
            if key in self._blocked_until and now >= until:
                del self._blocked_until[key]
                self._attempts.pop(key, None)
            # limpiar intentos fuera de ventana
            lst = self._attempts.get(key, [])
            lst = [t for t in lst if now - t < self.window]
            self._attempts[key] = lst
            return False, 0

    def record_failure(self, key: str) -> None:
        now = time.time()
        with self._lock:
            lst = self._attempts.setdefault(key, [])
            lst.append(now)
            lst[:] = [t for t in lst if now - t < self.window]
            if len(lst) > self.max_attempts:
                self._blocked_until[key] = now + self.block_time
                log.warning("rate limit: %s bloqueado %.0fs tras %d fallos", key, self.block_time, len(lst))

    def record_success(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)
            self._blocked_until.pop(key, None)

    def remaining(self, key: str) -> int:
        with self._lock:
            lst = self._attempts.get(key, [])
            now = time.time()
            lst = [t for t in lst if now - t < self.window]
            return max(0, self.max_attempts - len(lst))


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
        if auth == f"Bearer {token}":
            return True
        # Tambien aceptar cookie de sesion (login via /login)
        cookie = self.headers.get("Cookie", "")
        if f"pf_token={token}" in cookie:
            return True
        return False

    def _deny(self, status: int = 401, msg: str = "no autorizado") -> None:
        self._send(json.dumps({"ok": False, "error": msg},
                              ensure_ascii=False).encode("utf-8"), status)

    def _client_ip(self) -> str:
        try:
            return self.client_address[0] if self.client_address else "unknown"
        except Exception:
            return "unknown"

    def _rate_limited(self) -> bool:
        """Si el IP esta bloqueado, responde 429 y devuelve True."""
        blocked, remaining = self.panel.rate_limiter.is_blocked(self._client_ip())
        if blocked:
            body = json.dumps(
                {"ok": False, "error": f"demasiados intentos, espera {int(remaining)}s"},
                ensure_ascii=False,
            ).encode("utf-8")
            self.send_response(429)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Retry-After", str(int(remaining)))
            self.send_header("X-RateLimit-Remaining", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return True
        return False

    def _handle_login(self) -> None:
        """POST /api/v1/login — valida token con rate limiting."""
        if self._rate_limited():
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            raw = self.rfile.read(length) if length else b""
            body = json.loads(raw.decode("utf-8")) if raw.strip() else {}
        except (ValueError, json.JSONDecodeError):
            self._deny(400, "body JSON invalido")
            return
        token = str(body.get("token") or body.get("password") or "").strip()
        ip = self._client_ip()
        if token and token == self.panel.token:
            self.panel.rate_limiter.record_success(ip)
            body_b, _ = _json({"ok": True, "message": "login correcto"})
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body_b)))
            # Cookie de sesion para que GET / funcione sin Bearer header
            self.send_header("Set-Cookie", f"pf_token={token}; Path=/; HttpOnly; SameSite=Lax")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body_b)
            log.info("login ok desde %s", ip)
            return
        else:
            self.panel.rate_limiter.record_failure(ip)
            blocked, remaining = self.panel.rate_limiter.is_blocked(ip)
            if blocked:
                body_b, _ = _json({"ok": False, "error": f"demasiados intentos, espera {int(remaining)}s"})
                self.send_response(429)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body_b)))
                self.send_header("Retry-After", str(int(remaining)))
                self.send_header("X-RateLimit-Remaining", "0")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body_b)
            else:
                remaining = self.panel.rate_limiter.remaining(ip)
                body_b, _ = _json({"ok": False, "error": "token invalido"})
                self.send_response(401)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body_b)))
                self.send_header("X-RateLimit-Remaining", str(remaining))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body_b)

    def log_message(self, fmt: str, *args: Any) -> None:
        log.debug(fmt, *args)

    # -- rutas ----------------------------------------------------------------

    def _ws_handshake(self) -> socket.socket | None:
        """Upgrade a WebSocket si el cliente lo pide. Devuelve el socket crudo o None."""
        key = self.headers.get("Sec-WebSocket-Key", "")
        if not key:
            return None
        # Validar token via query ?token= o cookie
        qs = parse_qs(urlparse(self.path).query)
        token_qs = (qs.get("token", [""])[0] or "").strip()
        cookie = self.headers.get("Cookie", "")
        token_ck = ""
        for part in cookie.split(";"):
            if "pf_token=" in part:
                token_ck = part.split("pf_token=", 1)[1].strip()
                break
        provided = token_qs or token_ck or self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if self.panel.token and provided != self.panel.token:
            # No autorizado para WS
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        return self.request

    def _ws_serve(self, sock: socket.socket) -> None:
        """Loop WebSocket: envia estado inicial y mantiene vivo."""
        panel = self.panel
        with panel._ws_lock:
            panel.ws_clients.add(sock)
        try:
            # Estado inicial
            try:
                state = panel.state()
                panel._ws_send(sock, json.dumps({"type": "state", "data": state}, ensure_ascii=False).encode("utf-8"))
            except Exception:
                pass
            sock.settimeout(30)
            while panel.running:
                try:
                    # Leer frame del cliente (ping/pong/close)
                    header = sock.recv(2)
                    if not header or len(header) < 2:
                        break
                    opcode = header[0] & 0x0F
                    if opcode == 0x8:  # close
                        break
                    # Para simplificar, ignoramos el payload del cliente
                    masked = header[1] & 0x80
                    length = header[1] & 0x7F
                    if length == 126:
                        length = struct.unpack("!H", sock.recv(2))[0]
                    elif length == 127:
                        length = struct.unpack("!Q", sock.recv(8))[0]
                    if masked:
                        mask = sock.recv(4)
                    if length:
                        sock.recv(length + (4 if masked else 0))
                    # Responder pong si es ping
                    if opcode == 0x9:
                        sock.sendall(b"\x8A\x00")
                except socket.timeout:
                    # Ping de keepalive
                    try:
                        panel._ws_send(sock, json.dumps({"type": "ping"}, ensure_ascii=False).encode("utf-8"))
                    except Exception:
                        break
                except Exception:
                    break
        finally:
            with panel._ws_lock:
                panel.ws_clients.discard(sock)
            try:
                sock.close()
            except Exception:
                pass

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        # WebSocket upgrade
        if path == "/ws":
            sock = self._ws_handshake()
            if sock is not None:
                self._ws_serve(sock)
            return
        if path == "/login":
            self._send(LOGIN_HTML, 200, "text/html")
            return
        if path == "/":
            if self.panel.token and not self._authed():
                self._send(LOGIN_HTML, 200, "text/html")
                return
            self._send(self.panel.dashboard_html, 200, "text/html")
            return
        if not path.startswith("/api/"):
            self._deny(404, "no encontrado")
            return
        if not self._authed():
            if self._rate_limited():
                return
            self.panel.rate_limiter.record_failure(self._client_ip())
            blocked, remaining = self.panel.rate_limiter.is_blocked(self._client_ip())
            if blocked:
                body, _ = _json({"ok": False, "error": f"demasiados intentos, espera {int(remaining)}s"})
                self.send_response(429)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Retry-After", str(int(remaining)))
                self.send_header("X-RateLimit-Remaining", "0")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return
            remaining = self.panel.rate_limiter.remaining(self._client_ip())
            body, _ = _json({"ok": False, "error": "no autorizado"})
            self.send_response(401)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-RateLimit-Remaining", str(remaining))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        # exito: limpiar contador
        self.panel.rate_limiter.record_success(self._client_ip())
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
        # Login no requiere auth previa (es el login mismo)
        if path == "/api/v1/login":
            self._handle_login()
            return
        if not self._csrf_ok():
            self._deny(403, "origen no permitido (CSRF)")
            return
        if not self._authed():
            if self._rate_limited():
                return
            self.panel.rate_limiter.record_failure(self._client_ip())
            blocked, remaining = self.panel.rate_limiter.is_blocked(self._client_ip())
            if blocked:
                body, _ = _json({"ok": False, "error": f"demasiados intentos, espera {int(remaining)}s"})
                self.send_response(429)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Retry-After", str(int(remaining)))
                self.send_header("X-RateLimit-Remaining", "0")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return
            remaining = self.panel.rate_limiter.remaining(self._client_ip())
            body, _ = _json({"ok": False, "error": "no autorizado"})
            self.send_response(401)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-RateLimit-Remaining", str(remaining))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        self.panel.rate_limiter.record_success(self._client_ip())

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
        self.rate_limiter = RateLimiter()
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
        # WebSocket broadcast loop
        self._ws_thread = threading.Thread(target=self._ws_broadcast_loop, name="web-ws-broadcast", daemon=True)
        self._ws_thread.start()
        log.info("panel web en http://%s:%s", self.bind, self.port)

    def stop(self) -> None:
        self.running = False
        # Cerrar WebSockets
        if hasattr(self, 'ws_clients'):
            with self._ws_lock:
                for ws in list(self.ws_clients):
                    try:
                        ws.close()
                    except Exception:
                        pass
                self.ws_clients.clear()
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        log.info("panel web detenido")

    def broadcast_ws(self, msg: dict) -> None:
        data = __import__("json").dumps(msg, ensure_ascii=False).encode("utf-8")
        dead = []
        with self._ws_lock:
            for ws in list(self.ws_clients):
                try:
                    self._ws_send(ws, data)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self.ws_clients.discard(ws)

    def _ws_broadcast_loop(self) -> None:
        while self.running:
            import time as _t
            _t.sleep(3)
            if not self.running or not getattr(self, 'ws_clients', None) or not self.ws_clients:
                continue
            try:
                state = self.state()
                self.broadcast_ws({"type": "state", "data": state})
            except Exception:
                pass

    @staticmethod
    def _ws_send(sock, data: bytes) -> None:
        import struct
        frame = bytearray()
        frame.append(0x81)
        length = len(data)
        if length < 126:
            frame.append(length)
        elif length < 65536:
            frame.append(126)
            frame.extend(struct.pack("!H", length))
        else:
            frame.append(127)
            frame.extend(struct.pack("!Q", length))
        frame.extend(data)
        sock.sendall(frame)

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
                capture_output=True, timeout=3,
                creationflags=0x08000000,
            )
            if proc.returncode == 0:
                output = self._decode_wsl(proc.stdout)
                for line in output.splitlines():
                    line = line.strip()
                    if not line or "NAME" in line.upper() or "---" in line:
                        continue
                    if line.startswith("*"):
                        line = line[1:].strip()
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

    @staticmethod
    def _decode_wsl(data: bytes) -> str:
        """Decodifica salida de wsl.exe (UTF-16-LE con/sin BOM)."""
        if not data:
            return ""
        if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
            try:
                return data.decode("utf-16")
            except (UnicodeDecodeError, UnicodeError):
                pass
        try:
            s = data.decode("utf-8")
            if "\x00" in s:
                return data.decode("utf-16-le", errors="replace")
            return s
        except UnicodeDecodeError:
            return data.decode("utf-16-le", errors="replace")

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
        # Distros WSL: start/stop/restart
        if (parts[:3] == ["api", "v1", "distro"] and len(parts) == 5
                and parts[4] in ("start", "stop", "restart")):
            name, op = parts[3], parts[4]
            self.metrics.record_event("web_distro_" + op, distro=name)
            return self._distro_action(name, op)
        return {"ok": False, "error": f"accion desconocida: {path}"}

    def _distro_action(self, name: str, op: str) -> dict[str, Any]:
        """Ejecuta wsl.exe start/stop/restart sobre una distro (timeout corto)."""
        import subprocess

        def _run(cmd: list[str], timeout: float = 20) -> tuple[int, str]:
            try:
                p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                                   creationflags=0x08000000)
                err = (p.stderr or p.stdout or b"").decode("utf-8", "replace").strip()
                return p.returncode, err
            except subprocess.TimeoutExpired:
                return -1, f"timeout tras {timeout}s"

        verbs = {"start": "iniciada", "stop": "detenida", "restart": "reiniciada"}
        try:
            if op == "start":
                rc, err = _run(["wsl.exe", "-d", name, "--", "true"])
            elif op == "stop":
                rc, err = _run(["wsl.exe", "--terminate", name], timeout=15)
            else:  # restart
                _run(["wsl.exe", "--terminate", name], timeout=15)
                rc, err = _run(["wsl.exe", "-d", name, "--", "true"])
            if rc != 0:
                return {"ok": False, "error": f"fallo al {op} '{name}': {err or 'error'}"}
            return {"ok": True, "message": f"distro '{name}' {verbs[op]}"}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}


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


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wsl-port — WSL + Port Forwarding</title>
<style>
  :root { --bg:#0f1419; --card:#1a2130; --line:#2d3748; --text:#e6edf3; --muted:#8b95a5; --accent:#00d4ff; --ok:#00c853; --warn:#ff9100; --err:#ff1744; --info:#2196f3; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); }
  .header { display:flex; align-items:center; padding:14px 20px; gap:12px; border-bottom:1px solid var(--line); }
  .header h1 { font-size:20px; margin:0; color:var(--accent); }
  .header .sub { color:var(--muted); font-size:13px; }
  .header .status { margin-left:auto; color:var(--muted); font-size:12px; }
  .tabs { display:flex; gap:2px; padding:8px 12px 0; background:var(--bg); border-bottom:1px solid var(--line); }
  .tab { padding:8px 16px; border:0; background:transparent; color:var(--muted); cursor:pointer; font-size:13px; border-radius:6px 6px 0 0; }
  .tab.active { background:var(--card); color:var(--accent); border:1px solid var(--line); border-bottom:1px solid var(--card); margin-bottom:-1px; }
  .tab:hover { color:var(--text); }
  .tab-content { display:none; padding:14px; }
  .tab-content.active { display:block; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px; margin-bottom:14px; }
  .card h2 { font-size:13px; margin:0 0 10px; color:var(--muted); text-transform:uppercase; letter-spacing:.06em; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); }
  th { color:var(--muted); font-weight:600; }
  .badge { display:inline-block; padding:2px 8px; border-radius:20px; font-size:11px; }
  .ok { background:#12351f; color:var(--ok); }
  .warn { background:#3a2d0f; color:var(--warn); }
  .err { background:#3a1513; color:var(--err); }
  .muted { color:var(--muted); }
  button { background:#2563eb; border:0; color:#fff; padding:5px 10px; border-radius:6px; cursor:pointer; font-size:12px; }
  button:hover { filter:brightness(1.15); }
  button.danger { background:#b91c1c; }
  button.success { background:var(--ok); }
  button.warn { background:var(--warn); color:#000; }
  input, select { padding:5px 8px; border-radius:6px; border:1px solid var(--line); background:var(--bg); color:var(--text); font-size:12px; }
  .form { display:flex; gap:6px; flex-wrap:wrap; margin-top:8px; align-items:center; }
  .form label { color:var(--muted); font-size:12px; }
  .toolbar { display:flex; gap:6px; flex-wrap:wrap; margin-bottom:8px; }
  #activity { text-align:center; padding:6px; font-size:13px; font-weight:600; min-height:22px; }
  #activity.info { color:var(--info); }
  #activity.success { color:var(--ok); }
  #activity.warning { color:var(--warn); }
  #activity.error { color:var(--err); }
  #statusbar { display:flex; justify-content:space-between; padding:8px 20px; font-size:12px; color:var(--muted); border-top:1px solid var(--line); }
  #toast { position:fixed; bottom:16px; right:16px; background:#12335f; padding:10px 14px; border-radius:8px; font-size:13px; opacity:0; transition:opacity .3s; max-width:360px; box-shadow:0 4px 14px rgba(0,0,0,.4); border-left:4px solid #2563eb; z-index:100; }
  #toast.ok { border-left-color:var(--ok); }
  #toast.err { border-left-color:var(--err); }
  #toast.warn { border-left-color:var(--warn); }
  #events { font-family:ui-monospace,Consolas,monospace; font-size:11px; max-height:180px; overflow-y:auto; }
  #events div { padding:2px 0; border-bottom:1px dashed var(--line); }
  .ws-status { display:inline-block; width:8px; height:8px; border-radius:50%; margin-left:6px; }
  .ws-on { background:var(--ok); box-shadow:0 0 6px var(--ok); }
  .ws-off { background:var(--err); }
  tr.selected { background:rgba(0,212,255,.15) !important; }
</style>
</head>
<body>
<div class="header">
  <h1>wsl-port</h1><span class="sub">WSL + Port Forwarding integrados</span>
  <span class="status" id="header-status">conectando<span class="ws-status ws-off" id="ws-dot" title="WebSocket"></span></span>
</div>
<div class="tabs">
  <button class="tab active" onclick="showTab('distros')">Distros WSL</button>
  <button class="tab" onclick="showTab('publicar')">Publicar en Internet</button>
  <button class="tab" onclick="showTab('tunnels')">Tunnels / VPS</button>
  <button class="tab" onclick="showTab('forwards')">Forwards</button>
  <button class="tab" onclick="showTab('logs')">Logs</button>
  <button class="tab" onclick="showTab('ajustes')">Ajustes</button>
</div>
<div id="tab-distros" class="tab-content active">
  <div class="toolbar">
    <button class="success" onclick="refresh()">Refrescar</button>
    <button onclick="distroActionSel('start')">Iniciar</button>
    <button class="warn" onclick="distroActionSel('stop')">Detener</button>
    <button onclick="distroActionSel('restart')">Reiniciar</button>
    <button onclick="distroActionSel('snapshot')">Snapshot</button>
    <button onclick="showMetricsSel()">Metricas</button>
    <button class="success" onclick="showCreateDistro()">Crear...</button>
    <button class="danger" onclick="deleteDistroSel()">Eliminar</button>
  </div>
  <div class="card"><table><thead><tr><th>Distro</th><th>Estado</th><th>IP</th><th>Version</th></tr></thead><tbody id="distro-body"></tbody></table></div>
  <div class="card"><h2>Exportar / Importar</h2>
    <div class="form"><button onclick="exportDistroSel()">Exportar seleccionada</button><span class="muted">Descarga .tar de la distro seleccionada</span></div>
    <div class="form"><label>Importar:</label><input id="imp-name" placeholder="nombre distro" style="width:130px"><input id="imp-file" type="file" accept=".tar"><button onclick="importDistro()">Subir .tar</button></div>
  </div>
</div>
<div id="tab-publicar" class="tab-content">
  <div class="card">
    <h2>Publicar en Internet (1 clic)</h2>
    <p class="muted">Publica un servicio WSL en Internet via tu VPS. Ej: puerto 9000 de Debian → http://TU-VPS:18097</p>
    <div class="form"><label>Distro:</label><select id="pub-distro"></select><label>Puerto WSL:</label><input id="pub-wslport" value="9000" style="width:80px"><label>VPS:</label><select id="pub-vps"></select><label>Puerto publico:</label><input id="pub-port" value="18097" style="width:80px"></div>
    <div class="toolbar"><button class="success" onclick="doPublish()">Publicar</button><button class="danger" onclick="doUnpublish()">Detener publicacion</button><button onclick="openPublished()">Abrir en navegador</button></div>
    <div id="pub-result" class="muted" style="margin-top:8px;"></div>
  </div>
</div>
<div id="tab-tunnels" class="tab-content">
  <div class="toolbar">
    <button class="success" onclick="refresh()">Refrescar</button>
    <button onclick="showAddTunnel()">Nuevo Tunnel...</button>
    <button onclick="tunnelActionSel('start')">Iniciar</button>
    <button class="warn" onclick="tunnelActionSel('stop')">Detener</button>
    <button class="danger" onclick="deleteTunnelSel()">Eliminar</button>
  </div>
  <div class="card"><table><thead><tr><th>ID</th><th>Tipo</th><th>VPS</th><th>Local</th><th>Remoto</th><th>Estado</th></tr></thead><tbody id="tun-body"></tbody></table></div>
  <div class="toolbar">
    <button onclick="showAddVps()">Nuevo VPS...</button><button onclick="editVpsSel()">Editar VPS...</button><button class="danger" onclick="deleteVpsSel()">Eliminar VPS</button>
  </div>
  <div class="card"><table><thead><tr><th>VPS</th><th>Host</th><th>Usuario</th><th>Puerto</th></tr></thead><tbody id="vps-body"></tbody></table></div>
</div>
<div id="tab-forwards" class="tab-content">
  <div class="toolbar">
    <button class="success" onclick="refresh()">Refrescar</button><button onclick="showAddForward()">Nuevo Forward...</button><button onclick="post('/api/v1/forwards/apply')">Reaplicar todos</button><button class="danger" onclick="deleteForwardSel()">Eliminar</button><button class="danger" onclick="if(confirm('Limpiar TODOS?'))post('/api/v1/forwards/clear')">Limpiar todos</button>
  </div>
  <div class="card"><table><thead><tr><th>ID</th><th>Listen</th><th>Distro</th><th>WSL Port</th><th>Proto</th><th>Estado</th></tr></thead><tbody id="fwd-body"></tbody></table></div>
</div>
<div id="tab-logs" class="tab-content">
  <div class="toolbar"><button class="success" onclick="refreshEvents()">Refrescar logs</button><span class="muted">Eventos en vivo via WebSocket</span></div>
  <div class="card"><div id="events">...</div></div>
  <div class="card"><h2>Alertas</h2><table><thead><tr><th>Severidad</th><th>Mensaje</th></tr></thead><tbody id="alert-body"></tbody></table></div>
</div>
<div id="tab-ajustes" class="tab-content">
  <div class="card"><h2>Ajustes del sistema</h2>
    <p class="muted">Los ajustes se configuran en la GUI de escritorio (Ajustes) o via <code>wsl-port config</code>. El panel web es de solo lectura para ajustes sensibles.</p>
    <div class="form"><button onclick="window.open('/api/v1/state','_blank')">Ver estado JSON</button>
      <button onclick="post('/api/v1/maintenance/on')">Mantenimiento ON</button><button onclick="post('/api/v1/maintenance/off')">Mantenimiento OFF</button></div>
  </div>
</div>
<div id="activity"></div>
<div id="statusbar"><span id="sub">conectando...</span><span id="status-extra"></span></div>
<div id="toast"></div>
<script>
let TOKEN = localStorage.getItem('pf_token') || '';
function esc(v){ const d=document.createElement('div'); d.textContent=(v===null||v===undefined)?'':String(v); return d.innerHTML; }
function badge(s){ const cls=(s==='ok'||s==='running'||s==='up')?'ok':(s==='paused'||s==='waiting')?'warn':'err'; return '<span class="badge '+cls+'">'+esc(s)+'</span>'; }
function toast(msg, kind){ const t=document.getElementById('toast'); t.className=kind||''; t.textContent=msg; t.style.opacity=1; setTimeout(()=>{t.style.opacity=0; t.className='';}, 4000); }
function activity(msg, kind){ const a=document.getElementById('activity'); a.textContent=msg; a.className=kind||'info'; a.style.opacity=1; setTimeout(()=>{a.style.opacity=0;}, 5000); if(kind) toast(msg, kind); }
async function api(path, opts={}){
  const headers = Object.assign({'Content-Type':'application/json'}, opts.headers||{});
  if(TOKEN) headers['Authorization']='Bearer '+TOKEN;
  const r = await fetch(path, Object.assign({headers}, opts));
  if(r.status===401){ window.location.href='/login'; throw new Error('No autorizado'); }
  if(r.status===429){ const d=await r.clone().json().catch(()=>({})); toast(d.error||'Demasiados intentos','err'); throw new Error(d.error||'Rate limited'); }
  return r.json();
}
async function post(path){ toast('Iniciando tarea...','info'); const d=await api(path,{method:'POST'}); const k=d.ok===false?'err':'ok'; activity(d.message||d.error||'Tarea terminada',''+k); toast(d.message||d.error||'ok',k); refresh(); }
async function postJson(path, body){ toast('Iniciando tarea...','info'); const d=await api(path,{method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)}); const k=d.ok===false?'err':'ok'; activity(d.message||d.error||'Tarea terminada',''+k); toast(d.message||d.error||'ok',k); refresh(); }
function showTab(id){ document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active')); document.querySelectorAll('.tab-content').forEach(c=>c.classList.remove('active')); document.querySelector(`[onclick="showTab('${id}')"]`).classList.add('active'); document.getElementById('tab-'+id).classList.add('active'); localStorage.setItem('wslport-tab', id); }
(function(){ const t=localStorage.getItem('wslport-tab'); if(t) showTab(t); })();
function getSel(id){ const t=document.getElementById(id); const sel=t.querySelector('tr.selected'); if(!sel){ toast('Selecciona una fila primero','warn'); return null; } return sel.dataset.id; }
function makeSelectable(tbodyId){ document.getElementById(tbodyId).addEventListener('click', e=>{ const tr=e.target.closest('tr'); if(!tr||!tr.dataset.id) return; tr.parentElement.querySelectorAll('tr').forEach(r=>r.classList.remove('selected')); tr.classList.add('selected'); }); }
['distro-body','tun-body','vps-body','fwd-body'].forEach(makeSelectable);
function renderDistros(list){
  const b=document.getElementById('distro-body'); b.innerHTML='';
  const sel=document.getElementById('pub-distro'); if(sel){ const cur=sel.value; sel.innerHTML=''; list.forEach(d=>{const o=document.createElement('option');o.value=d.name;o.textContent=d.name;sel.appendChild(o);}); if(cur) sel.value=cur; else if(list[0]) sel.value=list[0].name; }
  if(!list||!list.length){ b.innerHTML='<tr><td colspan=4 class=muted>sin distros (WSL no responde)</td></tr>'; return; }
  for(const d of list){ const tr=document.createElement('tr'); tr.dataset.id=d.name; tr.innerHTML='<td>'+esc(d.name)+'</td><td>'+badge(d.state==='Running'?'ok':'err')+'</td><td>'+esc(d.ip||'-')+'</td><td>'+esc(d.version)+'</td>'; b.appendChild(tr); }
}
function distroActionSel(op){ const id=document.querySelector('#distro-body tr.selected'); if(!id){ toast('Selecciona una distro','warn'); return; } const name=id.dataset.id; activity('Iniciando tarea: '+op+' '+name+'...','info'); post('/api/v1/distro/'+encodeURIComponent(name)+'/'+op).then(()=>activity('Tarea terminada: '+name+' '+op,'success')); }
function exportDistroSel(){ const sel=document.querySelector('#distro-body tr.selected'); if(!sel){ toast('Selecciona una distro','warn'); return; } exportDistro(sel.dataset.id); }
function deleteDistroSel(){ const sel=document.querySelector('#distro-body tr.selected'); if(!sel){ toast('Selecciona una distro','warn'); return; } if(!confirm('Eliminar distro '+sel.dataset.id+' y TODOS sus datos?')) return; activity('Eliminando '+sel.dataset.id+'...','info'); api('/api/v1/distro/'+encodeURIComponent(sel.dataset.id)+'/delete',{method:'POST'}).then(d=>{activity(d.message||d.error, d.ok?'success':'error'); refresh();}); }
function showMetricsSel(){ const sel=document.querySelector('#distro-body tr.selected'); if(!sel){ toast('Selecciona una distro','warn'); return; } api('/api/v1/distro/'+encodeURIComponent(sel.dataset.id)+'/metrics').then(d=>{ alert(JSON.stringify(d,null,2)); }); }
function showCreateDistro(){ const name=prompt('Nombre de la distro a instalar (ej: Ubuntu):'); if(!name) return; activity('Instalando '+name+'...','info'); post('/api/v1/distro/create',{name}).then(()=>activity('Distro '+name+' instalada','success')); }
async function exportDistro(name){
  activity('Exportando '+name+'...','info');
  try{
    const r=await fetch('/api/v1/distro/'+encodeURIComponent(name)+'/export',{headers:{Authorization:'Bearer '+TOKEN}});
    if(!r.ok){ const d=await r.json().catch(()=>({})); toast(d.error||'Error','err'); activity(d.error,'error'); return; }
    const blob=await r.blob(); const url=URL.createObjectURL(blob);
    const a=document.createElement('a'); a.href=url; a.download=name+'.tar'; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    activity('Distro '+name+' exportada','success'); toast('Exportacion terminada','ok');
  }catch(e){ activity('Error: '+e.message,'error'); }
}
async function importDistro(){
  const file=document.getElementById('imp-file').files[0]; const name=document.getElementById('imp-name').value.trim();
  if(!file){ toast('Selecciona .tar','err'); return; }
  if(!name){ toast('Nombre requerido','err'); return; }
  const fd=new FormData(); fd.append('name',name); fd.append('install_dir',''); fd.append('file',file);
  activity('Importando '+name+'...','info');
  try{
    const r=await fetch('/api/v1/distro/import',{method:'POST', headers:{Authorization:'Bearer '+TOKEN}, body:fd});
    const d=await r.json(); activity(d.message||d.error, d.ok?'success':'error'); toast(d.message||d.error, d.ok?'ok':'err'); refresh();
  }catch(e){ activity('Error: '+e.message,'error'); }
}
function doPublish(){
  const distro=document.getElementById('pub-distro').value, wslport=parseInt(document.getElementById('pub-wslport').value), vps=document.getElementById('pub-vps').value, pubport=parseInt(document.getElementById('pub-port').value);
  if(!distro||!vps||!wslport||!pubport){ toast('Completa los campos','err'); return; }
  activity('Publicando '+distro+':'+wslport+'...','info');
  postJson('/api/v1/publish',{distro, wsl_port:wslport, vps_id:vps, public_port:pubport}).then(d=>{
    if(d.public_url){ document.getElementById('pub-result').textContent='Publicado: '+d.public_url; activity('Publicado en '+d.public_url,'success'); }
  });
}
function doUnpublish(){
  const distro=document.getElementById('pub-distro').value, wslport=parseInt(document.getElementById('pub-wslport').value);
  if(!distro||!wslport) return;
  const tid='pub-'+distro.toLowerCase().replace(/[^a-z0-9]+/g,'-')+'-'+wslport;
  activity('Deteniendo '+tid+'...','info');
  api('/api/v1/unpublish/'+encodeURIComponent(tid),{method:'POST'}).then(d=>{activity(d.message||'Eliminado','success'); refresh();});
}
function openPublished(){ const r=document.getElementById('pub-result').textContent; const m=r.match(/https?:\/\/\S+/); if(m) window.open(m[0],'_blank'); else toast('Nada publicado aun','warn'); }
function tunnelActionSel(op){ const sel=document.querySelector('#tun-body tr.selected'); if(!sel){ toast('Selecciona un tunnel','warn'); return; } activity('Iniciando tarea: '+op+'...','info'); post('/api/v1/tunnels/'+encodeURIComponent(sel.dataset.id)+'/'+op).then(()=>activity('Tarea terminada','success')); }
function deleteTunnelSel(){ const sel=document.querySelector('#tun-body tr.selected'); if(!sel){ toast('Selecciona un tunnel','warn'); return; } if(!confirm('Eliminar '+sel.dataset.id+'?')) return; post('/api/v1/tunnels/'+encodeURIComponent(sel.dataset.id)+'/remove'); }
function showAddTunnel(){ const id=prompt('ID del tunnel:'); if(!id) return; const vps=prompt('VPS id:'); if(!vps) return; const local=prompt('Local (ej 127.0.0.1:9000):','127.0.0.1:9000'); if(!local) return; const remote=prompt('Remoto (ej 0.0.0.0:18097):','0.0.0.0:18097'); if(!remote) return; postJson('/api/v1/tunnels/add',{id, vps_id:vps, local, remotes:[remote]}); }
function showAddVps(){ const id=prompt('ID VPS:'); if(!id) return; const host=prompt('Host/IP:'); if(!host) return; const user=prompt('Usuario:','debian'); const pass=prompt('Password (opcional):')||''; postJson('/api/v1/vps/add',{id, host, user, password:pass}); }
function editVpsSel(){ const sel=document.querySelector('#vps-body tr.selected'); if(!sel){ toast('Selecciona un VPS','warn'); return; } const host=prompt('Nuevo host:', sel.dataset.host||''); if(host===null) return; postJson('/api/v1/vps/add',{id:sel.dataset.id, host, user:sel.dataset.user||'debian'}); }
function deleteVpsSel(){ const sel=document.querySelector('#vps-body tr.selected'); if(!sel){ toast('Selecciona un VPS','warn'); return; } if(!confirm('Eliminar VPS '+sel.dataset.id+'?')) return; post('/api/v1/vps/remove/'+encodeURIComponent(sel.dataset.id)); }
function showAddForward(){ const id=prompt('ID forward:'); if(!id) return; const listen=prompt('Puerto listen:'); if(!listen) return; const distro=prompt('Distro:','Debian'); const wslp=prompt('Puerto WSL:'); postJson('/api/v1/forwards/add',{id, listen_port:parseInt(listen), distro, wsl_port:parseInt(wslp), auto_apply:true}); }
function deleteForwardSel(){ const sel=document.querySelector('#fwd-body tr.selected'); if(!sel){ toast('Selecciona un forward','warn'); return; } post('/api/v1/forwards/remove/'+encodeURIComponent(sel.dataset.id)); }
function renderForwards(list){
  const b=document.getElementById('fwd-body'); b.innerHTML='';
  if(!list.length){ b.innerHTML='<tr><td colspan=6 class=muted>sin forwards</td></tr>'; return; }
  for(const f of list){ const tr=document.createElement('tr'); tr.dataset.id=f.id; tr.innerHTML='<td>'+esc(f.id)+'</td><td>:'+esc(f.listen_port)+'</td><td>'+esc(f.wsl_distro||'--')+'</td><td>:'+esc(f.wsl_port)+'</td><td>'+esc(f.protocol||'tcp')+'</td><td>'+badge(f.state)+'</td>'; b.appendChild(tr); }
}
function renderTunnels(list){
  const b=document.getElementById('tun-body'); b.innerHTML='';
  if(!list.length){ b.innerHTML='<tr><td colspan=6 class=muted>sin tunnels</td></tr>'; return; }
  for(const t of list){ const tr=document.createElement('tr'); tr.dataset.id=t.id; tr.innerHTML='<td>'+esc(t.id)+'</td><td>'+esc(t.type||'ssh')+'</td><td>'+esc(t.vps_id||'--')+'</td><td>'+esc(t.local)+'</td><td>'+esc((t.remote||[]).join(', '))+'</td><td>'+badge(t.state)+'</td>'; b.appendChild(tr); }
}
function renderVps(list){
  const b=document.getElementById('vps-body'); b.innerHTML='';
  const sel=document.getElementById('pub-vps'); if(sel){ const cur=sel.value; sel.innerHTML=''; list.forEach(v=>{const o=document.createElement('option');o.value=v.id;o.textContent=v.id; sel.appendChild(o);}); if(cur) sel.value=cur; else if(list[0]) sel.value=list[0].id; }
  if(!list.length){ b.innerHTML='<tr><td colspan=4 class=muted>sin VPS</td></tr>'; return; }
  for(const v of list){ const tr=document.createElement('tr'); tr.dataset.id=v.id; tr.dataset.host=v.host; tr.dataset.user=v.user; tr.innerHTML='<td>'+esc(v.id)+'</td><td>'+esc(v.host)+'</td><td>'+esc(v.user)+'</td><td>'+esc(v.port)+'</td>'; b.appendChild(tr); }
}
function renderUptime(u){
  const d=document.getElementById('uptime'); d.innerHTML='';
  for(const [id,v] of Object.entries(u)){ const pct=Math.round((v.uptime_fraction||0)*100); const div=document.createElement('div'); div.style.marginBottom='8px'; div.innerHTML='<div style="display:flex;justify-content:space-between;font-size:12px"><span>'+esc(id)+'</span><span class=muted>'+esc(pct)+'% up</span></div><div style="height:6px;background:var(--line);border-radius:3px;overflow:hidden;"><i style="display:block;height:100%;background:var(--ok);width:'+esc(pct)+'%"></i></div>'; d.appendChild(div); }
  if(!Object.keys(u).length) d.innerHTML='<span class=muted>sin datos</span>';
}
function renderAlerts(list){
  const b=document.getElementById('alert-body'); b.innerHTML='';
  if(!list.length){ b.innerHTML='<tr><td colspan=2 class=muted>sin alertas</td></tr>'; return; }
  for(const a of list){ const tr=document.createElement('tr'); tr.innerHTML='<td>'+badge(a.severity==='error'?'down':a.severity)+'</td><td>'+esc(a.message)+'</td>'; b.appendChild(tr); }
}
function appendEvent(ev){
  const d=document.getElementById('events'); const div=document.createElement('div');
  div.textContent=new Date(ev.ts*1000).toLocaleTimeString()+' '+ev.type+(ev.detail?' '+ev.detail:'');
  d.prepend(div); while(d.children.length>100) d.removeChild(d.lastChild);
}
function renderEvents(list){
  const d=document.getElementById('events'); d.innerHTML='';
  for(const e of list.slice().reverse()){ const div=document.createElement('div'); div.textContent=new Date(e.ts*1000).toLocaleTimeString()+' '+e.type+(e.detail?' '+e.detail:''); d.appendChild(div); }
}
function renderAll(data){
  const s=data.status||data;
  const distros=s.distros||[];
  document.getElementById('sub').textContent='supervisor '+(s.supervisor_running?'activo':'inactivo')+' · '+(s.wsl_hung?'WSL no responde':'distros '+(s.distros||[]).length)+' · admin '+(s.admin?'SI':'NO')+' · '+new Date((data.ts||Date.now()/1000)*1000).toLocaleTimeString();
  document.getElementById('header-status').textContent=s.wsl_hung?'WSL no responde - reinicia el PC':('distros '+(s.distros||[]).filter(d=>d.running).length+'/'+(s.distros||[]).length+' · tuneles '+(s.tunnels||[]).filter(t=>t.state==='running').length+'/'+(s.tunnels||[]).length);
  renderDistros(distros); renderForwards(s.forwards||[]); renderTunnels(s.tunnels||[]); renderUptime(data.uptime||{}); renderAlerts(data.alerts||[]); if(s.vps) renderVps(s.vps);
}
async function refresh(){
  try{
    const d=await api('/api/v1/state');
    if(!d.ok && d.error) throw new Error(d.error);
    renderAll(d);
    const v=await api('/api/v1/vps');
    renderVps(v.vps||[]);
  }catch(e){ if(!e.message.includes('No autorizado') && !e.message.includes('Rate limited')) document.getElementById('sub').textContent='error: '+e.message; }
}
async function refreshEvents(){ try{ const d=await api('/api/v1/events?limit=50'); renderEvents(d.events||[]); }catch(e){} }
let WS=null; let wsTries=0;
function connectWS(){
  const proto=location.protocol==='https:'?'wss:':'ws:';
  const url=proto+'//'+location.host+'/ws?token='+encodeURIComponent(TOKEN);
  try{ WS=new WebSocket(url); }catch(e){ setTimeout(connectWS, 5000); return; }
  WS.onopen=()=>{ document.getElementById('ws-dot').className='ws-status ws-on'; document.getElementById('ws-dot').title='WebSocket conectado'; wsTries=0; };
  WS.onclose=()=>{ document.getElementById('ws-dot').className='ws-status ws-off'; document.getElementById('ws-dot').title='WebSocket desconectado'; WS=null; wsTries++; setTimeout(connectWS, Math.min(3000*wsTries, 15000)); };
  WS.onerror=()=>{ try{WS.close();}catch(e){} };
  WS.onmessage=(e)=>{
    try{
      const msg=JSON.parse(e.data);
      if(msg.type==='state'){ renderAll(msg.data); }
      else if(msg.type==='event'){ appendEvent(msg.data); }
      else if(msg.type==='toast'){ toast(msg.message, msg.kind||'info'); activity(msg.message, msg.kind||'info'); }
      else if(msg.type==='refresh'){ refresh(); refreshEvents(); }
    }catch(err){}
  };
}
setTimeout(connectWS, 400);
setTimeout(()=>{ if(!WS || WS.readyState!==1){ refresh(); refreshEvents(); }}, 5000);
setInterval(()=>{ if(!WS || WS.readyState!==1) refresh(); }, 10000);
setInterval(()=>{ if(!WS || WS.readyState!==1) refreshEvents(); }, 15000);
</script>
</body>
</html>

"""

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login - Port Forwarding Manager</title>
<style>
  :root { --bg:#0f1419; --card:#1a212b; --line:#2b3644; --text:#d7e0ea; --muted:#7d8ca1; --ok:#34c759; --err:#ff453a; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:system-ui,Segoe UI,sans-serif; background:var(--bg); color:var(--text);
         display:flex; align-items:center; justify-content:center; min-height:100vh; padding:16px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:24px; width:100%; max-width:380px; }
  h1 { font-size:18px; margin:0 0 4px; }
  .sub { color:var(--muted); font-size:13px; margin-bottom:16px; }
  input { width:100%; padding:8px 10px; border-radius:6px; border:1px solid var(--line); background:var(--bg); color:var(--text); font-size:14px; margin-bottom:12px; }
  button { width:100%; background:#2563eb; border:0; color:#fff; padding:8px 12px; border-radius:6px; cursor:pointer; font-size:14px; }
  button:hover { filter:brightness(1.15); }
  button:disabled { opacity:.5; cursor:not-allowed; }
  #msg { font-size:13px; margin-top:10px; min-height:18px; }
  #msg.err { color:var(--err); }
  #msg.ok { color:var(--ok); }
  #msg.warn { color:var(--warn); }
</style>
</head>
<body>
<div class="card">
  <h1>Port Forwarding Manager</h1>
  <div class="sub">Introduce el token del panel web</div>
  <input id="token" type="password" placeholder="Token" autocomplete="current-password">
  <button id="btn" onclick="doLogin()">Entrar</button>
  <div id="msg"></div>
</div>
<script>
function setMsg(text, cls){
  const el=document.getElementById('msg');
  el.textContent=text;
  el.className=cls||'';
}
async function doLogin(){
  const token=document.getElementById('token').value.trim();
  if(!token){ setMsg('Introduce el token','err'); return; }
  const btn=document.getElementById('btn');
  btn.disabled=true;
  setMsg('Verificando...','');
  try{
    const r=await fetch('/api/v1/login', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({token})});
    const d=await r.json();
    if(r.status===429){
      setMsg(d.error||'Demasiados intentos, espera','err');
      const retry=r.headers.get('Retry-After');
      if(retry) setMsg('Bloqueado '+retry+'s por demasiados intentos','err');
      btn.disabled=false;
      return;
    }
    if(!r.ok || !d.ok){
      const remaining=r.headers.get('X-RateLimit-Remaining');
      let msg=d.error||'Token invalido';
      if(remaining!==null) msg+=' ('+remaining+' intentos restantes)';
      setMsg(msg,'err');
      btn.disabled=false;
      return;
    }
    localStorage.setItem('pf_token', token);
    setMsg('Login correcto, redirigiendo...','ok');
    setTimeout(()=>{ window.location.href='/'; }, 600);
  }catch(e){
    setMsg('Error: '+e.message,'err');
    btn.disabled=false;
  }
}
document.getElementById('token').addEventListener('keydown', e=>{ if(e.key==='Enter') doLogin(); });
</script>
</body>
</html>
"""
