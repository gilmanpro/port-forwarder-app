"""Tests del panel web local (10.5): endpoints, auth y acciones."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from unittest import mock

import pytest

from src.core.config import Bind, ConfigStore, Tunnel, TunnelHealthGate, Vps
from src.core.metrics_store import MetricsStore
from src.core.supervisor import Supervisor
from src.web.server import WebPanel


@pytest.fixture
def env(tmp_path):
    store = ConfigStore(path=str(tmp_path / "config.json"))
    store.add_vps(Vps(id="v1", host="vps.example.com", user="tunnel"))
    store.cfg.tunnels.append(Tunnel(
        id="t1", vps_id="v1", local_bind=Bind(port=3000),
        remote_binds=[Bind(host="0.0.0.0", port=80)],
        health_gate=TunnelHealthGate(enabled=False),
    ))
    metrics = MetricsStore(str(tmp_path / "metrics.db"))
    sup = mock.Mock(spec=Supervisor)
    sup.metrics = metrics
    sup.store = store
    sup.netsh = mock.Mock()
    sup.ssh = mock.Mock()
    sup.running = True
    sup.maintenance = False
    sup.interval = 10
    sup.last_cycle = 0
    sup.status.return_value = {
        "running": True,
        "maintenance": False,
        "interval_seconds": 10,
        "last_cycle_ts": 0,
        "admin": False,
        "forwards": [{"id": "f1", "listen_port": 8080, "wsl_distro": "ubuntu",
                      "wsl_port": 3000, "protocol": "tcp", "auto_apply": True,
                      "state": "ok", "ip": "172.18.0.2"}],
        "tunnels": [{"id": "t1", "type": "ssh", "vps_id": "v1",
                     "local": "127.0.0.1:3000", "remote": ["0.0.0.0:80"],
                     "auto_start": True, "state": "running"}],
    }
    return store, sup, metrics


@pytest.fixture
def panel(env, tmp_path):
    store, sup, metrics = env
    p = WebPanel(sup, port=0, bind="127.0.0.1")
    p.start()
    yield p
    p.stop()


def _get(panel: WebPanel, path: str, token: str = "") -> tuple[int, dict]:
    req = urllib.request.Request(f"http://127.0.0.1:{panel.port}{path}")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def _post(panel: WebPanel, path: str, token: str = "",
          origin: str | None = "match", body: dict | None = None) -> tuple[int, dict]:
    payload = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        f"http://127.0.0.1:{panel.port}{path}", method="POST", data=payload
    )
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if origin == "match":
        req.add_header("Origin", f"http://127.0.0.1:{panel.port}")
    elif origin:
        req.add_header("Origin", origin)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def test_dashboard_served(panel):
    with urllib.request.urlopen(
        f"http://127.0.0.1:{panel.port}/", timeout=10
    ) as r:
        assert r.status == 200
        assert "Port Forwarding Manager" in r.read().decode("utf-8")


def test_state_endpoint(panel, env):
    store, sup, metrics = env
    status, data = _get(panel, "/api/v1/state")
    assert status == 200
    assert data["ok"] is True
    assert data["status"]["forwards"][0]["id"] == "f1"
    assert data["status"]["tunnels"][0]["state"] == "running"


def test_events_endpoint(panel, env):
    store, sup, metrics = env
    metrics.record_event("forward_applied", forward_id="f1")
    status, data = _get(panel, "/api/v1/events?limit=10")
    assert status == 200
    assert any(e["type"] == "forward_applied" for e in data["events"])


def test_alerts_endpoint(panel, env):
    store, sup, metrics = env
    metrics.record_alert("tunnel_down", "algo paso")
    status, data = _get(panel, "/api/v1/alerts")
    assert status == 200
    assert len(data["alerts"]) == 1


def test_unknown_api_404(panel):
    status, data = _get(panel, "/api/v1/no-existe")
    assert status == 404
    assert data["ok"] is False


def test_token_required(env, tmp_path):
    store, sup, metrics = env
    p = WebPanel(sup, port=0, bind="127.0.0.1", token="secreto")
    p.start()
    try:
        status, data = _get(p, "/api/v1/state")
        assert status == 401
        status, data = _get(p, "/api/v1/state", token="secreto")
        assert status == 200
        status, data = _get(p, "/api/v1/state", token="malo")
        assert status == 401
        # el dashboard HTML no requiere token (solo la API)
        with urllib.request.urlopen(f"http://127.0.0.1:{p.port}/", timeout=10) as r:
            assert r.status == 200
    finally:
        p.stop()


def test_post_forwards_apply(panel, env):
    store, sup, metrics = env
    status, data = _post(panel, "/api/v1/forwards/apply")
    assert status == 200
    assert data["ok"] is True
    sup.run_once.assert_called()


def test_csrf_allows_without_origin_for_api(panel):
    # Sin Origin/Referer = no es navegador (curl/script) -> permitir (auth sigue obligatoria)
    status, data = _post(panel, "/api/v1/forwards/apply", origin=None)
    assert status == 200
    assert data["ok"] is True


def test_csrf_rejects_evil_origin(panel):
    status, _ = _post(panel, "/api/v1/forwards/apply",
                      origin="https://evil.example.com")
    assert status == 403


def test_csrf_accepts_matching_origin(panel):
    status, data = _post(panel, "/api/v1/forwards/apply")
    assert status == 200
    assert data["ok"] is True


def test_csrf_rejects_evil_referer(panel):
    req = urllib.request.Request(
        f"http://127.0.0.1:{panel.port}/api/v1/forwards/apply", method="POST"
    )
    req.add_header("Referer", "https://evil.example.com/x")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            status = r.status
    except urllib.error.HTTPError as e:
        status = e.code
    assert status == 403


def test_security_headers_present(panel):
    with urllib.request.urlopen(
        f"http://127.0.0.1:{panel.port}/", timeout=10
    ) as r:
        headers = r.headers
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"
        assert "frame-ancestors 'none'" in headers.get(
            "Content-Security-Policy", "")
        assert headers.get("Referrer-Policy") == "no-referrer"


def test_dashboard_escapes_user_data(panel):
    """H2: el template del dashboard escapa todo lo interpolado."""
    html = panel.dashboard_html
    assert "function esc(v)" in html
    assert html.count("esc(") > 10
    # ningun sink directo sin escapar de campos de usuario
    assert "'<td>'+f.id+" not in html
    assert "'<td>'+t.id+" not in html
    assert "'+a.message+" not in html


def test_post_forwards_clear(panel, env):
    store, sup, metrics = env
    sup.netsh.clear_all.return_value = []
    status, data = _post(panel, "/api/v1/forwards/clear")
    assert status == 200
    assert data["ok"] is True
    sup.netsh.clear_all.assert_called()


def test_post_tunnel_start(panel, env):
    store, sup, metrics = env
    sup.ssh.is_alive.return_value = False
    status, data = _post(panel, "/api/v1/tunnels/t1/start")
    assert status == 200
    assert data["ok"] is True
    sup.ssh.start.assert_called_once()


def test_post_tunnel_start_unknown_tunnel(panel, env):
    store, sup, metrics = env
    status, data = _post(panel, "/api/v1/tunnels/no-existe/start")
    assert status == 200
    assert data["ok"] is False


def test_post_maintenance_on_off(panel, env):
    store, sup, metrics = env
    status, data = _post(panel, "/api/v1/maintenance/on")
    assert status == 200
    assert store.cfg.maintenance.active is True
    status, data = _post(panel, "/api/v1/maintenance/off")
    assert status == 200
    assert store.cfg.maintenance.active is False


# -- CRUD desde el panel web (paridad con la GUI) -------------------------------

def test_vps_list(panel, env):
    store, sup, metrics = env
    status, data = _get(panel, "/api/v1/vps")
    assert status == 200
    assert any(v["id"] == "v1" for v in data["vps"])


def test_forward_add_remove(panel, env):
    store, sup, metrics = env
    status, data = _post(panel, "/api/v1/forwards/add", body={
        "id": "web-f1", "listen_port": 9991, "distro": "ubuntu", "wsl_port": 3001,
    })
    assert status == 200 and data["ok"] is True
    assert store.get_forward("web-f1") is not None
    status, data = _post(panel, "/api/v1/forwards/remove/web-f1")
    assert status == 200 and data["ok"] is True
    assert store.get_forward("web-f1") is None


def test_forward_add_missing_fields(panel):
    status, data = _post(panel, "/api/v1/forwards/add", body={"id": "x"})
    assert data["ok"] is False


def test_tunnel_add_remove(panel, env):
    store, sup, metrics = env
    status, data = _post(panel, "/api/v1/tunnels/add", body={
        "id": "web-t1", "vps_id": "v1", "local": "127.0.0.1:4000",
        "remotes": ["0.0.0.0:8081"], "auto_start": False,
    })
    assert status == 200 and data["ok"] is True, data
    assert store.get_tunnel("web-t1") is not None
    status, data = _post(panel, "/api/v1/tunnels/remove/web-t1")
    assert status == 200 and data["ok"] is True
    assert store.get_tunnel("web-t1") is None


def test_tunnel_add_unknown_vps(panel, env):
    store, sup, metrics = env
    status, data = _post(panel, "/api/v1/tunnels/add", body={
        "id": "web-t2", "vps_id": "no-existe", "local": "127.0.0.1:4000",
        "remotes": ["0.0.0.0:8081"],
    })
    assert data["ok"] is False


def test_vps_add_remove(panel, env):
    store, sup, metrics = env
    status, data = _post(panel, "/api/v1/vps/add", body={
        "id": "web-v1", "host": "vps2.example.com", "user": "root",
    })
    assert status == 200 and data["ok"] is True
    assert store.get_vps("web-v1") is not None
    status, data = _post(panel, "/api/v1/vps/remove/web-v1")
    assert status == 200 and data["ok"] is True
    assert store.get_vps("web-v1") is None


def test_vps_add_with_password(panel, env):
    store, sup, metrics = env
    status, data = _post(panel, "/api/v1/vps/add", body={
        "id": "web-vp", "host": "vps3.example.com", "user": "root",
        "password": "clave-secreta",
    })
    assert status == 200 and data["ok"] is True
    v = store.get_vps("web-vp")
    assert v is not None and v.password == "clave-secreta"
    store.remove_vps("web-vp")


def test_crud_requires_token(env, tmp_path):
    store, sup, metrics = env
    p = WebPanel(sup, port=0, bind="127.0.0.1", token="secreto")
    p.start()
    try:
        status, data = _post(p, "/api/v1/forwards/add", body={
            "id": "x", "listen_port": 1, "wsl_port": 1,
        })
        assert status == 401
        status, data = _post(p, "/api/v1/vps/add", body={"id": "x", "host": "h", "user": "u"},
                             token="secreto")
        assert status == 200 and data["ok"] is True
    finally:
        p.stop()
