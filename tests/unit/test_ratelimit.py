"""Tests de rate limiting para panel web login y MCP (igual en ambos)."""
from __future__ import annotations

import json
import urllib.request
import urllib.error

import pytest

from src.core.config import Bind, ConfigStore, Tunnel, TunnelHealthGate, Vps
from src.core.metrics_store import MetricsStore
from src.core.supervisor import Supervisor
from src.web.server import WebPanel
from src.mcp.server import McpServer
from src.api.service import AppService
from unittest import mock


@pytest.fixture
def env(tmp_path):
    store = ConfigStore(path=str(tmp_path / "config.json"))
    metrics = MetricsStore(str(tmp_path / "metrics.db"))
    sup = mock.Mock(spec=Supervisor)
    sup.metrics = metrics
    sup.store = store
    sup.netsh = mock.Mock()
    sup.ssh = mock.Mock()
    sup.running = True
    return store, sup, metrics


@pytest.fixture
def panel_with_token(env):
    store, sup, metrics = env
    p = WebPanel(sup, port=0, bind="127.0.0.1", token="secreto123")
    p.start()
    yield p
    p.stop()


def _post_login(panel, token, origin="http://127.0.0.1"):
    import urllib.request, urllib.error, json
    url = f"http://127.0.0.1:{panel.port}/api/v1/login"
    body = json.dumps({"token": token}).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if origin:
        req.add_header("Origin", origin)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def _get_state(panel, token=""):
    import urllib.request, urllib.error, json
    url = f"http://127.0.0.1:{panel.port}/api/v1/state"
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def test_login_ok(panel_with_token):
    status, data = _post_login(panel_with_token, "secreto123")
    assert status == 200
    assert data["ok"] is True


def test_login_bad_token_401(panel_with_token):
    status, data = _post_login(panel_with_token, "malo")
    assert status == 401
    assert data["ok"] is False


def test_login_rate_limit_429(panel_with_token):
    # 5 fallos -> 429 en el 6o
    for i in range(5):
        status, _ = _post_login(panel_with_token, f"malo{i}")
        assert status == 401, f"intento {i+1} debe ser 401"
    status, data = _post_login(panel_with_token, "malo_final")
    assert status == 429
    assert "demasiados intentos" in data["error"].lower()
    # Cabecera Retry-After presente
    # Probar que incluso token correcto esta bloqueado mientras dure el bloqueo
    status, data = _post_login(panel_with_token, "secreto123")
    assert status == 429


def test_login_success_resets_counter(panel_with_token):
    # 4 fallos, luego exito, luego 4 fallos mas no deben bloquear (contador reseteado)
    for i in range(4):
        _post_login(panel_with_token, f"bad{i}")
    status, data = _post_login(panel_with_token, "secreto123")
    assert status == 200
    # Ahora 4 fallos mas
    for i in range(4):
        status, _ = _post_login(panel_with_token, f"bad2_{i}")
        assert status == 401
    # El 5o fallo aun es 401, no 429 (porque se reseteo)
    status, _ = _post_login(panel_with_token, "bad_final")
    assert status == 401


def test_login_page_served(panel_with_token):
    import urllib.request
    url = f"http://127.0.0.1:{panel_with_token.port}/login"
    with urllib.request.urlopen(url, timeout=5) as r:
        assert r.status == 200
        html = r.read().decode()
        assert "Port Forwarding Manager" in html
        assert 'id="token"' in html


def test_api_rate_limit_on_bearer_failures(panel_with_token):
    # Fallos de Bearer en /api/v1/state tambien cuentan para rate limit
    for i in range(5):
        status, _ = _get_state(panel_with_token, token="malo")
        assert status == 401
    status, data = _get_state(panel_with_token, token="malo2")
    assert status == 429


def test_mcp_rate_limit():
    svc = AppService()
    mcp = McpServer(service=svc, token="secreto123")
    # 5 fallos
    for i in range(5):
        r = mcp.handle({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                        "params": {"name": "status", "arguments": {"token": f"bad{i}"}}})
        assert "error" in r
        assert r["error"]["code"] == -32001
    # 6o debe estar bloqueado
    r = mcp.handle({"jsonrpc": "2.0", "id": 99, "method": "tools/call",
                    "params": {"name": "status", "arguments": {"token": "bad_final"}}})
    assert "error" in r
    assert "demasiados intentos" in r["error"]["message"].lower()
    # Incluso token correcto bloqueado
    r = mcp.handle({"jsonrpc": "2.0", "id": 100, "method": "tools/call",
                    "params": {"name": "status", "arguments": {"token": "secreto123"}}})
    assert "error" in r
    assert "demasiados intentos" in r["error"]["message"].lower()


def test_mcp_success_resets():
    svc = AppService()
    mcp = McpServer(service=svc, token="secreto123")
    for i in range(4):
        mcp.handle({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                    "params": {"name": "status", "arguments": {"token": "bad"}}})
    r = mcp.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                    "params": {"name": "status", "arguments": {"token": "secreto123"}}})
    assert "result" in r
    # 4 fallos mas no deben bloquear
    for i in range(4):
        r = mcp.handle({"jsonrpc": "2.0", "id": 10+i, "method": "tools/call",
                        "params": {"name": "status", "arguments": {"token": "bad"}}})
        assert r["error"]["code"] == -32001
        assert "demasiados intentos" not in r["error"]["message"].lower()
