"""Helpers de subprocess para Windows: ventanas ocultas, timeouts, powershell.

Regla del plan (13.2): UAC selectivo solo al aplicar forwards; el resto de
comandos corren sin elevacion y sin ventanas emergentes.

Circuit breaker para wsl.exe (portado de wsl-port):
- Serializacion wsl.exe + cortocircuito 30s evita colgados en cascada.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from typing import Sequence

CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
DETACHED_PROCESS = 0x00000008 if sys.platform == "win32" else 0

POWERSHELL_EXE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

_WSL_LOCK = threading.Lock()
_BREAKER_OPEN = False
_BREAKER_UNTIL = 0.0
_BREAKER_COOLDOWN = 30.0


def _is_wsl(args: Sequence[str]) -> bool:
    if not args:
        return False
    base = os.path.basename(str(args[0])).lower()
    return base in ("wsl", "wsl.exe")


def _breaker_check() -> bool:
    global _BREAKER_OPEN, _BREAKER_UNTIL
    if not _BREAKER_OPEN:
        return False
    if time.time() >= _BREAKER_UNTIL:
        _BREAKER_OPEN = False
        return False
    return True


def _breaker_open_now() -> None:
    global _BREAKER_OPEN, _BREAKER_UNTIL
    _BREAKER_OPEN = True
    _BREAKER_UNTIL = time.time() + _BREAKER_COOLDOWN


def _kill_tree(pid: int) -> None:
    """Mata el proceso y su arbol (solo PID, no /IM wsl.exe)."""
    try:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True, timeout=5,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception:
        pass


def reset_breaker() -> None:
    global _BREAKER_OPEN, _BREAKER_UNTIL
    _BREAKER_OPEN = False
    _BREAKER_UNTIL = 0.0


def breaker_state() -> dict:
    return {"open": _BREAKER_OPEN, "until": _BREAKER_UNTIL, "cooldown": _BREAKER_COOLDOWN}


def _creation_flags() -> int:
    return CREATE_NO_WINDOW


def run(
    args: Sequence[str],
    timeout: float = 10.0,
    check: bool = True,
    input_text: str | None = None,
    env: dict | None = None,
    breaker: bool = True,
) -> subprocess.CompletedProcess:
    """Ejecuta un comando sin ventana; lanza CalledProcessError si falla.

    Devuelve CompletedProcess con texto decodificado (utf-8 con fallback).
    breaker=True: timeout abre cortocircuito 30s (comandos criticos).
    breaker=False: timeout no abre cortocircuito (sondeos IP no fatales).
    """
    is_wsl = _is_wsl(args)

    if is_wsl and breaker and _breaker_check():
        proc = subprocess.CompletedProcess(
            list(args), -1, "", "WSL no responde (cortocircuito)"
        )
        if check:
            raise subprocess.CalledProcessError(-1, list(args), "", "WSL no responde (cortocircuito)")
        return proc

    if is_wsl:
        _WSL_LOCK.acquire()
    try:
        # Usar Popen para permitir tree-kill en timeout
        proc_obj = subprocess.Popen(
            list(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if input_text is not None else None,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=_creation_flags(),
            env=env,
        )
        try:
            stdout, stderr = proc_obj.communicate(
                input=input_text, timeout=timeout
            )
        except subprocess.TimeoutExpired:
            proc_obj.kill()
            if is_wsl:
                _kill_tree(proc_obj.pid)
                if breaker:
                    _breaker_open_now()
            # Construir CompletedProcess de timeout
            cp = subprocess.CompletedProcess(
                list(args), -1, stdout or "", f"timeout tras {timeout}s"
            )
            if check:
                raise subprocess.CalledProcessError(-1, list(args), cp.stdout, cp.stderr)
            return cp
        # Decodificacion ya hecha por text=True; construir CompletedProcess
        cp = subprocess.CompletedProcess(
            list(args), proc_obj.returncode, stdout or "", stderr or ""
        )
        # Exito cierra breaker
        if is_wsl and cp.returncode == 0:
            global _BREAKER_OPEN, _BREAKER_UNTIL
            _BREAKER_OPEN = False
            _BREAKER_UNTIL = 0.0
    finally:
        if is_wsl:
            _WSL_LOCK.release()

    if check and cp.returncode != 0:
        raise subprocess.CalledProcessError(
            cp.returncode, list(args), cp.stdout, cp.stderr
        )
    return cp


def run_powershell(
    script: str,
    timeout: float = 60.0,
    check: bool = True,
    elevate: bool = False,
) -> subprocess.CompletedProcess:
    """Ejecuta un script PowerShell.

    elevate=True lanza con -Verb RunAs (UAC). Solo debe usarse para
    netsh/firewall (UAC selectivo, seccion 13.2 del plan).
    """
    if elevate:
        # Start-Process -Verb RunAs dispara el prompt UAC; no esperamos salida.
        ps = (
            f"Start-Process -FilePath '{POWERSHELL_EXE}' -Verb RunAs "
            f"-ArgumentList '-NoProfile','-ExecutionPolicy','Bypass',"
            f"'-EncodedCommand','{_b64(script)}' -Wait"
        )
        args = [POWERSHELL_EXE, "-NoProfile", "-NonInteractive", "-Command", ps]
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout + 30,
            creationflags=_creation_flags(),
        )
        return proc
    args = [POWERSHELL_EXE, "-NoProfile", "-NonInteractive", "-Command", script]
    return run(args, timeout=timeout, check=check, breaker=False)


def _b64(text: str) -> str:
    import base64

    return base64.b64encode(text.encode("utf-16-le")).decode("ascii")


def is_admin() -> bool:
    """True si el proceso actual tiene privilegios de administrador."""
    if sys.platform != "win32":
        return os_geteuid() == 0  # type: ignore[attr-defined]
    try:
        return run(
            [POWERSHELL_EXE, "-NoProfile", "-Command",
             "([Security.Principal.WindowsPrincipal]"
             "[Security.Principal.WindowsIdentity]::GetCurrent()"
             ").IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"],
            check=False,
            breaker=False,
        ).stdout.strip() == "True"
    except Exception:
        return False


def os_geteuid() -> int:
    import os

    return os.geteuid()  # type: ignore[attr-defined]
