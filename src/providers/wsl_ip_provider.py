"""WslIpProvider: deteccion de IPs de distros WSL con cache (seccion 8.1).

La IP NAT cambia tras `wsl --shutdown` (advertencia 8.2): la app SIEMPRE
obtiene la IP al momento de aplicar y el Supervisor reaplica si detecta
cambio. La cache evita invocar wsl.exe en cada tick del loop.

Comando: wsl.exe -d <distro> hostname -I  ->  "172.18.0.2 172.18.0.3 ..."
"""

from __future__ import annotations

import re
import subprocess
import time

from src.utils import subprocess_async as sp

_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


class WslIpError(Exception):
    pass


class WslIpProvider:
    def __init__(
        self,
        wsl_exe: str | None = None,
        cache_ttl: float = 30.0,
        timeout: float = 8.0,
    ) -> None:
        import sys as _sys

        if wsl_exe is None:
            wsl_exe = (r"C:\Windows\System32\wsl.exe"
                       if _sys.platform == "win32" else "wsl")
        self.wsl_exe = wsl_exe
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self._cache: dict[str, tuple[float, str | None]] = {}

    def get_ip(self, distro: str) -> str | None:
        """Primera IP de la distro (hostname -I). None si la distro no responde."""
        now = time.monotonic()
        cached = self._cache.get(distro)
        if cached and now - cached[0] < self.cache_ttl:
            return cached[1]
        try:
            proc = sp.run(
                [self.wsl_exe, "-d", distro, "hostname", "-I"],
                timeout=self.timeout,
                check=False,
                breaker=False,  # sondeo IP no fatal: no abre cortocircuito
            )
        except (OSError, subprocess.TimeoutExpired):
            self._cache[distro] = (now, None)
            return None
        if proc.returncode != 0:
            self._cache[distro] = (now, None)
            return None
        m = _IP_RE.search(proc.stdout or "")
        ip = m.group(1) if m else None
        self._cache[distro] = (now, ip)
        return ip

    def get_all_ips(self, distros: list[str]) -> dict[str, str | None]:
        return {d: self.get_ip(d) for d in dict.fromkeys(distros)}

    def invalidate(self, distro: str | None = None) -> None:
        if distro:
            self._cache.pop(distro, None)
        else:
            self._cache.clear()

    def list_distros(self) -> list[str]:
        """Nombres de distros instaladas (wsl -l -q), para la GUI/CLI."""
        try:
            proc = sp.run([self.wsl_exe, "-l", "-q"], timeout=30.0, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return []
        names: list[str] = []
        for line in (proc.stdout or "").splitlines():
            line = line.strip().replace("\x00", "")
            if line and line not in names:
                names.append(line)
        return names
