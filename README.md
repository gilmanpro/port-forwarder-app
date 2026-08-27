# Port Forwarding Manager

[![Licencia](https://img.shields.io/badge/Licencia-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Plataforma](https://img.shields.io/badge/Plataforma-Windows%20%7C%20Linux%20%7C%20Docker-0078D6?logo=windows&logoColor=white)](#requisitos)
[![Tests](https://img.shields.io/badge/Tests-147%2F147%20passed-2ea44f)](#tests)

> Gestión de **redirección de puertos Windows → WSL** (netsh portproxy + firewall) y **túneles SSH hacia VPS**, con supervisor automático, health checks, alertas, programador, perfiles, panel web y CLI completo con **paridad garantizada** con la GUI.

### Ecosistema

| Repositorio | Descripción |
|---|---|
| **[wsl-port](https://github.com/gilmanpro/wsl-port)** | ⭐ **App unificada** — WSL Manager + Port Forwarder en 1 clic (recomendada) |
| [wsl-manager-gui](https://github.com/gilmanpro/wsl-manager-gui) | Base de gestión WSL — vendored en wsl-port |
| **port-forwarder-app** (este repo) | Base de port forwarding — vendored en wsl-port |

> **Recomendado:** usa **[wsl-port](https://github.com/gilmanpro/wsl-port)** que unifica ambas bases. Este repo sigue siendo útil de forma independiente y coexiste con wsl-manager-gui (puertos propios).

---

## Índice

- [Características](#características)
- [Capturas de la interfaz](#capturas-de-la-interfaz)
- [Requisitos](#requisitos)
- [Linux y Docker](#linux-y-docker)
- [Instalación](#instalación)
- [Uso rápido (CLI)](#uso-rápido-cli)
- [Panel web](#panel-web)
- [API REST](#api-rest)
- [MCP (agentes LLM)](#mcp-agentes-llm)
- [Seguridad](#seguridad)
- [Tests](#tests)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Packaging](#packaging)
- [Desinstalación (completa)](#desinstalación-completa)
- [Contribuir](#contribuir)
- [Licencia](#licencia)

## Características

| Área | Funcionalidad |
|------|---------------|
| Forwards (F1-F8, F14) | CRUD, aplicar/limpiar (netsh + firewall), test TCP, detector de conflictos, clone |
| Tunnels (T1-T6) | SSH reverse multi-puerto, start/stop/restart, health gate, latency, clone |
| Supervisor (12.3) | Loop único: IPs WSL cambian → reaplica; tunnel muerto → backoff + restart; health gate pausa forwards sin servicio |
| Monitoring (M3-M6) | Health checks, alertas (SQLite), portmap, conexiones activas, **tráfico por túnel** (bytes acumulados + velocidad) |
| Automatización (A2-A3) | Scheduler por días/hora, perfiles de exposición (capture/apply) |
| Seguridad (13) | Secrets cifrados con DPAPI, redactor de secretos en logs, backups de config, journal en SQLite |
| Diagnóstico (U7-U8) | `doctor` (detector de problemas), `diag` (bundle sin secretos), `drift` (config vs realidad) |
| **Panel web (10.5)** | Dashboard HTML en `127.0.0.1:8794` + API JSON `/api/v1`, **token obligatorio** (DPAPI), uptime de túneles |
| **API REST (21)** | `/api/v1` completa con tokens Bearer + scopes read/write/admin, rate limit y auditoría |
| **MCP (21.4)** | Servidor stdio JSON-RPC (`mcp serve`) con 29 tools mapeadas al CLI |
| GUI (7) | Tray + ventana con pestañas (requiere extras opcionales) |

## Capturas de la interfaz

| | |
|---|---|
| ![Forwards](assets/screenshots/pf-forwards.png) | ![Tunnels](assets/screenshots/pf-tunnels.png) |
| *Forwards: redirección Windows → WSL (netsh + firewall)* | *Tunnels: túneles SSH hacia VPS + gestión de servidores VPS (nuevo/editar/eliminar)* |
| ![Logs](assets/screenshots/pf-logs.png) | ![Ajustes](assets/screenshots/pf-ajustes.png) |
| *Logs: últimas líneas de port-forwarder.log* | *Ajustes: clave del panel web, MCP y API* |

### Panel web (http://127.0.0.1:8794)

![Panel web de Port Forwarding](assets/screenshots/web-pf.png)

*Dashboard web con estado de forwards/túneles, uptime, alertas y eventos. Requiere el token configurado en Ajustes o con `secrets set web_panel_token`.*

## Requisitos

- **Windows 10/11** con `netsh.exe`, `ssh.exe` y `wsl.exe` (System32).
- **Python 3.11+** (core sin dependencias externas).
- Una distro WSL real (ej. `ubuntu`) para forwards; un VPS con `GatewayPorts yes` para túneles.
- Admin (UAC) solo para aplicar forwards — el resto corre sin elevación.

## Linux y Docker

El **core es multiplataforma** (Python 3.11+): panel web, supervisor, túneles SSH,
API REST, MCP, programador, perfiles, alertas y CLI funcionan en Linux y macOS
sin dependencias externas. Los **forwards** funcionan en **Windows** (`netsh portproxy`
+ firewall) y en **Linux/Docker** (`socat` TCP-LISTEN → destino).

> **Reenvío en Linux/Docker:** requiere `socat` (`apt-get install socat`). En Docker
> la imagen ya lo trae. Para puertos <1024 y reenvío host real, el contenedor
> necesita `cap_add: [NET_ADMIN, NET_RAW]` y/o `network_mode: host` (ver `docker-compose.yml`).

### Ejecutar en Linux (sin contenedor)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .  # core, sin extras de GUI

port-forwarder doctor                              # entornos no soportados: avisa
port-forwarder vps add --id vps-main --host vps.example.com --user tunnel --identity ~/.ssh/wsl-manager-main
port-forwarder tunnels add --id tunnel-web --vps vps-main --local 127.0.0.1:8080 --remote 0.0.0.0:80
port-forwarder web start                           # panel web + supervisor en foreground
```

Los datos viven en `$XDG_CONFIG_HOME/PortForwarder` o `~/.config/PortForwarder` y los
logs en `$XDG_DATA_HOME/PortForwarder/logs`.

### Contenedor Docker

```bash
# clave del panel (si se omite, el entrypoint la genera y la muestra en los logs)
export PF_WEB_TOKEN=mi-clave-secreta

docker compose build
docker compose up -d
# panel web en http://localhost:8794 (requiere la clave)
```

- Imagen: `python:3.11-slim` + `openssh-client` (para los túneles SSH).
- Volumen `pf-data` en `/data` (config, secrets, métricas, pidfiles) — es persistente.
- Opcional: monta tus claves SSH con `- ${USERPROFILE}/.ssh:/root/.ssh:ro` en `docker-compose.yml`.
- Puertos: `8794` panel web · `8795` API REST · `8796` MCP (si se activan).
  No chocan con wsl-manager-gui (que usa 8790/8791/8792): ambas apps pueden
  correr a la vez en la misma máquina.

## Instalación

```powershell
# Desde el repo:
git clone https://github.com/gilmanpro/port-forwarder-app
cd port-forwarder-app
python -m venv .venv
.venv\Scripts\activate
pip install -e .              # core + CLI (cero dependencias externas)

# (Opcional) extras de GUI:
pip install -e ".[gui]"

# (Opcional) para ejecutar los tests: añade pytest
pip install -e ".[dev]"
```

> **¿No quieres tocar código?** Usa los ejecutables ya compilados de la carpeta
> `ejecutables\port-forwarder\` (CLI) y `ejecutables\port-forwarder-window\` (GUI).

Config inicial en `%APPDATA%\PortForwarder\config.json` (auto-creada).
Ejemplo completo: `config/config.example.json`.

## Uso rápido (CLI)

```bash
port-forwarder doctor                          # entorno sano?
port-forwarder status --json                   # estado global

# Forward Windows -> WSL (pide UAC al aplicar)
port-forwarder forwards add --id fwd-web --listen-port 8080 --distro ubuntu-dev --wsl-port 8080 --auto-apply
port-forwarder forwards test fwd-web
port-forwarder forwards conflicts 8080

# Tunnel hacia VPS (prepara el VPS con vps/install.sh y scripts/setup_ssh_key.ps1)
port-forwarder vps add --id vps-main --host vps.example.com --user tunnel --identity "%USERPROFILE%\.ssh\wsl-manager-main"
port-forwarder tunnels add --id tunnel-web --vps vps-main --local 127.0.0.1:8080 --remote 0.0.0.0:80
port-forwarder tunnels start tunnel-web
port-forwarder tunnels status tunnel-web --json   # incluye "traffic" (rx/tx + velocidad)
```

> Los **VPS también se gestionan desde la app de escritorio**: pestaña *Tunnels*
> → sección **Servidores VPS** (listar, nuevo, editar y eliminar), con aviso si
> un VPS está en uso por túneles.
>
> 📘 **Manual completo:** [publicar servicios de WSL en Internet a través de tu
> VPS](docs/manual-wsl-vps.md).
>
> **Keepalive para túneles estables** (evita cortes por NAT/firewall): el cliente
> lanza **autossh** (si está instalado) con `-M 0 -o ServerAliveInterval=30 -o
> ServerAliveCountMax=3 -o TCPKeepAlive=yes -o ExitOnForwardFailure=yes -o
> ConnectTimeout=10`; si no hay autossh, usa `ssh` con las mismas opciones. En el
> VPS se configura `ClientAliveInterval 60` / `ClientAliveCountMax 3` /
> `TCPKeepAlive yes` (incluido en `vps/sshd_config.snippet` y `vps/install.sh`).
>
> Para forzar/indicar autossh: `config.json` → `windows.autossh_exe` (ruta al
> binario). Instalación: `scripts/install_autossh.sh` (en WSL/Linux).

# Supervisión
port-forwarder supervise                      # supervisor headless (Ctrl+C)
port-forwarder watch --json                   # eventos en vivo
port-forwarder health check --json
port-forwarder alerts list
```

## Panel web

```bash
# Token del panel (OBLIGATORIO, cifrado DPAPI; sin él `web start` no arranca):
printf 'mi-token' | port-forwarder secrets set web_panel_token

# También puedes configurarlo desde la app de escritorio:
# port-forwarder-window -> pestaña Ajustes -> Panel web -> Clave.

port-forwarder web start                       # dashboard en http://127.0.0.1:8794
port-forwarder web status --json
port-forwarder web stop

# Desde el móvil (misma red), con token obligatorio:
port-forwarder web start --bind 0.0.0.0        # exige token configurado
```

El dashboard muestra forwards/tunnels con estado en vivo, alertas, uptime de túneles y journal de eventos; permite reaplicar forwards, limpiar, arrancar/detener túneles y activar mantenimiento desde el navegador. API JSON en `/api/v1/*` (Bearer token obligatorio).

> **Seguridad:** los POST del panel exigen `Origin`/`Referer` del mismo host (CSRF).
> Si automatizas con curl, añade `-H "Origin: http://127.0.0.1:8794"`. El token se
> guarda cifrado en secrets (DPAPI): `secrets set web_panel_token`.

## API REST

```bash
port-forwarder api enable --port 8795          # activa (token obligatorio)
port-forwarder api tokens create --scope admin # muestra el token UNA sola vez
port-forwarder api tokens list
port-forwarder api serve                       # corre la API en foreground
```

> El token también se puede crear desde la app de escritorio
> (`port-forwarder-window` → Ajustes → API REST → Generar token API).

Endpoints en `http://127.0.0.1:8795/api/v1` (tabla completa en el plan, 21.3): `status`, `forwards` (CRUD/apply/clear/test/conflicts), `tunnels` (CRUD/start/stop/restart), `vps`, `health`, `alerts`, `schedule`, `profiles`, `maintenance`, `drift`, `secrets/check`, `doctor`. Scopes: `read` < `write` < `admin` (destructivos exigen `?confirm=1`). Rate limit 120 req/min read, 30 write. Auditoría de cada llamada en SQLite.

## MCP (agentes LLM)

```bash
port-forwarder mcp test                        # self-test del handshake
PORT_FORWARDER_TOKEN=<token> port-forwarder mcp serve   # stdio
```

Configuración en el cliente (Zed / Claude Code / cursor):

```json
{ "mcpServers": { "port-forwarder": {
  "command": "port-forwarder", "args": ["mcp", "serve"],
  "env": { "PORT_FORWARDER_TOKEN": "<token>" } } } }
```

## Seguridad

- Secrets cifrados con **DPAPI** (CurrentUser) en `secrets.json`; nunca en claro.
- Redactor global de secretos en logs y bundles de diagnóstico (`diag`).
- CSRF protegido en el panel web (Origin/Referer) + headers de seguridad.
- Backups automáticos de config antes de cada escritura.
- API REST con tokens hash + scopes + rate limit + auditoría en SQLite.
- UAC selectivo: solo aplicar/limpiar forwards elevan.

## Tests

```bash
pip install -e ".[dev]"      # añade pytest (el core no necesita dependencias)

python -m pytest tests/unit -q          # unit (sin admin)
python -m pytest tests/test_cli.py -q   # smoke del CLI (sin admin)
python -m pytest tests -m integration   # E2E real (requiere admin + distro WSL)
```

## Estructura del proyecto

```
src/
├── app.py                 # Entry GUI (tray + ventana, extras opcionales)
├── core/                  # config, supervisor, scheduler, metrics, profiles, notifier, power_events
├── providers/             # netsh, wsl_ip, ssh_tunnel, tailscale, cloudflare (paridad GUI/CLI/web)
├── cli/                   # port-forwarder (argparse, cero dependencias)
├── api/                   # REST /api/v1 + AuthService (tokens, scopes, rate limit)
├── mcp/                   # servidor MCP stdio (JSON-RPC)
├── web/                   # panel web stdlib + API JSON
├── gui/                   # ventana tkinter + tray (opcional)
└── utils/                 # subprocess, paths, secrets DPAPI
scripts/                   # setup_ssh_key.ps1, check_environment.ps1, install_autossh.sh, smoke_web_live.py, build.ps1
vps/                       # sshd_config.snippet + install.sh
skills/port-forwarder-cli/ # skill para agentes LLM
```

## Packaging

```powershell
pip install pyinstaller
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
# -> dist\port-forwarder\port-forwarder.exe  (+ PortForwarder-Setup.exe si hay Inno Setup)
```

> Si el `python` del PATH no tiene PyInstaller (p. ej. apunta a otro venv),
> usa el venv del proyecto directamente:
> ```powershell
> .venv\Scripts\python.exe -m PyInstaller --clean --noconfirm scripts\port-forwarder.spec
> ```

## Desinstalación (completa)

Pasos para quitar **toda** huella de la app en Windows. Ejecuta en PowerShell
**como administrador** cuando se indique.

1. **Detener la app** (panel web + supervisor y cualquier proceso restante):
   ```powershell
   .\port-forwarder.exe web stop          # si está en foreground desde CLI
   Stop-Process -Name "port-forwarder" -Force -ErrorAction SilentlyContinue
   Stop-Process -Name "port-forwarder-window" -Force -ErrorAction SilentlyContinue
   ```

2. **Quitar el autoarranque** (entrada de registro del lanzador `.vbs`):
   ```powershell
   Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "PortForwarder" -ErrorAction SilentlyContinue
   ```

3. **Borrar datos y logs** (config, secrets cifrados con DPAPI, métricas, backups):
   ```powershell
   Remove-Item "$env:APPDATA\PortForwarder"      -Recurse -Force
   Remove-Item "$env:LOCALAPPDATA\PortForwarder" -Recurse -Force
   ```

4. **Limpiar los forwards aplicados** (si había portproxies/firewall activos):
   ```powershell
   .\port-forwarder.exe forwards clear    # requiere admin
   ```

5. **Borrar los ejecutables** (si usabas los `.exe` compilados):
   ```powershell
   Remove-Item ".\ejecutables\port-forwarder"        -Recurse -Force
   Remove-Item ".\ejecutables\port-forwarder-window" -Recurse -Force
   ```

6. **Borrar el entorno virtual** (si instalaste desde el código):
   ```powershell
   Remove-Item ".\proyectos\port-forwarder-app\.venv" -Recurse -Force
   ```

7. **Docker** (si lo usaste con contenedor; Docker Desktop en sí es aparte):
   ```powershell
   docker compose down --volumes   # desde el repo: borra contenedor, imagen y volumen pf-data
   ```

8. **Verificar que no queda nada**:
   ```powershell
   Get-Process -Name "port-forwarder" -ErrorAction SilentlyContinue              # nada
   Get-NetTCPConnection -LocalPort 8794,8795,8796 -State Listen -ErrorAction SilentlyContinue  # nada
   Test-Path "$env:APPDATA\PortForwarder"                                          # False
   ```

> El código fuente (`proyectos\port-forwarder-app`) y los repos de GitHub se
> conservan; puedes reinstalar cuando quieras siguiendo la sección
> [Instalación](#instalación).

## Contribuir

1. Haz un fork del repositorio.
2. Crea una rama: `git checkout -b feature/mi-mejora`.
3. Haz tus cambios y asegúrate de que pasan los tests (`pytest tests/unit -q`).
4. Envía un pull request describiendo el cambio.

Reporta bugs o pide funciones en
[Issues](https://github.com/gilmanpro/port-forwarder-app/issues).

## Licencia

[MIT](LICENSE) © 2026 — gilbertomanc. Ver también el [CHANGELOG](CHANGELOG.md).