# /// script
# dependencies = ["mcp[cli]", "rich"]
# ///

import argparse
import json
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt
    from rich.table import Table
except Exception:  # pragma: no cover - fallback for very small installs
    Console = None
    Panel = None
    Prompt = None
    Confirm = None
    Table = None


APP_NAME = "ComputerBridge"
APP_ID = "computerbridge"
ROOT = Path(__file__).resolve().parent
SERVER_PATH = ROOT / "server.py"
DEFAULT_PORT = 8000


def user_dirs() -> dict[str, Path]:
    system = platform.system().lower()
    if system == "windows":
        roaming = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
        local = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
        config_dir = roaming / APP_NAME
        state_dir = local / APP_NAME
        log_dir = state_dir / "logs"
        runtime_dir = state_dir
    elif system == "darwin":
        support = Path.home() / "Library" / "Application Support" / APP_NAME
        config_dir = support
        state_dir = support
        log_dir = Path.home() / "Library" / "Logs" / APP_NAME
        runtime_dir = support
    else:
        config_dir = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")) / APP_ID
        state_dir = Path(os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state")) / APP_ID
        log_dir = state_dir / "logs"
        runtime_base = os.environ.get("XDG_RUNTIME_DIR")
        runtime_dir = (Path(runtime_base) / APP_ID) if runtime_base else state_dir
    for path in (config_dir, state_dir, log_dir, runtime_dir):
        path.mkdir(parents=True, exist_ok=True)
    return {
        "config": config_dir,
        "state": state_dir,
        "logs": log_dir,
        "runtime": runtime_dir,
    }


DIRS = user_dirs()
CONFIG_PATH = DIRS["config"] / "config.json"
PID_PATH = DIRS["runtime"] / "computerbridge.pid.json"
SERVER_LOG_PATH = DIRS["logs"] / "server.log"
NGROK_LOG_PATH = DIRS["logs"] / "ngrok.log"
LEGACY_CONFIG_PATH = ROOT / "config.json"
LEGACY_PID_PATHS = [ROOT / ".computerbridge.pid.json"]
OBSOLETE_PID_PATHS = [ROOT / ".localpilot.pid.json", DIRS["runtime"] / "localpilot.pid.json"]
LEGACY_LOG_PATHS = [(ROOT / "server.log", SERVER_LOG_PATH), (ROOT / "ngrok.log", NGROK_LOG_PATH)]


console = Console() if Console else None


def say(message: str = "", style: str | None = None) -> None:
    if console:
        console.print(message, style=style)
    else:
        print(message)


def ask(prompt: str, default: str | None = None) -> str:
    if console:
        console.print(f"{prompt}: ", end="")
    else:
        print(f"{prompt}: ", end="")
    value = input().strip()
    return value or (default or "")


def confirm(prompt: str, default: bool = True) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    if console:
        console.print(f"{prompt} {suffix}: ", end="")
    else:
        print(f"{prompt} {suffix}: ", end="")
    value = input().strip().lower()
    if not value:
        return default
    return value in {"y", "yes", "true", "1"}


def load_config() -> dict[str, Any]:
    migrate_legacy_files()
    if CONFIG_PATH.exists():
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    return {}


def save_config(config: dict[str, Any]) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")


def move_or_archive(src: Path, dest: Path) -> None:
    if not src.exists():
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    target = dest
    if target.exists():
        stamp = time.strftime("%Y%m%d-%H%M%S")
        target = dest.with_name(f"{dest.stem}-{stamp}{dest.suffix}")
    shutil.move(str(src), str(target))


def migrate_legacy_files() -> None:
    if LEGACY_CONFIG_PATH.exists() and LEGACY_CONFIG_PATH != CONFIG_PATH:
        move_or_archive(LEGACY_CONFIG_PATH, CONFIG_PATH)
    for legacy_pid in LEGACY_PID_PATHS:
        if legacy_pid.exists() and legacy_pid != PID_PATH:
            move_or_archive(legacy_pid, PID_PATH)
    for obsolete_pid in OBSOLETE_PID_PATHS:
        obsolete_pid.unlink(missing_ok=True)
    for legacy_log, new_log in LEGACY_LOG_PATHS:
        if legacy_log.exists() and legacy_log != new_log:
            move_or_archive(legacy_log, new_log)


def path_or_none(value: str | None) -> str | None:
    if value and Path(value).exists():
        return value
    return None


def detect_shells() -> list[dict[str, str]]:
    shells: list[dict[str, str]] = []
    system = platform.system().lower()
    if system == "windows":
        candidates = [
            ("PowerShell 7", shutil.which("pwsh.exe"), "recommended"),
            ("Windows PowerShell", shutil.which("powershell.exe"), "recommended"),
            ("Windows PowerShell", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "recommended"),
            ("Git Bash", r"C:\Program Files\Git\bin\bash.exe", ""),
            ("Git Bash", r"C:\Program Files (x86)\Git\bin\bash.exe", ""),
            ("Git Bash", shutil.which("bash.exe"), ""),
            ("Command Prompt", shutil.which("cmd.exe"), ""),
        ]
    else:
        candidates = [
            ("User shell", os.environ.get("SHELL"), "recommended"),
            ("bash", shutil.which("bash"), ""),
            ("zsh", shutil.which("zsh"), ""),
            ("sh", shutil.which("sh"), ""),
        ]

    seen: set[str] = set()
    for name, path, note in candidates:
        resolved = path_or_none(path)
        if not resolved:
            continue
        key = str(Path(resolved).resolve()).lower()
        if key in seen:
            continue
        seen.add(key)
        shells.append({"name": name, "path": str(Path(resolved).resolve()), "note": note})
    return shells


def detect_ngrok() -> str | None:
    candidates = [
        shutil.which("ngrok"),
        shutil.which("ngrok.exe"),
        str(Path.home() / "AppData/Local/Microsoft/WinGet/Packages/Ngrok.Ngrok_Microsoft.Winget.Source_8wekyb3d8bbwe/ngrok.exe"),
        str(Path.home() / "AppData/Local/Programs/ngrok/ngrok.exe"),
        "/usr/local/bin/ngrok",
        "/opt/homebrew/bin/ngrok",
    ]
    for candidate in candidates:
        resolved = path_or_none(candidate)
        if resolved:
            return str(Path(resolved).resolve())
    return None


def default_projects_root() -> str:
    return str(Path.home())


def port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", port)) != 0


def normalize_public_base_url(value: str) -> str:
    value = value.strip().rstrip("/")
    if value.endswith("/mcp"):
        value = value[:-4].rstrip("/")
    return value


def setup(_: argparse.Namespace) -> None:
    existing = load_config()
    shells = detect_shells()
    ngrok = detect_ngrok()

    if console and Panel:
        say(Panel.fit(
            "[bold]ComputerBridge setup[/bold]\nA small local bridge that lets ChatGPT use this computer for coding and desktop-adjacent work.",
            border_style="cyan",
        ))
    else:
        say("ComputerBridge setup")

    projects_default = existing.get("projects_root") or default_projects_root()
    projects_root = ask(f"Where are your projects located? Press Enter to use {projects_default}, or type your directory", projects_default)
    projects_root = str(Path(projects_root).expanduser().resolve())

    shell_choice = "auto"
    shell_path = ""
    if platform.system().lower() == "windows" and shells:
        recommended = shells[0]
        say()
        say(f"Shell: {recommended['name']} detected at {recommended['path']}", "cyan")
        if confirm("Use this shell automatically?", True):
            shell_choice = "auto"
            shell_path = recommended["path"]
        else:
            for idx, shell in enumerate(shells, 1):
                note = f" ({shell['note']})" if shell["note"] else ""
                say(f"{idx}. {shell['name']}{note}: {shell['path']}")
            raw = ask("Choose a shell number or paste a custom path. Press Enter to use 1", "1")
            if raw.isdigit() and 1 <= int(raw) <= len(shells):
                shell_choice = "selected"
                shell_path = shells[int(raw) - 1]["path"]
            else:
                shell_choice = "custom"
                shell_path = str(Path(raw).expanduser().resolve())
    elif platform.system().lower() == "windows":
        say("No PowerShell installation was detected automatically. ComputerBridge will try the system default shell.", "yellow")

    say()
    tunnel_default = existing.get("tunnel", "ngrok" if ngrok else "manual")
    say("How should ChatGPT reach this computer?", "cyan")
    say("- ngrok: ComputerBridge starts an ngrok tunnel for you.")
    say("- manual: you will provide your own public HTTPS tunnel or reverse proxy.")
    say("- later: skip the public URL for now.")
    tunnel = ask(f"Choose ngrok/manual/later. Press Enter to use {tunnel_default}", tunnel_default).lower()
    if tunnel not in {"ngrok", "manual", "later"}:
        tunnel = "manual"

    port_default = str(existing.get("port") or DEFAULT_PORT)
    port = int(ask(f"Local port for ComputerBridge. Press Enter to use {port_default} by default", port_default))
    if not port_available(port):
        say(f"Port {port} is already in use. That can be okay if ComputerBridge is already running.", "yellow")

    public_base_url = existing.get("public_base_url", "")
    if tunnel == "ngrok":
        if not ngrok:
            say("ngrok was not detected. You can install it later or paste a manual tunnel URL.", "yellow")
        say("Open ngrok.com, sign in, reserve or copy your HTTPS forwarding URL, then paste it here without /mcp.", "cyan")
        public_base_url = normalize_public_base_url(ask("Public ngrok base URL, without /mcp", ""))
    elif tunnel == "manual":
        say("Paste the public HTTPS base URL for your tunnel or reverse proxy, without /mcp.", "cyan")
        public_base_url = normalize_public_base_url(ask("Public HTTPS base URL, without /mcp", ""))
    else:
        public_base_url = ""

    start_on_login = confirm("Start automatically when this computer logs in?", bool(existing.get("start_on_login", platform.system().lower() == "windows")))

    config = {
        "app_name": APP_NAME,
        "projects_root": projects_root,
        "host": "127.0.0.1",
        "port": port,
        "public_base_url": public_base_url,
        "tunnel": tunnel,
        "ngrok_path": ngrok or "",
        "shell_choice": shell_choice,
        "shell_path": shell_path,
        "command_timeout_ms": int(existing.get("command_timeout_ms") or 300_000),
        "start_on_login": start_on_login,
        "auth": "none",
    }
    save_config(config)
    configure_startup(config) if start_on_login else None

    say()
    show_summary(config)
    say()
    start_now_prompt = "Start ComputerBridge now? Choose yes to use it immediately"
    if start_on_login:
        start_now_prompt += "; choose no to start it the next time this computer logs in"
    else:
        start_now_prompt += "; choose no to leave it stopped for now"
    if confirm(start_now_prompt, True):
        start(argparse.Namespace(foreground=False))
    elif start_on_login:
        say("ComputerBridge is configured to start the next time this computer logs in.", "cyan")
    else:
        say("ComputerBridge is configured but not running. Start it later with: computerbridge start", "cyan")


def configure_startup(config: dict[str, Any]) -> None:
    system = platform.system().lower()
    python = sys.executable
    command = f'"{python}" "{ROOT / "cli.py"}" start'
    if system == "windows":
        startup = Path(os.environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/Startup"
        startup.mkdir(parents=True, exist_ok=True)
        (startup / "computerbridge.bat").write_text(f"@echo off\nstart /min {command}\n", encoding="utf-8")
    elif system == "darwin":
        plist = Path.home() / "Library/LaunchAgents/com.computerbridge.mcp.plist"
        plist.write_text(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.computerbridge.mcp</string>
<key>ProgramArguments</key><array><string>{python}</string><string>{ROOT / "cli.py"}</string><string>start</string></array>
<key>RunAtLoad</key><true/>
<key>WorkingDirectory</key><string>{ROOT}</string>
</dict></plist>
""", encoding="utf-8")
    else:
        systemd = Path.home() / ".config/systemd/user"
        systemd.mkdir(parents=True, exist_ok=True)
        (systemd / "computerbridge.service").write_text(f"""[Unit]
Description=ComputerBridge MCP

[Service]
WorkingDirectory={ROOT}
ExecStart={python} {ROOT / "cli.py"} start --foreground
Restart=on-failure

[Install]
WantedBy=default.target
""", encoding="utf-8")


def show_summary(config: dict[str, Any]) -> None:
    mcp_url = f"{config['public_base_url']}/mcp" if config.get("public_base_url") else "(add a public URL later)"
    rows = [
        ("Projects", config["projects_root"]),
        ("Local server", f"http://{config['host']}:{config['port']}/mcp"),
        ("ChatGPT URL", mcp_url),
        ("Tunnel", config["tunnel"]),
        ("Shell", config.get("shell_path") or "auto"),
        ("Auth", "none"),
    ]
    if console and Table:
        table = Table(title="Setup complete")
        table.add_column("Setting", style="cyan")
        table.add_column("Value")
        for key, value in rows:
            table.add_row(key, str(value))
        console.print(table)
    else:
        for key, value in rows:
            print(f"{key}: {value}")


def server_command(config: dict[str, Any]) -> list[str]:
    return [
        sys.executable,
        str(SERVER_PATH),
        "--transport",
        "streamable-http",
        "--host",
        config.get("host", "127.0.0.1"),
        "--port",
        str(config.get("port", DEFAULT_PORT)),
    ]


def start(args: argparse.Namespace) -> None:
    config = load_config() or {
        "host": "127.0.0.1",
        "port": DEFAULT_PORT,
        "projects_root": default_projects_root(),
        "tunnel": "manual",
        "public_base_url": "",
        "command_timeout_ms": 300_000,
    }
    env = os.environ.copy()
    if config.get("shell_path"):
        env["LOCAL_CODING_MCP_SHELL"] = config["shell_path"]
    env["LOCAL_CODING_MCP_PROJECTS_ROOT"] = config.get("projects_root", default_projects_root())

    if args.foreground:
        os.execve(sys.executable, server_command(config), env)

    stop(argparse.Namespace())
    kill_existing_computerbridge_processes()
    server_log = SERVER_LOG_PATH.open("a", encoding="utf-8")
    ngrok_log = NGROK_LOG_PATH.open("a", encoding="utf-8")
    server = subprocess.Popen(server_command(config), cwd=str(ROOT), env=env, stdout=server_log, stderr=subprocess.STDOUT)
    tunnel = None
    if config.get("tunnel") == "ngrok" and config.get("ngrok_path"):
        domain = normalize_public_base_url(config.get("public_base_url", "")).replace("https://", "").replace("http://", "")
        tunnel_args = [config["ngrok_path"], "http", str(config.get("port", DEFAULT_PORT))]
        if domain and "your-ngrok-domain" not in domain:
            tunnel_args.extend(["--url", domain])
        tunnel = subprocess.Popen(tunnel_args, cwd=str(ROOT), stdout=ngrok_log, stderr=subprocess.STDOUT)

    PID_PATH.write_text(json.dumps({"server_pid": server.pid, "tunnel_pid": tunnel.pid if tunnel else None}, indent=2), encoding="utf-8")
    wait_until_ready(config.get("port", DEFAULT_PORT))
    show_summary(config)


def wait_until_ready(port: int) -> None:
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            urlopen(f"http://127.0.0.1:{port}/mcp", timeout=1)
        except HTTPError as exc:
            if exc.code in {400, 404, 405, 406}:
                return
        except URLError:
            time.sleep(0.25)
    say(f"Server did not answer on port {port} within 15 seconds.", "yellow")


def kill_pid(pid: int | None) -> None:
    if not pid:
        return
    try:
        if platform.system().lower() == "windows":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, check=False)
        else:
            os.kill(pid, signal.SIGTERM)
    except Exception:
        pass


def kill_existing_computerbridge_processes() -> None:
    root_text = str(ROOT).replace("\\", "/")
    server_text = str(SERVER_PATH).replace("\\", "/")
    if platform.system().lower() == "windows":
        script = f"""
$targets = Get-CimInstance Win32_Process | Where-Object {{
    $cmd = ($_.CommandLine -replace '\\\\', '/')
    ($_.Name -in @('python.exe','pythonw.exe','uv.exe') -and (
        ($cmd -like '*server.py*' -and $cmd -like '*streamable-http*') -or
        $cmd -like '*{root_text}*server.py*' -or
        $cmd -like '*{server_text}*'
    )) -or
    ($_.Name -eq 'ngrok.exe')
}}
$targets | ForEach-Object {{
    Start-Process -FilePath taskkill.exe -ArgumentList @('/PID', $_.ProcessId, '/T', '/F') -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
}}
"""
        subprocess.run(["powershell.exe", "-NoProfile", "-Command", script], capture_output=True, check=False)
        return

    patterns = [str(SERVER_PATH), f"ngrok http {DEFAULT_PORT}"]
    for pattern in patterns:
        try:
            result = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True, check=False)
            for line in result.stdout.splitlines():
                pid = int(line.strip())
                if pid != os.getpid():
                    kill_pid(pid)
        except Exception:
            pass


def stop(_: argparse.Namespace) -> None:
    if not PID_PATH.exists():
        kill_existing_computerbridge_processes()
        return
    data = json.loads(PID_PATH.read_text(encoding="utf-8"))
    kill_pid(data.get("tunnel_pid"))
    kill_pid(data.get("server_pid"))
    kill_existing_computerbridge_processes()
    PID_PATH.unlink(missing_ok=True)


def status(_: argparse.Namespace) -> None:
    config = load_config()
    if not config:
        say("No setup found. Run: python cli.py setup", "yellow")
        return
    show_summary(config)
    say(f"Config: {CONFIG_PATH}")
    say(f"Logs: {DIRS['logs']}")
    say(f"Runtime: {DIRS['runtime']}")
    say(f"PID file: {PID_PATH if PID_PATH.exists() else '(not running from cli.py)'}")


def main() -> None:
    parser = argparse.ArgumentParser(prog=APP_NAME.lower(), description=f"{APP_NAME} local MCP setup and launcher")
    sub = parser.add_subparsers(dest="command", required=True)
    setup_parser = sub.add_parser("setup")
    setup_parser.set_defaults(func=setup)
    start_parser = sub.add_parser("start")
    start_parser.add_argument("--foreground", action="store_true")
    start_parser.set_defaults(func=start)
    sub.add_parser("stop").set_defaults(func=stop)
    sub.add_parser("status").set_defaults(func=status)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
