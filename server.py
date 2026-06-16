# /// script
# dependencies = ["mcp[cli]"]
# ///

import argparse
import base64
import json
import mimetypes
import os
import platform
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field


mcp = FastMCP(
    "ComputerBridge",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)

APP_NAME = "ComputerBridge"
APP_ID = "computerbridge"


def platform_state_dir() -> Path:
    override = os.environ.get("COMPUTERBRIDGE_DATA_DIR")
    if override:
        return Path(override).expanduser()
    system = platform.system().lower()
    if system == "windows":
        return Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")) / APP_NAME
    if system == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    return Path(os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state")) / APP_ID


DATA_ROOT = platform_state_dir()
RUNS_ROOT = DATA_ROOT / "runs"
HISTORY_PATH = DATA_ROOT / "command-history.jsonl"
RUNS_ROOT.mkdir(parents=True, exist_ok=True)

MAX_TEXT_BYTES = 1024 * 1024
MAX_OUTPUT_CHARS = 80_000
SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|password|secret|authorization)\s*[:=]\s*([^\s;'\"`]+)"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+\-/=]+"),
]
ANSI_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def redact(value: str) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        if pattern.groups >= 2:
            redacted = pattern.sub(lambda m: f"{m.group(1)}=[REDACTED]", redacted)
        else:
            redacted = pattern.sub(lambda m: f"{m.group(1)}[REDACTED]", redacted)
    return redacted


def expand_path_value(value: str) -> str:
    if os.name == "nt" and "$HOME" in value and "HOME" not in os.environ:
        value = value.replace("$HOME", os.environ.get("USERPROFILE", str(Path.home())))
    return os.path.expandvars(value)


def resolve_base_dir(workdir: str | None = None) -> Path:
    base = Path(expand_path_value(workdir or DEFAULT_CWD)).expanduser()
    if not base.is_absolute():
        base = Path(DEFAULT_CWD) / base
    return base.resolve()


def resolve_path(path: str, workdir: str | None = None) -> Path:
    candidate = Path(expand_path_value(path)).expanduser()
    if not candidate.is_absolute():
        candidate = resolve_base_dir(workdir) / candidate
    return candidate.resolve()


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def read_tail(path: Path, max_chars: int) -> str:
    if not path.exists():
        return ""
    with path.open("rb") as handle:
        size = handle.seek(0, os.SEEK_END)
        handle.seek(max(0, size - max_chars * 4))
        return handle.read().decode("utf-8", errors="replace")[-max_chars:]


def bounded_text(text: str, max_chars: int = MAX_OUTPUT_CHARS) -> tuple[str, bool]:
    text = ANSI_PATTERN.sub("", text)
    if len(text) <= max_chars:
        return text, False
    return text[-max_chars:], True


def patch_line_counts(action: str, payload: Any) -> tuple[int, int]:
    if action == "add":
        return len(str(payload).splitlines()), 0
    if action == "delete":
        return 0, 0
    added = removed = 0
    for line in payload.get("lines", []):
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return added, removed


def image_dimensions(path: Path) -> tuple[int | None, int | None]:
    try:
        with path.open("rb") as handle:
            header = handle.read(32)
            if header.startswith(b"\x89PNG\r\n\x1a\n") and len(header) >= 24:
                return int.from_bytes(header[16:20], "big"), int.from_bytes(header[20:24], "big")
            if header.startswith(b"\xff\xd8"):
                handle.seek(2)
                while True:
                    marker_start = handle.read(1)
                    if not marker_start:
                        break
                    if marker_start != b"\xff":
                        continue
                    marker = handle.read(1)
                    while marker == b"\xff":
                        marker = handle.read(1)
                    if marker in {b"\xc0", b"\xc1", b"\xc2", b"\xc3", b"\xc5", b"\xc6", b"\xc7", b"\xc9", b"\xca", b"\xcb", b"\xcd", b"\xce", b"\xcf"}:
                        handle.read(3)
                        height = int.from_bytes(handle.read(2), "big")
                        width = int.from_bytes(handle.read(2), "big")
                        return width, height
                    length_bytes = handle.read(2)
                    if len(length_bytes) != 2:
                        break
                    length = int.from_bytes(length_bytes, "big")
                    handle.seek(max(0, length - 2), os.SEEK_CUR)
    except Exception:
        return None, None
    return None, None


def kill_process_tree(process: subprocess.Popen | None) -> None:
    if not process or process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, timeout=10, check=False)
            return
        except Exception:
            pass
    try:
        process.kill()
    except Exception:
        pass


class ShellConfig:
    def __init__(self, shell: str, args_prefix: list[str], shell_type: str) -> None:
        self.shell = shell
        self.args_prefix = args_prefix
        self.shell_type = shell_type


def detect_shell() -> ShellConfig:
    override = os.environ.get("LOCAL_CODING_MCP_SHELL") or os.environ.get("PS_MCP_SHELL")
    if override:
        return shell_config_for_path(override)

    if os.name == "nt":
        candidates = [
            shutil.which("pwsh.exe"),
            shutil.which("powershell.exe"),
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files (x86)\Git\bin\bash.exe",
            shutil.which("bash.exe"),
            shutil.which("cmd.exe"),
        ]
        for candidate in candidates:
            if candidate and Path(candidate).exists():
                return shell_config_for_path(candidate)
        raise RuntimeError("No usable shell found. Install PowerShell.")

    shell = os.environ.get("SHELL") or shutil.which("bash") or shutil.which("sh")
    if not shell:
        raise RuntimeError("No usable shell found.")
    return shell_config_for_path(shell)


def shell_config_for_path(path: str) -> ShellConfig:
    lower = Path(path).name.lower()
    if lower in {"bash", "bash.exe", "sh", "sh.exe", "zsh", "zsh.exe"}:
        return ShellConfig(path, ["-lc"], "bash")
    if lower in {"pwsh", "pwsh.exe", "powershell", "powershell.exe"}:
        return ShellConfig(path, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"], "powershell")
    if lower in {"cmd", "cmd.exe"}:
        return ShellConfig(path, ["/d", "/s", "/c"], "cmd")
    return ShellConfig(path, ["-lc"], "bash")


SHELL = detect_shell()
DEFAULT_CWD = str(Path(os.environ.get("LOCAL_CODING_MCP_PROJECTS_ROOT") or Path.cwd()).expanduser().resolve())

EXEC_CARD_URI = "ui://computerbridge/exec-card-v9.html"
STDIN_CARD_URI = "ui://computerbridge/stdin-card-v9.html"
READ_CARD_URI = "ui://computerbridge/read-card-v9.html"
PATCH_CARD_URI = "ui://computerbridge/patch-card-v9.html"
IMAGE_CARD_URI = "ui://computerbridge/image-card-v9.html"


def tool_card_meta(uri: str, invoking: str, invoked: str) -> dict[str, Any]:
    return {
        "ui": {"resourceUri": uri},
        "openai/outputTemplate": uri,
        "openai/toolInvocation/invoking": invoking,
        "openai/toolInvocation/invoked": invoked,
    }


def card_resource_meta(description: str) -> dict[str, Any]:
    return {
        "ui": {
            "description": description,
            "prefersBorder": False,
            "csp": {
                "connectDomains": [],
                "resourceDomains": [],
            },
        },
        "openai/widgetDescription": description,
        "openai/widgetPrefersBorder": False,
        "openai/widgetCSP": {
            "connect_domains": [],
            "resource_domains": [],
            "connectDomains": [],
            "resourceDomains": [],
        },
    }


def coding_card_html(kind: str, title: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root {{
      color-scheme: light dark;
      --bg: #fbfbfa;
      --panel: #f7f7f8;
      --panel-2: #ffffff;
      --line: rgb(15 23 42 / 10%);
      --text: #18181b;
      --muted: #71717a;
      --green: #22c55e;
      --red: #ef4444;
      --cyan: #0e7490;
      --amber: #b45309;
      --purple: #7c3aed;
      --blue: #1d4ed8;
      --shadow: 0 10px 28px rgb(15 23 42 / 8%);
      --header-bg: #f7f7f8;
      --pill-bg: #ffffff;
      --code-text: #18181b;
      --added-bg: #dcfce7;
      --removed-bg: #fee2e2;
      --image-bg: #fbfbfa;
      --checker: #ececea;
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        --bg: #151515;
        --panel: #1c1c1c;
        --panel-2: #101010;
        --line: rgb(255 255 255 / 7%);
        --text: #f4f4f5;
        --muted: #a1a1aa;
        --green: #22c55e;
        --red: #ef4444;
        --cyan: #67e8f9;
        --amber: #fbbf24;
        --purple: #c084fc;
        --blue: #93c5fd;
        --shadow: 0 10px 28px rgb(0 0 0 / 22%);
        --header-bg: #1c1c1c;
        --pill-bg: #181818;
        --code-text: #f4f4f5;
        --added-bg: rgb(46 160 67 / 22%);
        --removed-bg: rgb(248 81 73 / 22%);
        --image-bg: #0f0f0f;
        --checker: #171717;
      }}
    }}
    :root[data-theme="dark"] {{
      --bg: #151515;
      --panel: #1c1c1c;
      --panel-2: #101010;
      --line: rgb(255 255 255 / 7%);
      --text: #f4f4f5;
      --muted: #a1a1aa;
      --green: #22c55e;
      --red: #ef4444;
      --cyan: #67e8f9;
      --amber: #fbbf24;
      --purple: #c084fc;
      --blue: #93c5fd;
      --shadow: 0 10px 28px rgb(0 0 0 / 22%);
      --header-bg: #1c1c1c;
      --pill-bg: #181818;
      --code-text: #f4f4f5;
      --added-bg: rgb(46 160 67 / 22%);
      --removed-bg: rgb(248 81 73 / 22%);
      --image-bg: #0f0f0f;
      --checker: #171717;
    }}
    :root[data-theme="light"] {{
      color-scheme: light;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 12px;
      background: transparent;
      color: var(--text);
      font: 13px/1.45 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    .card {{
      overflow: hidden;
      border: 0;
      border-radius: 9px;
      background: var(--bg);
      color: var(--text);
      box-shadow:
        inset 0 0 0 1px var(--line),
        var(--shadow);
    }}
    .head {{
      display: flex;
      gap: 10px;
      align-items: center;
      justify-content: space-between;
      width: 100%;
      padding: 10px 12px;
      box-shadow: inset 0 -1px 0 var(--line);
      background: var(--header-bg);
      color: inherit;
      cursor: pointer;
      border-left: 0;
      border-right: 0;
      border-top: 0;
    }}
    .left {{ display: flex; flex: 1 1 auto; min-width: 0; gap: 8px; align-items: center; text-align: left; }}
    .icon {{
      display: none;
      width: 24px;
      height: 24px;
      place-items: center;
      border-radius: 7px;
      background: var(--pill-bg);
      color: var(--cyan);
      font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
      font-weight: 700;
    }}
    .left > div {{ min-width: 0; flex: 1 1 auto; text-align: left; }}
    .title {{
      overflow: hidden;
      font-weight: 700;
      text-overflow: ellipsis;
      white-space: nowrap;
      max-width: 100%;
      text-align: left;
    }}
    .subtitle {{
      overflow: hidden;
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
      text-overflow: ellipsis;
      white-space: nowrap;
      max-width: 100%;
      margin-top: 1px;
      text-align: left;
    }}
    .right {{ display: flex; align-items: center; gap: 8px; min-width: max-content; }}
    .chevron {{
      color: var(--muted);
      font: 14px/1 ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
      transition: transform 0.16s ease;
    }}
    .card:not(.collapsed) .chevron {{ transform: rotate(180deg); }}
    .pills {{ display: flex; gap: 6px; align-items: center; color: var(--muted); white-space: nowrap; }}
    .pill {{
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 3px 8px;
      background: var(--pill-bg);
      font-size: 12px;
    }}
    .ok {{ color: var(--green); }}
    .bad {{ color: var(--red); }}
    .warn {{ color: var(--amber); }}
    .plus {{ color: var(--green); }}
    .minus {{ color: var(--red); }}
    .body {{
      max-height: 420px;
      overflow: auto;
      background: var(--panel-2);
    }}
    .card.collapsed .body {{ display: none; }}
    pre {{
      margin: 0;
      padding: 13px 14px;
      color: var(--code-text);
      font: 12.5px/1.45 ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
      white-space: pre;
    }}
    .line {{ display: grid; grid-template-columns: 54px minmax(0, 1fr); }}
    .num {{
      user-select: none;
      padding-right: 12px;
      color: #737782;
      text-align: right;
    }}
    .code {{ white-space: pre; }}
    .added {{ background: var(--added-bg); border-left: 4px solid #2ea043; }}
    .removed {{ background: var(--removed-bg); border-left: 4px solid #f85149; }}
    .keyword {{ color: var(--purple); }}
    .string {{ color: var(--green); }}
    .comment {{ color: #8b949e; }}
    .heading {{ color: var(--blue); font-weight: 700; }}
    .prompt {{
      margin: 0;
      padding: 12px 14px 0;
      color: var(--muted);
      font: 12.5px/1.45 ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }}
    .prompt span {{ color: var(--text); }}
    .patch-head {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 9px 14px;
      border-bottom: 1px solid var(--line);
      background: var(--panel-2);
      font: 12.5px/1.45 ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
    }}
    .patch-file {{ overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .patch-delta {{ white-space: nowrap; }}
    .diff-empty {{
      margin: 0;
      padding: 10px 14px;
      color: var(--muted);
      font: 12.5px/1.45 ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
    }}
    .grid {{ display: grid; gap: 8px; padding: 12px 14px; background: var(--panel-2); }}
    .row {{ display: flex; justify-content: space-between; gap: 12px; border-bottom: 1px solid var(--line); padding-bottom: 7px; }}
    .row:last-child {{ border-bottom: 0; padding-bottom: 0; }}
    .key {{ color: var(--muted); }}
    .val {{ overflow: hidden; font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace; text-overflow: ellipsis; white-space: nowrap; }}
    .image-wrap {{
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 180px;
      padding: 16px;
      background:
        linear-gradient(45deg, var(--checker) 25%, transparent 25%),
        linear-gradient(-45deg, var(--checker) 25%, transparent 25%),
        linear-gradient(45deg, transparent 75%, var(--checker) 75%),
        linear-gradient(-45deg, transparent 75%, var(--checker) 75%);
      background-color: var(--image-bg);
      background-position: 0 0, 0 8px, 8px -8px, -8px 0;
      background-size: 16px 16px;
    }}
    img {{
      display: block;
      max-width: 100%;
      max-height: 360px;
      object-fit: contain;
      border-radius: 6px;
      box-shadow: 0 0 0 1px rgb(15 23 42 / 12%);
    }}
  </style>
</head>
<body>
  <div id="root" class="card{" collapsed" if kind != "image" else ""}">
    <button id="head" class="head" type="button" aria-expanded="{"false" if kind != "image" else "true"}">
      <div class="left">
        <div id="icon" class="icon">?</div>
        <div>
          <div class="title">{title}</div>
          <div id="subtitle" class="subtitle">Waiting for tool result...</div>
        </div>
      </div>
      <div class="right">
        <div id="pills" class="pills"></div>
        <div id="chevron" class="chevron">⌄</div>
      </div>
    </button>
    <div id="body" class="body"><pre>Waiting for command output...</pre></div>
  </div>
  <script>
    const KIND = {kind!r};
    const applyTheme = () => {{
      const theme = window.openai?.theme;
      if (theme === "light" || theme === "dark") {{
        document.documentElement.dataset.theme = theme;
      }}
    }};
    applyTheme();
    const root = document.getElementById("root");
    const head = document.getElementById("head");
    const icon = document.getElementById("icon");
    const titleEl = document.querySelector(".title");
    const subtitle = document.getElementById("subtitle");
    const pills = document.getElementById("pills");
    const body = document.getElementById("body");
    head.addEventListener("click", () => {{
      const collapsed = root.classList.toggle("collapsed");
      head.setAttribute("aria-expanded", String(!collapsed));
    }});

    const esc = (value) => String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
    const basename = (path) => String(path || "").split(/[\\\\/]/).pop() || path || "";
    const dirname = (path) => String(path || "").split(/[\\\\/]/).slice(0, -1).join(path?.includes("\\\\") ? "\\\\" : "/");
    const pill = (text, cls = "") => `<span class="pill ${{cls}}">${{esc(text)}}</span>`;
    const compactPath = (path) => {{
      const value = String(path || "");
      if (value.length <= 86) return value;
      const slash = value.includes("\\\\") ? "\\\\" : "/";
      const parts = value.split(/[\\\\/]/);
      return `${{parts[0]}}${{slash}}...${{slash}}${{parts.slice(-3).join(slash)}}`;
    }};
    const commandPreview = (data) => data.command ? `<div class="prompt"><span>${{esc(data.command)}}</span></div>` : "";
    const statusPills = (data) => [
      pill(data.status || "unknown", data.status === "completed" && data.exit_code === 0 ? "ok" : data.status === "running" ? "warn" : data.exit_code ? "bad" : ""),
      data.exit_code !== null && data.exit_code !== undefined ? pill(`exit ${{data.exit_code}}`, data.exit_code === 0 ? "ok" : "bad") : "",
      data.duration_ms !== null && data.duration_ms !== undefined ? pill(`${{data.duration_ms}} ms`) : ""
    ].join("");
    const highlight = (line) => {{
      let value = esc(line);
      if (/^\\s*#/.test(line)) return `<span class="heading">${{value}}</span>`;
      value = value.replace(/(&quot;.*?&quot;|'.*?'|`.*?`)/g, '<span class="string">$1</span>');
      value = value.replace(/\\b(def|class|return|import|from|if|else|elif|for|while|try|except|with|function|const|let|var|async|await|true|false|null|None|True|False)\\b/g, '<span class="keyword">$1</span>');
      value = value.replace(/(#.*$|\\/\\/.*$)/g, '<span class="comment">$1</span>');
      return value || " ";
    }};

    function currentPayload() {{
      return window.openai?.toolOutput?.structuredContent
        || window.openai?.toolResponse?.structuredContent
        || window.openai?.toolResponse
        || window.openai?.toolOutput
        || window.openai?.structuredContent
        || window.openai?.toolInput?.structuredContent
        || window.openai?.toolInput
        || null;
    }}

    function renderLines(content, start) {{
      const lines = String(content ?? "").split("\\n");
      return `<pre>${{lines.map((line, i) =>
        `<span class="line"><span class="num">${{start + i}}</span><span class="code">${{highlight(line)}}</span></span>`
      ).join("")}}</pre>`;
    }}

    function renderDiff(changes) {{
      const rows = (changes || []).map((change, index) => {{
        const action = String(change.action || "");
        const file = change.file_name || basename(change.path);
        const parent = compactPath(change.parent || dirname(change.path));
        const displayLines = change.display_lines || [];
        const diff = displayLines.length
          ? `<pre>${{displayLines.map((line) => {{
              const raw = String(line ?? "");
              const prefix = raw[0] || " ";
              const cls = prefix === "+" ? "added" : prefix === "-" ? "removed" : "";
              const sign = prefix === "+" || prefix === "-" ? prefix : " ";
              const code = prefix === "+" || prefix === "-" || prefix === " " ? raw.slice(1) : raw;
              return `<span class="line ${{cls}}"><span class="num">${{esc(sign)}}</span><span class="code">${{highlight(code)}}</span></span>`;
            }}).join("")}}</pre>`
          : `<div class="diff-empty">${{esc(action)}} ${{esc(file)}}</div>`;
        return `<div class="patch-head"><span class="patch-file">${{esc(file)}} <span class="comment">${{esc(parent)}}</span></span></div>` +
          diff;
      }}).join("");
      return rows || `<pre>No file changes reported.</pre>`;
    }}

    function renderData(data) {{
      if (!data) return;
      if (data.structuredContent) data = data.structuredContent;
      if (data.result?.structuredContent) data = data.result.structuredContent;
      if (data.result && !data.run_id && !data.path && !data.changes && !data.image_url) data = data.result;
      if (KIND === "exec" || KIND === "stdin") {{
        icon.textContent = KIND === "exec" ? ">_" : "in";
        const commandText = data.command || "command";
        const action = data.status === "running" ? "Running" : data.status === "completed" ? "Ran" : data.status === "timed_out" ? "Timed out" : "Command";
        titleEl.textContent = KIND === "exec" ? `${{action}} ${{commandText}}` : "Sent input to running command";
        subtitle.textContent = compactPath(data.cwd || data.run_id || "Command");
        pills.innerHTML = statusPills(data);
        const empty = data.status === "running" ? "Waiting for command output..." : "(no output)";
        body.innerHTML = `${{commandPreview(data)}}<pre>${{esc(data.output || empty)}}</pre>`;
      }} else if (KIND === "read") {{
        icon.textContent = "doc";
        const fileName = basename(data.path) || "file";
        titleEl.textContent = `Read ${{fileName}}`;
        subtitle.textContent = compactPath(dirname(data.path));
        const count = Math.max(0, (data.end_line || data.offset || 1) - (data.offset || 1) + 1);
        pills.innerHTML = [pill(`${{count}} lines`), data.truncated ? pill("truncated", "warn") : ""].join("");
        body.innerHTML = renderLines(data.content, data.offset || 1);
      }} else if (KIND === "patch") {{
        icon.textContent = "±";
        const changes = data.changes || [];
        titleEl.textContent = changes.length === 1
          ? `Edited ${{changes[0].file_name || basename(changes[0].path) || "file"}}`
          : `${{changes.length}} files edited`;
        const parents = [...new Set(changes.map(c => c.parent || dirname(c.path)).filter(Boolean))];
        subtitle.textContent = changes.length === 1
          ? compactPath(changes[0].parent || dirname(changes[0].path))
          : parents.length === 1
            ? compactPath(parents[0])
            : `${{changes.length}} files across ${{parents.length}} folders`;
        const addedFiles = changes.filter(c => c.action === "add").length;
        const deleted = changes.filter(c => c.action === "delete").length;
        const updated = changes.length - addedFiles - deleted;
        const addedLines = Number(data.added_lines || changes.reduce((sum, c) => sum + Number(c.added_lines || 0), 0));
        const removedLines = Number(data.removed_lines || changes.reduce((sum, c) => sum + Number(c.removed_lines || 0), 0));
        pills.innerHTML = [
          addedLines ? pill(`+${{addedLines}}`, "ok") : "",
          removedLines ? pill(`-${{removedLines}}`, "bad") : "",
          changes.length > 1 && updated ? pill(`${{updated}} updated`) : "",
          changes.length > 1 && addedFiles ? pill(`${{addedFiles}} added`) : ""
        ].join("");
        body.innerHTML = renderDiff(changes);
      }} else if (KIND === "image") {{
        icon.textContent = "img";
        titleEl.textContent = basename(data.path) || "View Image";
        subtitle.textContent = compactPath(dirname(data.path)) || "Image preview";
        const dimensions = data.width && data.height ? `${{data.width}}×${{data.height}}` : "";
        pills.innerHTML = [pill(data.detail || "high"), dimensions ? pill(dimensions) : "", data.mime_type ? pill(data.mime_type) : ""].join("");
        body.innerHTML = `<div class="image-wrap"><img src="${{esc(data.image_url)}}" alt="Tool image preview" /></div>`;
      }}
    }}

    window.addEventListener("message", (event) => {{
      applyTheme();
      const method = event.data?.method;
      const payload = event.data?.params?.result?.structuredContent
        || event.data?.params?.toolResult?.structuredContent
        || event.data?.params?.toolOutput?.structuredContent
        || event.data?.params?.structuredContent
        || event.data?.params?.result
        || event.data?.params?.toolResult
        || event.data?.params?.toolOutput
        || event.data?.result?.structuredContent
        || event.data?.result
        || (method === "ui/notifications/tool-result" ? event.data?.params : null);
      if (payload) renderData(payload);
    }});

    let rendered = false;
    const tryRender = () => {{
      const payload = currentPayload();
      if (payload) {{
        rendered = true;
        renderData(payload);
      }}
    }};
    const showLoading = () => {{
      if (rendered) return;
      const messages = {{
        exec: "Waiting for command output...",
        stdin: "Waiting for command output...",
        read: "Waiting for file contents...",
        patch: "Waiting for patch result...",
        image: "Waiting for image preview..."
      }};
      subtitle.textContent = "Working...";
      body.innerHTML = `<pre>${{messages[KIND] || "Waiting for result..."}}</pre>`;
    }};
    tryRender();
    const poll = setInterval(() => {{
      tryRender();
      if (rendered) clearInterval(poll);
    }}, 250);
    setTimeout(showLoading, 2000);
  </script>
</body>
</html>"""


@mcp.resource(
    EXEC_CARD_URI,
    name="exec-command-card",
    mime_type="text/html;profile=mcp-app",
    meta=card_resource_meta("A terminal-style card showing command status, exit code, duration, and output."),
)
def exec_command_card() -> str:
    return coding_card_html("exec", "Command")


@mcp.resource(
    STDIN_CARD_URI,
    name="write-stdin-card",
    mime_type="text/html;profile=mcp-app",
    meta=card_resource_meta("A terminal-style card showing input sent to a running command and the latest output."),
)
def write_stdin_card() -> str:
    return coding_card_html("stdin", "Input")


@mcp.resource(
    READ_CARD_URI,
    name="read-file-card",
    mime_type="text/html;profile=mcp-app",
    meta=card_resource_meta("A file viewer card showing the selected path, line count, and numbered file contents."),
)
def read_file_card() -> str:
    return coding_card_html("read", "Read File")


@mcp.resource(
    PATCH_CARD_URI,
    name="apply-patch-card",
    mime_type="text/html;profile=mcp-app",
    meta=card_resource_meta("A patch summary card showing files added, updated, moved, or deleted."),
)
def apply_patch_card() -> str:
    return coding_card_html("patch", "Apply Patch")


@mcp.resource(
    IMAGE_CARD_URI,
    name="view-image-card",
    mime_type="text/html;profile=mcp-app",
    meta=card_resource_meta("An image preview card showing the image returned by the tool."),
)
def view_image_card() -> str:
    return coding_card_html("image", "View Image")


def register_legacy_card(uri: str, name: str, kind: str, title: str, description: str) -> None:
    def legacy_card() -> str:
        return coding_card_html(kind, title)

    legacy_card.__name__ = f"legacy_{name}".replace("-", "_").replace(".", "_")
    mcp.resource(
        uri,
        name=name,
        mime_type="text/html;profile=mcp-app",
        meta=card_resource_meta(description),
    )(legacy_card)


for version in range(5, 9):
    register_legacy_card(
        f"ui://computerbridge/exec-card-v{version}.html",
        f"legacy-exec-command-card-v{version}",
        "exec",
        "Command",
        "A terminal-style card showing command status, exit code, duration, and output.",
    )
    register_legacy_card(
        f"ui://computerbridge/stdin-card-v{version}.html",
        f"legacy-write-stdin-card-v{version}",
        "stdin",
        "Input",
        "A terminal-style card showing input sent to a running command and the latest output.",
    )
    register_legacy_card(
        f"ui://computerbridge/read-card-v{version}.html",
        f"legacy-read-file-card-v{version}",
        "read",
        "Read File",
        "A file viewer card showing the selected path, line count, and numbered file contents.",
    )
    register_legacy_card(
        f"ui://computerbridge/patch-card-v{version}.html",
        f"legacy-apply-patch-card-v{version}",
        "patch",
        "Apply Patch",
        "A patch summary card showing files added, updated, moved, or deleted.",
    )
    register_legacy_card(
        f"ui://computerbridge/image-card-v{version}.html",
        f"legacy-view-image-card-v{version}",
        "image",
        "View Image",
        "An image preview card showing the image returned by the tool.",
    )


class ExecResult(BaseModel):
    projects_root: str
    run_id: str
    session_id: str | None
    status: str
    cwd: str
    command: str | None = None
    shell: str
    shell_type: str
    pid: int | None
    exit_code: int | None
    duration_ms: int | None
    timed_out: bool
    output: str
    output_truncated: bool


class ReadResult(BaseModel):
    projects_root: str
    path: str
    offset: int
    end_line: int
    content: str
    truncated: bool


class PatchChange(BaseModel):
    action: str
    path: str
    file_name: str
    parent: str
    added_lines: int = 0
    removed_lines: int = 0
    display_lines: list[str] = Field(default_factory=list)


class PatchResult(BaseModel):
    projects_root: str
    changes: list[PatchChange]
    added_lines: int = 0
    removed_lines: int = 0


class ImageResult(BaseModel):
    projects_root: str
    image_url: str
    detail: Literal["high", "original"]
    path: str
    mime_type: str
    width: int | None = None
    height: int | None = None


class AuditStore:
    def __init__(self) -> None:
        self.lock = threading.Lock()

    def create(self, command: str, cwd: str, timeout_ms: int) -> dict[str, Any]:
        run_id = uuid.uuid4().hex
        run_dir = RUNS_ROOT / run_id
        run_dir.mkdir(parents=True)
        metadata = {
            "run_id": run_id,
            "status": "running",
            "started_at": utc_now(),
            "ended_at": None,
            "working_directory": cwd,
            "command": redact(command),
            "timeout_ms": timeout_ms,
            "exit_code": None,
            "duration_ms": None,
            "timed_out": False,
            "pid": None,
            "shell": SHELL.shell,
            "shell_type": SHELL.shell_type,
        }
        (run_dir / "command.txt").write_text(redact(command), encoding="utf-8")
        (run_dir / "stdout.log").touch()
        (run_dir / "stderr.log").touch()
        (run_dir / "stdin.log").touch()
        self.save(metadata)
        return metadata

    def save(self, metadata: dict[str, Any]) -> None:
        with self.lock:
            (RUNS_ROOT / metadata["run_id"] / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    def finish(self, metadata: dict[str, Any], started: float, **updates: Any) -> None:
        metadata.update(updates)
        metadata["ended_at"] = utc_now()
        metadata["duration_ms"] = round((time.monotonic() - started) * 1000)
        self.save(metadata)
        record = dict(metadata)
        record["stdout_tail"] = read_tail(RUNS_ROOT / metadata["run_id"] / "stdout.log", 4000)
        record["stderr_tail"] = read_tail(RUNS_ROOT / metadata["run_id"] / "stderr.log", 4000)
        with self.lock:
            with HISTORY_PATH.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record) + "\n")

    def load(self, run_id: str) -> dict[str, Any]:
        path = RUNS_ROOT / run_id / "metadata.json"
        if not path.is_file():
            raise ValueError(f"Run not found: {run_id}")
        return json.loads(path.read_text(encoding="utf-8"))


audit = AuditStore()


class RunManager:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.processes: dict[str, subprocess.Popen] = {}

    def start(self, command: str, workdir: str | None, timeout_ms: int, yield_time_ms: int, max_output_chars: int) -> ExecResult:
        cwd = str(resolve_base_dir(workdir))
        if not Path(cwd).is_dir():
            raise ValueError(f"Working directory not found: {cwd}")
        timeout_ms = max(1000, min(int(timeout_ms), 86_400_000))
        yield_time_ms = max(250, min(int(yield_time_ms), 30_000))
        metadata = audit.create(command, cwd, timeout_ms)
        run_id = metadata["run_id"]
        run_dir = RUNS_ROOT / run_id
        stdout_handle = (run_dir / "stdout.log").open("ab", buffering=0)
        stderr_handle = (run_dir / "stderr.log").open("ab", buffering=0)
        process = subprocess.Popen(
            [SHELL.shell, *SHELL.args_prefix, command],
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=stdout_handle,
            stderr=stderr_handle,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
        )
        metadata["pid"] = process.pid
        audit.save(metadata)
        started = time.monotonic()
        with self.lock:
            self.processes[run_id] = process
        threading.Thread(target=self._monitor, args=(metadata, process, started, stdout_handle, stderr_handle), daemon=True).start()
        time.sleep(yield_time_ms / 1000)
        current = audit.load(run_id)
        return self._result(run_id, current, max_output_chars)

    def _monitor(self, metadata: dict[str, Any], process: subprocess.Popen, started: float, stdout_handle: Any, stderr_handle: Any) -> None:
        try:
            exit_code = process.wait(timeout=metadata["timeout_ms"] / 1000)
            status = "completed"
            timed_out = False
        except subprocess.TimeoutExpired:
            kill_process_tree(process)
            exit_code = -1
            status = "timed_out"
            timed_out = True
        finally:
            stdout_handle.close()
            stderr_handle.close()
        current = audit.load(metadata["run_id"])
        audit.finish(current, started, status=status, exit_code=exit_code, timed_out=timed_out)
        with self.lock:
            self.processes.pop(metadata["run_id"], None)

    def write(self, session_id: str, chars: str, yield_time_ms: int, max_output_chars: int) -> ExecResult:
        with self.lock:
            process = self.processes.get(session_id)
        if chars:
            if not process or process.poll() is not None or not process.stdin:
                raise ValueError(f"Session is not accepting input: {session_id}")
            data = chars.encode("utf-8")
            process.stdin.write(data)
            process.stdin.flush()
            with (RUNS_ROOT / session_id / "stdin.log").open("ab") as handle:
                handle.write(data)
        time.sleep(max(250, min(int(yield_time_ms), 30_000)) / 1000)
        return self._result(session_id, audit.load(session_id), max_output_chars)

    def _result(self, run_id: str, metadata: dict[str, Any], max_output_chars: int) -> ExecResult:
        with self.lock:
            process = self.processes.get(run_id)
        running = bool(process and process.poll() is None)
        if not running:
            try:
                metadata = audit.load(run_id)
            except Exception:
                pass
        stdout = read_tail(RUNS_ROOT / run_id / "stdout.log", max(1000, min(max_output_chars, 200_000)))
        stderr = read_tail(RUNS_ROOT / run_id / "stderr.log", max(1000, min(max_output_chars, 200_000)))
        output, output_truncated = bounded_text(stdout + stderr, max_output_chars)
        return ExecResult(
            projects_root=DEFAULT_CWD,
            run_id=run_id,
            session_id=run_id if running else None,
            status="running" if running else metadata["status"],
            cwd=metadata["working_directory"],
            command=metadata.get("command"),
            shell=metadata["shell"],
            shell_type=metadata["shell_type"],
            pid=metadata.get("pid"),
            exit_code=None if running else metadata.get("exit_code"),
            duration_ms=metadata.get("duration_ms"),
            timed_out=metadata.get("timed_out", False),
            output=output,
            output_truncated=output_truncated,
        )


run_manager = RunManager()
mutation_lock = threading.Lock()


@mcp.tool(
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=True),
    meta=tool_card_meta(EXEC_CARD_URI, "Running command", "Command finished"),
    structured_output=True,
)
def exec_command(
    cmd: str,
    workdir: str | None = None,
    timeout_ms: int = 60_000,
    yield_time_ms: int = 1_000,
    max_output_chars: int = 20_000,
) -> ExecResult:
    """Use this when you need to run a project command, test, build, or small inspection command. Paths are resolved from the configured projects root returned as projects_root. Prefer relative workdir values like "test" or "my-project"; avoid broad filesystem discovery and avoid $HOME in workdir. On Windows this uses PowerShell by default; on macOS/Linux it uses the user's shell. If the command is still running after yield_time_ms, a session_id is returned for write_stdin polling/input."""
    return run_manager.start(cmd, workdir, timeout_ms, yield_time_ms, max_output_chars)


@mcp.tool(
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False),
    meta=tool_card_meta(STDIN_CARD_URI, "Sending input", "Input sent"),
    structured_output=True,
)
def write_stdin(
    session_id: str,
    chars: str = "",
    yield_time_ms: int = 1_000,
    max_output_chars: int = 20_000,
) -> ExecResult:
    """Use this when an existing exec_command session is waiting for input or needs to be polled. This does not start a new command, open files, or access the network; it only sends chars to the already-running session_id. Pass empty chars to poll a still-running command."""
    return run_manager.write(session_id, chars, yield_time_ms, max_output_chars)


@mcp.tool(
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False),
    meta=tool_card_meta(READ_CARD_URI, "Reading file", "File read"),
    structured_output=True,
)
def read(path: str, offset: int = 1, limit: int = 500, workdir: str | None = None) -> ReadResult:
    """Use this when you need bounded UTF-8 file contents. Prefer relative path/workdir values from the configured projects root; avoid broad shell discovery and avoid $HOME in workdir. Offset is a 1-indexed line number."""
    file_path = resolve_path(path, workdir or DEFAULT_CWD)
    if not file_path.is_file():
        raise ValueError(f"File not found: {file_path}")
    offset = max(1, int(offset))
    limit = max(1, min(int(limit), 2000))
    raw = file_path.read_bytes()[: MAX_TEXT_BYTES + 1]
    text = raw[:MAX_TEXT_BYTES].decode("utf-8", errors="replace")
    lines = text.splitlines()
    selected = lines[offset - 1:offset - 1 + limit]
    return ReadResult(
        projects_root=DEFAULT_CWD,
        path=str(file_path),
        offset=offset,
        end_line=offset + len(selected) - 1,
        content="\n".join(selected),
        truncated=len(raw) > MAX_TEXT_BYTES or offset - 1 + limit < len(lines),
    )


def parse_patch(patch: str) -> list[tuple[str, str, Any]]:
    lines = patch.splitlines()
    if not lines or lines[0] != "*** Begin Patch" or lines[-1] != "*** End Patch":
        raise ValueError("Patch must start with '*** Begin Patch' and end with '*** End Patch'")
    actions, index = [], 1
    while index < len(lines) - 1:
        header = lines[index]
        index += 1
        if header.startswith("*** Add File: "):
            path, added = header[14:], []
            while index < len(lines) - 1 and not lines[index].startswith("*** "):
                if not lines[index].startswith("+"):
                    raise ValueError("Added file lines must start with '+'")
                added.append(lines[index][1:])
                index += 1
            actions.append(("add", path, "\n".join(added) + ("\n" if added else "")))
        elif header.startswith("*** Delete File: "):
            actions.append(("delete", header[17:], None))
        elif header.startswith("*** Update File: "):
            path, body = header[17:], []
            move_to = None
            if index < len(lines) - 1 and lines[index].startswith("*** Move to: "):
                move_to = lines[index][13:]
                index += 1
            while index < len(lines) - 1 and not lines[index].startswith(("*** Add File: ", "*** Delete File: ", "*** Update File: ")):
                body.append(lines[index])
                index += 1
            actions.append(("update", path, {"lines": body, "move_to": move_to}))
        else:
            raise ValueError(f"Unknown patch header: {header}")
    return actions


def apply_update(original: str, patch_lines: list[str]) -> str:
    hunks: list[list[str]] = []
    current: list[str] = []
    for line in patch_lines:
        if line.startswith("@@"):
            if current:
                hunks.append(current)
                current = []
            continue
        if line == "*** End of File":
            continue
        current.append(line)
    if current:
        hunks.append(current)
    updated = original
    for hunk in hunks:
        old_lines, new_lines = [], []
        for line in hunk:
            if not line or line[0] not in " +-":
                raise ValueError(f"Invalid update line: {line}")
            if line[0] in " -":
                old_lines.append(line[1:])
            if line[0] in " +":
                new_lines.append(line[1:])
        old = "\n".join(old_lines)
        new = "\n".join(new_lines)
        if old not in updated:
            raise ValueError("Update context was not found in file")
        if updated.count(old) != 1:
            raise ValueError("Update context is ambiguous")
        updated = updated.replace(old, new, 1)
    return updated


def patch_display_lines(action: str, payload: Any, original: str | None = None) -> list[str]:
    if action == "add":
        return [f"+{line}" for line in str(payload).splitlines()][:200]
    if action == "delete":
        if original is None:
            return []
        return [f"-{line}" for line in original.splitlines()][:200]
    lines = []
    for line in payload.get("lines", []):
        if line.startswith("@@") or line == "*** End of File":
            continue
        if line[:1] in {"+", "-", " "}:
            lines.append(line)
    return lines[:200]


@mcp.tool(
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False),
    meta=tool_card_meta(PATCH_CARD_URI, "Applying patch", "Patch applied"),
    structured_output=True,
)
def apply_patch(patch: str, workdir: str | None = None) -> PatchResult:
    """Use this when you need to make a small, targeted Codex-style file edit inside the configured projects root. Prefer relative workdir values and relative patch paths. Avoid absolute paths, broad filesystem operations, and unrelated edits. Supports add, update, move, and delete operations."""
    actions = parse_patch(patch)
    changed = []
    total_added = 0
    total_removed = 0
    with mutation_lock:
        for action, raw_path, payload in actions:
            path = resolve_path(raw_path, workdir or DEFAULT_CWD)
            added_lines, removed_lines = patch_line_counts(action, payload)
            total_added += added_lines
            total_removed += removed_lines
            if action == "add":
                if path.exists():
                    raise ValueError(f"File already exists: {path}")
                atomic_write(path, payload)
                changed.append({"action": "add", "path": str(path), "file_name": path.name, "parent": str(path.parent), "added_lines": added_lines, "removed_lines": removed_lines, "display_lines": patch_display_lines(action, payload)})
            elif action == "delete":
                if not path.is_file():
                    raise ValueError(f"File not found: {path}")
                original = path.read_text(encoding="utf-8")
                path.unlink()
                changed.append({"action": "delete", "path": str(path), "file_name": path.name, "parent": str(path.parent), "added_lines": added_lines, "removed_lines": removed_lines, "display_lines": patch_display_lines(action, payload, original)})
            else:
                original = path.read_text(encoding="utf-8")
                updated = apply_update(original, payload["lines"])
                destination = resolve_path(payload["move_to"], workdir or DEFAULT_CWD) if payload["move_to"] else path
                atomic_write(destination, updated)
                if destination != path:
                    path.unlink()
                changed.append({"action": "move" if destination != path else "update", "path": str(destination), "file_name": destination.name, "parent": str(destination.parent), "added_lines": added_lines, "removed_lines": removed_lines, "display_lines": patch_display_lines(action, payload)})
    return PatchResult(projects_root=DEFAULT_CWD, changes=[PatchChange(**change) for change in changed], added_lines=total_added, removed_lines=total_removed)


@mcp.tool(
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False),
    meta=tool_card_meta(IMAGE_CARD_URI, "Loading image", "Image loaded"),
    structured_output=True,
)
def view_image(path: str, detail: Literal["high", "original"] = "high", workdir: str | None = None) -> ImageResult:
    """Use this when you need to preview a local image file. Prefer relative path/workdir values from the configured projects root; avoid $HOME in workdir."""
    image_path = resolve_path(path, workdir or DEFAULT_CWD)
    if not image_path.is_file():
        raise ValueError(f"Image not found: {image_path}")
    mime, _ = mimetypes.guess_type(image_path.name)
    if not mime or not mime.startswith("image/"):
        raise ValueError("Unsupported image type")
    encoded = base64.b64encode(image_path.read_bytes()).decode("ascii")
    width, height = image_dimensions(image_path)
    return ImageResult(projects_root=DEFAULT_CWD, image_url=f"data:{mime};base64,{encoded}", detail=detail, path=str(image_path), mime_type=mime, width=width, height=height)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Local coding MCP server")
    parser.add_argument("--transport", choices=["stdio", "sse", "streamable-http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if args.transport in {"sse", "streamable-http"}:
        mcp.settings.host = args.host
        mcp.settings.port = args.port
    mcp.run(transport=args.transport)
