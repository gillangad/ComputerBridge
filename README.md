# ComputerBridge

ComputerBridge lets ChatGPT use your computer through an MCP server. It gives ChatGPT a small Codex-style toolset for coding work: run shell commands, read files, apply patches, preview images, and send input to long-running commands.

## Installation and Use

1) Clone the repo and run the setup command.

Windows PowerShell:

```powershell
git clone <YOUR_REPO_URL> computerbridge
cd computerbridge
.\setup.ps1
```

macOS/Linux/Bash:

```bash
git clone <YOUR_REPO_URL> computerbridge
cd computerbridge
sh setup.sh
```

Cross-platform fallback:

```bash
uv run --with "mcp[cli]" --with rich cli.py setup
```

The setup wizard asks for your projects folder, shell, tunnel option, local port, public URL, startup preference, and whether to start ComputerBridge immediately.

2) After setup, copy the printed ChatGPT URL. It looks like:

```text
https://your-public-tunnel.example.com/mcp
```

In ChatGPT Developer Mode, create an app/connector with that MCP URL, and select No Auth or Oauth

## Short Commands

Windows:

```powershell
.\setup.ps1
.\start.ps1
.\stop.ps1
```

macOS/Linux:

```bash
sh setup.sh
sh start.sh
sh stop.sh
```

## Tools

- `exec_command`: runs project commands in the detected shell.
- `write_stdin`: sends input to, or polls, a running command.
- `read`: reads bounded UTF-8 file contents.
- `apply_patch`: applies small Codex-style file patches.
- `view_image`: previews a local image in ChatGPT.

## Local Data

ComputerBridge stores user config and runtime data outside the repo.

Config:

```text
Windows: %APPDATA%\ComputerBridge\config.json
macOS:   ~/Library/Application Support/ComputerBridge/config.json
Linux:   ~/.config/computerbridge/config.json
```

Logs, run output, and audit data:

```text
Windows: %LOCALAPPDATA%\ComputerBridge\
macOS:   ~/Library/Application Support/ComputerBridge/ and ~/Library/Logs/ComputerBridge/
Linux:   ~/.local/state/computerbridge/
```

## Notes

- Windows uses PowerShell by default.
- macOS/Linux use the user shell.
- Relative paths are resolved from the configured projects folder.
- `ngrok` is supported for local testing, but any public HTTPS tunnel can work.
- If you use a no-auth public tunnel, anyone with that URL can act as the OS user running ComputerBridge, so use no-auth mode only on a device you trust.