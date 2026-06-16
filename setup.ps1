$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot

& uv.exe run --with "mcp[cli]" --with "rich" "$ProjectRoot\cli.py" setup
