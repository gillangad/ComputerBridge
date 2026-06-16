$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot

Write-Host "Starting ComputerBridge..." -ForegroundColor Green
& uv.exe run --with "mcp[cli]" --with "rich" "$ProjectRoot\cli.py" start
