Write-Host "Stopping ComputerBridge..." -ForegroundColor Yellow

$ProjectRoot = $PSScriptRoot
& uv.exe run --with "mcp[cli]" --with "rich" "$ProjectRoot\cli.py" stop

# Stop ngrok process
Stop-Process -Name "ngrok" -Force -ErrorAction SilentlyContinue

# Stop only the uv/Python process trees running this server. Do not match the
# PowerShell process that is executing this script.
Get-CimInstance Win32_Process | Where-Object {
    $_.Name -in @("uv.exe", "python.exe", "pythonw.exe") -and
    $_.CommandLine -like "*$ProjectRoot*server.py*"
} | Sort-Object ParentProcessId | ForEach-Object {
    Start-Process -FilePath "taskkill.exe" -ArgumentList @("/PID", $_.ProcessId, "/T", "/F") -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
}

Write-Host "All background agent processes stopped." -ForegroundColor Green
