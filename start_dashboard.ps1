param([switch]$OpenBrowser, [int]$BackendPort = 8000, [int]$FrontendPort = 5173)
$ErrorActionPreference = 'Stop'
foreach ($port in @($BackendPort, $FrontendPort)) {
    if (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue) {
        throw "Port $port is already in use. Stop its server or choose another port."
    }
}
$backend = Join-Path $PSScriptRoot 'dashboard\backend'
$frontend = Join-Path $PSScriptRoot 'dashboard\frontend'
$python = (Get-Command python -ErrorAction Stop).Source
$npm = (Get-Command npm.cmd -ErrorAction Stop).Source
$logs = Join-Path $PSScriptRoot 'logs'
New-Item -ItemType Directory -Force -Path $logs | Out-Null
if (-not (Test-Path (Join-Path $frontend 'node_modules'))) {
    throw 'Install frontend dependencies first: cd dashboard/frontend; npm.cmd ci'
}
$backendProcess = Start-Process -FilePath $python -WindowStyle Hidden -WorkingDirectory $backend -ArgumentList @('-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', $BackendPort) -RedirectStandardOutput (Join-Path $logs 'backend.log') -RedirectStandardError (Join-Path $logs 'backend-error.log') -PassThru
$env:VITE_PROXY_TARGET = "http://127.0.0.1:$BackendPort"
$frontendProcess = Start-Process -FilePath $npm -WindowStyle Hidden -WorkingDirectory $frontend -ArgumentList @('run', 'dev', '--', '--host', '127.0.0.1', '--port', $FrontendPort, '--strictPort') -RedirectStandardOutput (Join-Path $logs 'frontend.log') -RedirectStandardError (Join-Path $logs 'frontend-error.log') -PassThru
@{ backend = $backendProcess.Id; frontend = $frontendProcess.Id } | ConvertTo-Json | Set-Content (Join-Path $logs 'processes.json')
Write-Host "Dashboard: http://127.0.0.1:$FrontendPort"
Write-Host "API docs: http://127.0.0.1:$BackendPort/docs"
Write-Host "Logs and process IDs: $logs"
if ($OpenBrowser) { Start-Process "http://127.0.0.1:$FrontendPort" }
