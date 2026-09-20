$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$null = Set-Location $Root
$VenvPython = Join-Path $Root '.venv\Scripts\python.exe'
$Dashboard = Join-Path $Root 'dashboard'

if (-not (Test-Path $VenvPython)) {
    throw 'Talos is not set up. Run .\setup.ps1 first.'
}
if (-not (Get-Command pnpm -ErrorAction SilentlyContinue)) {
    throw 'pnpm is required for the React dashboard. Install it with: npm install -g pnpm'
}

& $VenvPython -c "from agentguard.database import init_db; init_db()"
$env:VITE_AGENTGUARD_API_URL = if ($env:VITE_AGENTGUARD_API_URL) { $env:VITE_AGENTGUARD_API_URL } else { 'http://localhost:8000' }

$Api = Start-Process -FilePath $VenvPython -ArgumentList '-m','uvicorn','agentguard.hitl_api:app','--host','127.0.0.1','--port','8000' -WorkingDirectory $Root -PassThru
$Streamlit = Start-Process -FilePath $VenvPython -ArgumentList '-m','streamlit','run','agentguard/app.py','--server.headless','true','--server.port','8501' -WorkingDirectory $Root -PassThru
$Frontend = Start-Process -FilePath 'pnpm.cmd' -ArgumentList 'dev','--host','0.0.0.0','--port','3000' -WorkingDirectory $Dashboard -PassThru

Write-Host ''
Write-Host 'Talos is running:' -ForegroundColor Green
Write-Host '  React dashboard:       http://localhost:3000'
Write-Host '  Streamlit dashboard:   http://localhost:8501'
Write-Host '  FastAPI Swagger docs:  http://localhost:8000/docs'
Write-Host ''
Write-Host 'Close the three service windows, or press Ctrl+C here to stop child processes.'

try {
    Wait-Process -Id $Api.Id, $Streamlit.Id, $Frontend.Id
} finally {
    foreach ($Process in @($Api, $Streamlit, $Frontend)) {
        if ($Process -and -not $Process.HasExited) {
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        }
    }
}
