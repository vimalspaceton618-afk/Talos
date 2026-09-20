$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$null = Set-Location $Root
$Venv = Join-Path $Root '.venv'
$Python = if (Get-Command py -ErrorAction SilentlyContinue) { 'py' } else { 'python' }

Write-Host 'Setting up Talos / AgentGuard...' -ForegroundColor Cyan

if (-not (Test-Path $Venv)) {
    & $Python -3 -m venv $Venv
}

$VenvPython = Join-Path $Venv 'Scripts\python.exe'
if (-not (Test-Path $VenvPython)) {
    throw "Could not create the Python virtual environment at $Venv"
}

& $VenvPython -m pip install --upgrade pip
& $VenvPython -m pip install -r (Join-Path $Root 'requirements.txt')
& $VenvPython -c "from agentguard.database import init_db; init_db()"

$Dashboard = Join-Path $Root 'dashboard'
if (Get-Command pnpm -ErrorAction SilentlyContinue) {
    Push-Location $Dashboard
    try { pnpm install --frozen-lockfile } finally { Pop-Location }
} else {
    Write-Warning 'pnpm was not found. Install it with: npm install -g pnpm, then run this script again.'
}

Write-Host ''
Write-Host 'Talos setup complete.' -ForegroundColor Green
Write-Host 'Run .\start.ps1 to launch the services.'
