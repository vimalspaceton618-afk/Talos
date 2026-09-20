# Talos — AgentGuard

AgentGuard is a local-first security firewall proxy for AI agents. It combines inbound indirect-prompt-injection detection, outbound DLP, risk-based policy enforcement, a mock agent environment, a FastAPI HITL API, a Streamlit security dashboard, and red-team regression benchmarks.

## Plug-and-play quick start

Requirements: Python 3.11+, Node.js 20+, and `pnpm`.

```bash
git clone https://github.com/vimalspaceton618-afk/Talos.git
cd Talos
cp .env.example .env
chmod +x setup.sh start.sh
./setup.sh
./start.sh
```

This launches the FastAPI API at `http://localhost:8000`, the Streamlit operations dashboard at `http://localhost:8501`, and the React command center at `http://localhost:3000`. Press `Ctrl+C` once to stop all three processes.

For a backend-only install, use `pip install -e .` after creating a virtual environment. The default SQLite database is created automatically on startup.

## Repository layout

- `agentguard/` — Python security engine, database layer, FastAPI HITL API, Streamlit dashboard, mock tools, and tests.
- `dashboard/` — React command-center frontend for live telemetry and quarantine review.
- `requirements.txt` — Python runtime dependencies.
- `setup.sh` — one-command environment and dependency setup.
- `start.sh` — one-command API, Streamlit, and React launcher.
- `.env.example` — safe local configuration defaults.

## Python setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Initialize SQLite tables:

```bash
python3 -c "from agentguard.database import init_db; init_db()"
```

Run the FastAPI HITL API manually:

```bash
uvicorn agentguard.hitl_api:app --reload --port 8000
```

Run the Streamlit operations dashboard manually:

```bash
streamlit run agentguard/app.py
```

Run the red-team suite:

```bash
python3 -m unittest -v agentguard.test_red_team
```

Print benchmark analytics:

```bash
python3 -m agentguard.test_red_team --benchmark
```

## GitHub Actions security regression testing

The workflow at `.github/workflows/security-regression.yml` runs automatically on pushes and pull requests targeting `main`, and can also be started manually from the **Actions** tab. It installs the pinned Python dependency set, compiles the package, runs the red-team suite, runs every standalone security-module test, and uploads the benchmark JSON as a 30-day workflow artifact.

To require the security suite before merging, open **Settings → Branches → Branch protection rules**, protect `main`, and require the check named **AgentGuard Security Regression / Red-team suite and benchmark**. No repository secrets are required because the suite uses deterministic local fixtures.

Run all standalone security-module tests:

```bash
python3 -m agentguard.inbound_scanner
python3 -m agentguard.outbound_dlp
python3 -m agentguard.policy_engine
python3 -m agentguard.agent_guard_middleware
python3 -m agentguard.quarantine_manager
```

## Windows PowerShell

Do not run `chmod` in PowerShell; it is a Linux/macOS command. Do not launch the `.sh` files directly from Windows unless you are using WSL or Git Bash. Use the native PowerShell scripts:

```powershell
git clone https://github.com/vimalspaceton618-afk/Talos.git
cd Talos
Copy-Item .env.example .env
npm install -g pnpm
.\setup.ps1
.\start.ps1
```

If PowerShell blocks local scripts, allow them for your user account once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

The services open at `http://localhost:3000` (React), `http://localhost:8501` (Streamlit), and `http://localhost:8000/docs` (FastAPI). If you use WSL or Git Bash, the original `./setup.sh` and `./start.sh` commands remain supported.

## React dashboard

```bash
cd dashboard
pnpm install
pnpm check
pnpm build
pnpm dev
```

Set `VITE_AGENTGUARD_API_URL` to the FastAPI base URL when connecting the React dashboard to a running backend. The dashboard falls back to demo telemetry when the API is unavailable.

## Security notes

The default configuration is intended for local development and demonstration. Before production use, configure authentication and authorization for the FastAPI and dashboard surfaces, replace the in-process notification registry with a durable event transport, and review destination allowlists and database access controls.
