# Talos — AgentGuard

AgentGuard is a local-first security firewall proxy for AI agents. It combines inbound indirect-prompt-injection detection, outbound DLP, risk-based policy enforcement, a mock agent environment, a FastAPI HITL API, a Streamlit security dashboard, and red-team regression benchmarks.

## Repository layout

- `agentguard/` — Python security engine, database layer, FastAPI HITL API, Streamlit dashboard, mock tools, and tests.
- `dashboard/` — React command-center frontend for live telemetry and quarantine review.
- `requirements.txt` — Python runtime dependencies.

## Python setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Initialize SQLite tables:

```bash
python3 -c "from agentguard.database import init_db; init_db()"
```

Run the FastAPI HITL API:

```bash
uvicorn agentguard.hitl_api:app --reload --port 8000
```

Run the Streamlit operations dashboard:

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

Run all standalone security-module tests:

```bash
python3 -m agentguard.inbound_scanner
python3 -m agentguard.outbound_dlp
python3 -m agentguard.policy_engine
python3 -m agentguard.agent_guard_middleware
python3 -m agentguard.quarantine_manager
```

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
