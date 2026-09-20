#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${ROOT_DIR}/.venv"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python 3 is required." >&2
  exit 1
fi

if [[ ! -d "$VENV_DIR" ]]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"
python -m pip install --upgrade pip
python -m pip install -r "${ROOT_DIR}/requirements.txt"
python -m agentguard.database 2>/dev/null || true
python -c "from agentguard.database import init_db; init_db()"

if command -v pnpm >/dev/null 2>&1; then
  (cd "${ROOT_DIR}/dashboard" && pnpm install --frozen-lockfile)
elif command -v npm >/dev/null 2>&1; then
  echo "pnpm is unavailable; use 'npm install' in dashboard for frontend dependencies." >&2
else
  echo "Install Node.js and pnpm to run the React dashboard." >&2
fi

echo
echo "AgentGuard setup complete. Run ./start.sh to launch the API, Streamlit dashboard, and React frontend."
