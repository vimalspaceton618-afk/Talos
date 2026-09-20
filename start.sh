#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"
API_PORT="${AGENTGUARD_API_PORT:-8000}"
STREAMLIT_PORT="${AGENTGUARD_STREAMLIT_PORT:-8501}"
FRONTEND_PORT="${AGENTGUARD_FRONTEND_PORT:-3000}"

if [[ -f "${ROOT_DIR}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${ROOT_DIR}/.env"
  set +a
  API_PORT="${AGENTGUARD_API_PORT:-8000}"
  STREAMLIT_PORT="${AGENTGUARD_STREAMLIT_PORT:-8501}"
  FRONTEND_PORT="${AGENTGUARD_FRONTEND_PORT:-3000}"
fi

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  echo "Virtual environment not found. Run ./setup.sh first." >&2
  exit 1
fi
if ! command -v pnpm >/dev/null 2>&1; then
  echo "pnpm is required for the React frontend. Install Node.js/pnpm or run the API and Streamlit dashboard separately." >&2
  exit 1
fi

# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"
python -c "from agentguard.database import init_db; init_db()"

cleanup() {
  trap - INT TERM EXIT
  [[ -n "${API_PID:-}" ]] && kill "${API_PID}" 2>/dev/null || true
  [[ -n "${STREAMLIT_PID:-}" ]] && kill "${STREAMLIT_PID}" 2>/dev/null || true
  [[ -n "${FRONTEND_PID:-}" ]] && kill "${FRONTEND_PID}" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

python -m uvicorn agentguard.hitl_api:app --host "${AGENTGUARD_API_HOST:-127.0.0.1}" --port "$API_PORT" &
API_PID=$!
streamlit run agentguard/app.py --server.headless true --server.port "$STREAMLIT_PORT" &
STREAMLIT_PID=$!
(
  cd "${ROOT_DIR}/dashboard"
  VITE_AGENTGUARD_API_URL="${VITE_AGENTGUARD_API_URL:-http://localhost:${API_PORT}}" pnpm dev --host 0.0.0.0 --port "$FRONTEND_PORT"
) &
FRONTEND_PID=$!

echo "FastAPI:    http://localhost:${API_PORT}/docs"
echo "Streamlit:  http://localhost:${STREAMLIT_PORT}"
echo "React UI:   http://localhost:${FRONTEND_PORT}"
echo "Press Ctrl+C to stop all services."
wait -n "$API_PID" "$STREAMLIT_PID" "$FRONTEND_PID"
