#!/usr/bin/env bash
# Start both CloudLab twins (vuln :4566, hardened :4567) and wait for Ctrl-C.
set -euo pipefail
cd "$(dirname "$0")"
PY="${PYTHON:-../../.venv/bin/python}"
[[ -x "$PY" ]] || PY="python3"

"$PY" server.py --mode vuln --port 4566 &
VULN=$!
"$PY" server.py --mode hardened --port 4567 &
HARD=$!
trap 'kill $VULN $HARD 2>/dev/null || true' EXIT
cat <<'EOF'
CloudLab twins (moto, in-memory, fake data):
  vuln     http://127.0.0.1:4566
  hardened http://127.0.0.1:4567
Press Ctrl-C to stop. Self-check: python verify_ground_truth.py
EOF
wait