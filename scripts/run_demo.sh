#!/usr/bin/env bash
# Run the full demo non-interactively. POSIX shells.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

PYTHON="${PYTHON:-python3}"

if [ ! -d ".venv" ]; then
    "$PYTHON" -m venv .venv
fi
# shellcheck disable=SC1091
. .venv/bin/activate

pip install --upgrade pip >/dev/null
pip install -e . >/dev/null

python -m hacking_ai_agents.cli full-demo --no-pause "$@"
