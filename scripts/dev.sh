#!/usr/bin/env bash
# Developer bootstrap + checks for IsaHat.
# Usage: scripts/dev.sh [setup|check|lab|scan-lab]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

setup() {
  python3 -m venv .venv
  # shellcheck disable=SC1091
  source .venv/bin/activate
  python -m pip install --upgrade pip
  pip install -e ".[dev]"
  echo "Done. Activate with: source .venv/bin/activate"
}

check() {
  # shellcheck disable=SC1091
  source .venv/bin/activate
  ruff check src tests
  mypy
  pytest -q
}

lab() {
  # shellcheck disable=SC1091
  source .venv/bin/activate
  python labs/vulnerable_apps/simple_app/app.py --port 8123
}

scan_lab() {
  # shellcheck disable=SC1091
  source .venv/bin/activate
  isahat scan http://127.0.0.1:8123 --yes --verbose
}

case "${1:-check}" in
  setup) setup ;;
  check) check ;;
  lab) lab ;;
  scan-lab) scan_lab ;;
  *) echo "usage: scripts/dev.sh [setup|check|lab|scan-lab]" ; exit 2 ;;
esac
