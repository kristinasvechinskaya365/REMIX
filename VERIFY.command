#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
python3 -m compileall -q remix tests
python3 -m unittest discover -v tests
python3 -m remix --version
python3 -m remix --help >/dev/null
echo REMIX_VERIFY_PASS
