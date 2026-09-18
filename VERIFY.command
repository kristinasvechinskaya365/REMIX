#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
python3 -m compileall -q remix tests
python3 -m unittest discover -v tests
python3 -m remix --version
python3 -m remix --help >/dev/null
python3 -m remix engines --no-version >/dev/null
python3 -m remix recipe list >/dev/null
python3 -m remix select --help >/dev/null
python3 -m remix flow --help >/dev/null
python3 -m remix validate --help >/dev/null
python3 -m remix decompile --help >/dev/null
python3 -m remix kotlin-names --help >/dev/null
echo REMIX_VERIFY_PASS
