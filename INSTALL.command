#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
LAB="${ANDROID_CTF_LAB:-$HOME/AndroidCTFMax}"
PY="${REMIX_PYTHON:-$(command -v python3)}"
mkdir -p "$LAB/remix-v2" "$LAB/bin"
rm -rf "$LAB/remix-v2/app"
cp -R "$ROOT" "$LAB/remix-v2/app"
cat > "$LAB/bin/remix" <<EOF
#!/usr/bin/env bash
exec "$PY" -m remix "\$@"
EOF
chmod +x "$LAB/bin/remix"
# Run from installed source without mutating site-packages.
python3 - <<PY
from pathlib import Path
p=Path.home()/'.zshrc'
print('Installed REMIX source under $LAB/remix-v2/app')
PY
cat > "$LAB/bin/remix" <<EOF
#!/usr/bin/env bash
export PYTHONPATH="$LAB/remix-v2/app:\${PYTHONPATH:-}"
exec "$PY" -m remix "\$@"
EOF
chmod +x "$LAB/bin/remix"
echo "Installed: $LAB/bin/remix"
echo "Run: $LAB/bin/remix doctor --serial emulator-5554"
