#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
LAB="${ANDROID_CTF_LAB:-$HOME/AndroidCTFMax}"
PY="${REMIX_PYTHON:-$(command -v python3)}"
DEST="$LAB/remix-v3/app"
mkdir -p "$LAB/remix-v3" "$LAB/bin"
rm -rf "$DEST"
cp -R "$ROOT" "$DEST"
cat > "$LAB/bin/remix" <<EOF
#!/usr/bin/env bash
export PYTHONPATH="$DEST:\${PYTHONPATH:-}"
exec "$PY" -m remix "\$@"
EOF
chmod +x "$LAB/bin/remix"
echo "Installed: $LAB/bin/remix"
echo "Source:    $DEST"
echo "Try:       $LAB/bin/remix engines --available"
