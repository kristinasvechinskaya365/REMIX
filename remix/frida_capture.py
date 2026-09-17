from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--package", required=True)
    ap.add_argument("--script", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--duration", type=float, default=20)
    ap.add_argument("--endpoint")
    ap.add_argument("--spawn", action="store_true")
    args = ap.parse_args()

    import frida  # type: ignore

    if args.endpoint:
        dev = frida.get_device_manager().add_remote_device(args.endpoint)
    else:
        try:
            dev = frida.get_usb_device(timeout=5)
        except Exception:
            dev = frida.get_local_device()

    pid = None
    if args.spawn:
        pid = dev.spawn([args.package])
        session = dev.attach(pid)
    else:
        try:
            session = dev.attach(args.package)
        except Exception:
            pid = dev.spawn([args.package])
            session = dev.attach(pid)

    js = Path(args.script).read_text(encoding="utf-8")
    script = session.create_script(js)
    outp = Path(args.out)
    outp.parent.mkdir(parents=True, exist_ok=True)
    f = outp.open("w", encoding="utf-8")

    def on_message(message, data):
        row = {"ts": time.time(), "message": message}
        if data is not None:
            row["data_len"] = len(data)
        if message.get("type") == "send" and isinstance(message.get("payload"), dict):
            row = {"ts": time.time(), **message["payload"]}
        f.write(json.dumps(row, sort_keys=True) + "\n")
        f.flush()

    script.on("message", on_message)
    script.load()
    if pid is not None:
        dev.resume(pid)
    try:
        time.sleep(args.duration)
    finally:
        try:
            session.detach()
        except Exception:
            pass
        f.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
