#!/usr/bin/env python3
import base64, io, tarfile
from pathlib import Path
root=Path(__file__).resolve().parent
parts=sorted((root/"bootstrap_payload").glob("*.b64"))
if not parts:
    raise SystemExit("missing bootstrap payload")
data=base64.b64decode("".join(p.read_text().strip() for p in parts))
with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
    members=tf.getmembers()
    rr=root.resolve()
    for member in members:
        target=(root/member.name).resolve()
        if rr not in target.parents and target != rr:
            raise SystemExit(f"unsafe archive path: {member.name}")
    tf.extractall(root, filter="fully_trusted")
print(f"REMIX_BOOTSTRAP_OK files={len(members)}")
