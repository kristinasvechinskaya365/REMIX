#!/usr/bin/env python3
import hashlib, tarfile
from pathlib import Path

root=Path(__file__).resolve().parent
archive=root/".v301_patch.tar.gz"
expected="4f267ff5e5becb7bc5f05fc9dd67fe87e5e1a0d21ebc8b7bab39c4144d6e3667"
got=hashlib.sha256(archive.read_bytes()).hexdigest()
print("PATCH_SHA256",got)
if got != expected:
    raise SystemExit("patch SHA-256 mismatch")
with tarfile.open(archive,"r:gz") as tf:
    rr=root.resolve()
    for member in tf.getmembers():
        target=(root/member.name).resolve()
        if rr not in target.parents and target != rr:
            raise SystemExit(f"unsafe path: {member.name}")
    tf.extractall(root, filter="fully_trusted")
print("REMIX_V301_PATCH_APPLIED")
