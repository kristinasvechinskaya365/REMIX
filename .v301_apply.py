#!/usr/bin/env python3
import hashlib, tarfile
from pathlib import Path

root=Path(__file__).resolve().parent
archive=root/".v301_patch.tar.gz"
expected="0d41170a09ec9d8a3eae2fc308b844b4d8a8c3f1d01a2ad2ba153767f75613ae"
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
