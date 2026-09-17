from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


class CommandError(RuntimeError):
    pass


@dataclass(slots=True)
class RunResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    elapsed: float
    timed_out: bool = False

    def json(self):
        return json.loads(self.stdout)


class Budget:
    def __init__(self, seconds: float | None):
        self.seconds = seconds
        self.started = time.monotonic()

    @property
    def remaining(self) -> float | None:
        if self.seconds is None:
            return None
        return max(0.0, self.seconds - (time.monotonic() - self.started))

    def clamp(self, requested: float | None, floor: float = 1.0) -> float | None:
        rem = self.remaining
        if rem is None:
            return requested
        if rem <= 0:
            raise TimeoutError("analysis budget exhausted")
        if requested is None:
            return max(floor, rem)
        return max(floor, min(requested, rem))


def run(argv: Iterable[str], *, timeout: float | None = None, cwd: str | Path | None = None,
        env: dict[str, str] | None = None, check: bool = False, input_text: str | None = None) -> RunResult:
    argv = [str(x) for x in argv]
    start = time.monotonic()
    try:
        cp = subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            env=env,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        result = RunResult(argv, cp.returncode, cp.stdout, cp.stderr, time.monotonic() - start)
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        err = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
        result = RunResult(argv, 124, out, err, time.monotonic() - start, timed_out=True)
    if check and result.returncode != 0:
        raise CommandError(f"command failed ({result.returncode}): {shlex.join(argv)}\n{result.stderr[-4000:]}")
    return result


def which_any(names: Iterable[str]) -> str | None:
    for name in names:
        p = shutil.which(name)
        if p:
            return p
    return None


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def atomic_json(path: str | Path, obj) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)
