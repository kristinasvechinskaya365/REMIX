from __future__ import annotations

import json
from pathlib import Path

from .model import ModuleAnalysis
from .serde import module_from_dict, module_to_dict
from .runner import atomic_json


class ModuleCache:
    def __init__(self, root: str | Path | None = None, *, version: str = "2"):
        self.root = Path(root or (Path.home() / ".cache/remix"))
        self.version = version

    def path(self, sha256: str, mode: str) -> Path:
        return self.root / self.version / mode / f"{sha256}.json"

    def get(self, sha256: str, mode: str, actual_path: str) -> ModuleAnalysis | None:
        p = self.path(sha256, mode)
        if not p.exists():
            return None
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            m = module_from_dict(d)
            m.path = actual_path
            m.metadata["cache_hit"] = True
            return m
        except Exception:
            return None

    def put(self, m: ModuleAnalysis, mode: str) -> None:
        p = self.path(m.sha256, mode)
        atomic_json(p, module_to_dict(m))
