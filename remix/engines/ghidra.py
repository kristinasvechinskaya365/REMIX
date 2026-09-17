from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

from ..model import Evidence, ModuleAnalysis
from ..runner import Budget, run


class GhidraEngine:
    def __init__(self, *, budget: Budget, script_dir: str | Path):
        self.budget = budget
        self.script_dir = Path(script_dir)
        self.headless = self._find_headless()

    def _find_headless(self) -> str | None:
        p = shutil.which("analyzeHeadless")
        if p:
            return p
        roots = [Path("/Applications"), Path.home() / "Applications", Path.home() / "ghidra"]
        candidates = []
        for root in roots:
            if root.exists():
                candidates += list(root.glob("**/support/analyzeHeadless"))
        return str(sorted(candidates)[-1]) if candidates else None

    @property
    def available(self) -> bool:
        return bool(self.headless)

    def enrich(self, module: ModuleAnalysis, offsets: list[int], *, case_dir: str | Path, timeout: int = 120) -> list[dict]:
        if not self.headless or not offsets:
            return []
        case_dir = Path(case_dir)
        out = case_dir / "ghidra" / f"{module.name}.jsonl"
        out.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="remix-ghidra-") as proj:
            argv = [
                self.headless, proj, "REMIX", "-import", module.path,
                "-scriptPath", str(self.script_dir),
                "-postScript", "RemixFunctionDossier.java", str(out), ",".join(hex(x) for x in offsets),
                "-analysisTimeoutPerFile", str(max(30, timeout - 10)), "-deleteProject",
            ]
            rr = run(argv, timeout=self.budget.clamp(timeout))
            (out.parent / f"{module.name}.log").write_text(rr.stdout + "\n" + rr.stderr, errors="replace")
        rows = []
        if out.exists():
            for line in out.read_text(errors="replace").splitlines():
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
        byoff = {f.offset: f for f in module.functions}
        for row in rows:
            try:
                off = int(str(row.get("offset")), 0)
            except Exception:
                continue
            fn = byoff.get(off)
            if not fn:
                continue
            if row.get("pseudocode") and not fn.pseudocode:
                fn.pseudocode = row["pseudocode"]
            fn.evidence.append(Evidence("ghidra", "function-dossier", row, 1.0))
        return rows
