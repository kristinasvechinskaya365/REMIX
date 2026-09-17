from __future__ import annotations

import json
from pathlib import Path

from .model import (
    AnalysisCase, AndroidArtifact, DynamicModule, Evidence, FunctionNode, ImportRef,
    JNIMapping, ModuleAnalysis, StringRef, SymbolRef,
)


def module_to_dict(m: ModuleAnalysis) -> dict:
    from dataclasses import asdict
    return asdict(m)


def module_from_dict(d: dict) -> ModuleAnalysis:
    m = ModuleAnalysis(
        path=d["path"], name=d["name"], sha256=d["sha256"], arch=d.get("arch", ""),
        bits=d.get("bits", 0), image_base=d.get("image_base", 0), entry=d.get("entry", 0),
        relocations=d.get("relocations", []), sections=d.get("sections", []),
        metadata=d.get("metadata", {}), errors=d.get("errors", []),
    )
    for fd in d.get("functions", []):
        ev = [Evidence(**x) for x in fd.pop("evidence", [])]
        f = FunctionNode(**{k: v for k, v in fd.items() if k in FunctionNode.__dataclass_fields__})
        f.evidence = ev
        m.functions.append(f)
    m.strings = [StringRef(**{k: v for k, v in x.items() if k in StringRef.__dataclass_fields__}) for x in d.get("strings", [])]
    m.imports = [ImportRef(**{k: v for k, v in x.items() if k in ImportRef.__dataclass_fields__}) for x in d.get("imports", [])]
    m.symbols = [SymbolRef(**{k: v for k, v in x.items() if k in SymbolRef.__dataclass_fields__}) for x in d.get("symbols", [])]
    m.jni = [JNIMapping(**{k: v for k, v in x.items() if k in JNIMapping.__dataclass_fields__}) for x in d.get("jni", [])]
    return m


def case_from_dict(d: dict) -> AnalysisCase:
    art = AndroidArtifact(**d["artifact"]) if d.get("artifact") else None
    c = AnalysisCase(
        case_dir=d["case_dir"], target=d["target"], mode=d["mode"], created_at=d["created_at"],
        artifact=art, java_findings=d.get("java_findings", []), dynamic_events=d.get("dynamic_events", []),
        topology=d.get("topology", []), summary=d.get("summary", {}), warnings=d.get("warnings", []), errors=d.get("errors", []),
    )
    c.modules = [module_from_dict(x) for x in d.get("modules", [])]
    c.dynamic_modules = [DynamicModule(**x) for x in d.get("dynamic_modules", [])]
    return c


def load_case(path: str | Path) -> AnalysisCase:
    path = Path(path)
    if path.is_dir():
        path = path / "case.json"
    return case_from_dict(json.loads(path.read_text(encoding="utf-8")))
