from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .model import AnalysisCase
from .runner import atomic_json


def write_case(case: AnalysisCase) -> None:
    root = Path(case.case_dir)
    root.mkdir(parents=True, exist_ok=True)
    atomic_json(root / "case.json", case.to_dict())
    _write_jsonl(case, root / "functions.jsonl")
    _write_graph(case, root / "topology.dot")
    _write_markdown(case, root / "REPORT.md")
    _write_sqlite(case, root / "case.sqlite")


def _write_jsonl(case: AnalysisCase, path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        for m in case.modules:
            for fn in m.functions:
                row = fn.to_dict()
                row["module_path"] = m.path
                f.write(json.dumps(row, sort_keys=True) + "\n")


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _write_graph(case: AnalysisCase, path: Path) -> None:
    lines = ["digraph REMIX {", "  rankdir=LR;", "  node [shape=box,fontname=monospace];"]
    count = 0
    for e in case.topology:
        if count >= 5000:
            break
        if e["kind"] == "call":
            a = f'{e["module"]}:{e["from_hex"]}'
            b = f'{e["module"]}:{e["to_hex"]}'
            lines.append(f'  "{_esc(a)}" -> "{_esc(b)}" [label="call"];')
            count += 1
        elif e["kind"] == "jni":
            a = str(e["from"]); b = f'{e["module"]}:{e["to_hex"]}'
            lines.append(f'  "{_esc(a)}" -> "{_esc(b)}" [label="JNI"];')
            count += 1
    lines.append("}")
    path.write_text("\n".join(lines) + "\n")


def _write_markdown(case: AnalysisCase, path: Path) -> None:
    s = case.summary
    lines = [
        "# REMIX reverse-engineering report", "",
        f"- Target: `{case.target}`",
        f"- Mode: `{case.mode}`",
        f"- Created: `{case.created_at}`",
        f"- Native modules analyzed: **{s.get('modules', 0)}**",
        f"- Functions indexed: **{s.get('functions', 0)}**",
        f"- Strings indexed: **{s.get('strings', 0)}**",
        f"- Imports indexed: **{s.get('imports', 0)}**",
        f"- JNI mappings: **{s.get('jni_mappings', 0)}**",
        f"- Dynamic events correlated: **{s.get('dynamic_events', 0)}**", "",
        "## Semantic topology", "",
    ]
    for tag, count in (s.get("tag_counts") or {}).items():
        lines.append(f"- `{tag}`: {count} ranked functions")
    lines += ["", "## Highest-value functions", "",
              "| score | module | offset | function | tags |",
              "|---:|---|---:|---|---|"]
    for row in (s.get("top_functions") or [])[:80]:
        lines.append(f"| {row['score']:.2f} | `{row['module']}` | `{row['offset_hex']}` | `{row['name']}` | {', '.join(row['tags'])} |")
    if case.warnings:
        lines += ["", "## Warnings", ""] + [f"- {x}" for x in case.warnings]
    if case.errors:
        lines += ["", "## Errors", ""] + [f"- {x}" for x in case.errors]
    lines += ["", "## Artifacts", "",
              "- `case.json` — complete machine-readable evidence model",
              "- `case.sqlite` — queryable functions/xrefs/strings/imports/JNI index",
              "- `functions.jsonl` — one normalized function dossier per line",
              "- `topology.dot` — call/JNI topology for Graphviz or text tooling",
              "- `artifact/` — acquired APK/DEX/native inputs",
              "- `live-root/` — non-instrumented runtime snapshot when enabled",
              "- `live-frida/events.jsonl` — instrumented runtime observations when explicitly enabled",
              ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_sqlite(case: AnalysisCase, path: Path) -> None:
    if path.exists():
        path.unlink()
    db = sqlite3.connect(path)
    db.executescript("""
    CREATE TABLE functions(module TEXT,address INTEGER,offset INTEGER,name TEXT,size INTEGER,score REAL,tags TEXT,
                           callers TEXT,callees TEXT,imports TEXT,jni TEXT,PRIMARY KEY(module,address));
    CREATE INDEX functions_score ON functions(score DESC);
    CREATE INDEX functions_offset ON functions(module,offset);
    CREATE TABLE strings(module TEXT,address INTEGER,value TEXT,tags TEXT,refs_from TEXT);
    CREATE INDEX strings_value ON strings(value);
    CREATE TABLE imports(module TEXT,name TEXT,address INTEGER,plt INTEGER,library TEXT,tags TEXT,refs_from TEXT);
    CREATE TABLE jni(module TEXT,java_class TEXT,java_method TEXT,signature TEXT,native_address INTEGER,native_offset INTEGER,source TEXT,confidence REAL);
    CREATE TABLE edges(kind TEXT,module TEXT,src TEXT,dst TEXT,payload TEXT);
    """)
    for m in case.modules:
        for f in m.functions:
            db.execute("INSERT INTO functions VALUES(?,?,?,?,?,?,?,?,?,?,?)", (
                m.name, f.address, f.offset, f.name, f.size, f.score, json.dumps(f.tags), json.dumps(f.callers),
                json.dumps(f.callees), json.dumps(f.imports), json.dumps(f.jni_methods)))
        for st in m.strings:
            db.execute("INSERT INTO strings VALUES(?,?,?,?,?)", (m.name, st.address, st.value, json.dumps(st.tags), json.dumps(st.refs_from)))
        for im in m.imports:
            db.execute("INSERT INTO imports VALUES(?,?,?,?,?,?,?)", (m.name, im.name, im.address, im.plt, im.library, json.dumps(im.tags), json.dumps(im.refs_from)))
        for j in m.jni:
            db.execute("INSERT INTO jni VALUES(?,?,?,?,?,?,?,?)", (m.name, j.java_class, j.java_method, j.signature, j.native_address, j.native_offset, j.source, j.confidence))
    for e in case.topology:
        db.execute("INSERT INTO edges VALUES(?,?,?,?,?)", (e.get("kind"), e.get("module"), str(e.get("from", "")), str(e.get("to", e.get("to_name", ""))), json.dumps(e)))
    db.commit(); db.close()
