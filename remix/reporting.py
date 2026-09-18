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
        f"- Xref edges indexed: **{s.get('xref_edges', 0)}**",
        f"- PLT/GOT relocations: **{s.get('pltgot_relocations', 0)}**",
        f"- Constructors/destructors: **{s.get('constructors', 0)} / {s.get('destructors', 0)}**",
        f"- C++ RTTI/vtable objects: **{s.get('cxx_type_objects', 0)}**",
        f"- Dynamic events correlated: **{s.get('dynamic_events', 0)}**", "",
        "## Semantic topology", "",
    ]
    for tag, count in (s.get("tag_counts") or {}).items():
        lines.append(f"- `{tag}`: {count} ranked functions")
    lines += ["", "## Mechanism fingerprints", ""]
    for mech, rows in (s.get("mechanisms") or {}).items():
        lines.append(f"### `{mech}`")
        for row in rows:
            lines.append(f"- `{row['module']}`: {', '.join('`'+x+'`' for x in row.get('imports', []))}")
        lines.append("")
    lines += ["## Semantic flow roots / hubs / sinks", ""]
    for tag, flow in (s.get("semantic_flows") or {}).items():
        roots = ", ".join(f"`{x['module']}+{x['offset_hex']} {x['name']}`" for x in flow.get("roots", [])[:4]) or "-"
        hubs = ", ".join(f"`{x['module']}+{x['offset_hex']} {x['name']}`" for x in flow.get("hubs", [])[:4]) or "-"
        sinks = ", ".join(f"`{x['module']}+{x['offset_hex']} {x['name']}`" for x in flow.get("sinks", [])[:4]) or "-"
        lines.append(f"- **{tag}** ({flow.get('functions',0)} fn): roots {roots}; hubs {hubs}; sinks {sinks}")
    lines += ["", "## Module loader topology", ""]
    for m in case.modules:
        sec = m.metadata.get("security") or {}
        lines.append(f"### `{m.name}`")
        lines.append(f"- SHA-256 `{m.sha256}`; arch `{m.arch}`/{m.bits}; image base `{hex(m.image_base)}`")
        lines.append(f"- DT_NEEDED: {', '.join('`'+x+'`' for x in m.metadata.get('libraries', [])) or '-'}")
        lines.append(f"- PIE={sec.get('pie')} RELRO={sec.get('relro_segment')} NX_STACK={sec.get('nx_stack')} RWX_SEGMENTS={sec.get('rwx_segment_count')}")
        lines.append(f"- ctors={len(m.metadata.get('constructors') or [])} dtors={len(m.metadata.get('destructors') or [])} pltgot={len(m.metadata.get('pltgot_relocations') or [])} RTTI/vtable={len(m.metadata.get('cxx_type_topology') or [])}")
        lines.append("")
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
    CREATE TABLE symbols(module TEXT,name TEXT,demangled TEXT,address INTEGER,size INTEGER,bind TEXT,type TEXT,visibility TEXT,section TEXT,imported INTEGER,exported INTEGER,tags TEXT);
    CREATE INDEX symbols_name ON symbols(name);
    CREATE TABLE xrefs(module TEXT,src_function INTEGER,from_addr INTEGER,to_addr INTEGER,type TEXT,to_function INTEGER,to_symbol TEXT,to_import TEXT,to_string TEXT,payload TEXT);
    CREATE INDEX xrefs_src ON xrefs(module,src_function);
    CREATE INDEX xrefs_to ON xrefs(module,to_addr);
    CREATE TABLE relocations(module TEXT,address INTEGER,type TEXT,symbol TEXT,purpose TEXT,payload TEXT);
    CREATE TABLE java(kind TEXT,class TEXT,method TEXT,file TEXT,line INTEGER,tags TEXT,payload TEXT);
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
        for sy in m.symbols:
            db.execute("INSERT INTO symbols VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                       (m.name, sy.name, sy.demangled, sy.address, sy.size, sy.bind, sy.type, sy.visibility, sy.section, int(sy.imported), int(sy.exported), json.dumps(sy.tags)))
        for f in m.functions:
            for xr in f.xrefs_from:
                db.execute("INSERT INTO xrefs VALUES(?,?,?,?,?,?,?,?,?,?)",
                           (m.name, f.address, xr.get("from"), xr.get("to"), xr.get("type"), xr.get("to_function"), xr.get("to_symbol"), xr.get("to_import"), xr.get("to_string"), json.dumps(xr)))
        for r in (m.metadata.get("lief_relocations") or m.relocations or []):
            db.execute("INSERT INTO relocations VALUES(?,?,?,?,?,?)",
                       (m.name, r.get("address") or r.get("vaddr") or 0, str(r.get("type", "")), str(r.get("symbol", "")), str(r.get("purpose", "")), json.dumps(r)))
        for j in m.jni:
            db.execute("INSERT INTO jni VALUES(?,?,?,?,?,?,?,?)", (m.name, j.java_class, j.java_method, j.signature, j.native_address, j.native_offset, j.source, j.confidence))
    for row in case.java_findings:
        db.execute("INSERT INTO java VALUES(?,?,?,?,?,?,?)",
                   (row.get("kind"), row.get("class"), row.get("method"), row.get("file"), row.get("line") or row.get("start_line") or 0, json.dumps(row.get("tags") or []), json.dumps(row)))
    for e in case.topology:
        db.execute("INSERT INTO edges VALUES(?,?,?,?,?)", (e.get("kind"), e.get("module"), str(e.get("from", "")), str(e.get("to", e.get("to_name", ""))), json.dumps(e)))
    db.commit(); db.close()
