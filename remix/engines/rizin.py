from __future__ import annotations

import json
import re
import tempfile
from bisect import bisect_right
from pathlib import Path
from typing import Any

from ..categories import classify, score_tags
from ..model import FunctionNode, ImportRef, ModuleAnalysis, StringRef, SymbolRef
from ..runner import Budget, run, sha256_file, which_any

MARK = "__REMIX_SECTION__"


def _json_from(text: str, default):
    text = text.strip()
    if not text:
        return default
    try:
        return json.loads(text)
    except Exception:
        for i, ch in enumerate(text):
            if ch in "[{":
                try:
                    return json.loads(text[i:])
                except Exception:
                    continue
    return default


def _num(v: Any, default=0) -> int:
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v, 0)
        except ValueError:
            return default
    return default


class RizinEngine:
    """Bulk Rizin extractor.

    The important performance property is one analysis process per ELF. We export
    functions, global xrefs, strings, symbols, imports, relocations and sections in
    one Rizin session, then correlate them in Python. We do *not* run `axt` once per
    function.
    """

    def __init__(self, *, budget: Budget, deep: bool = False, timeout: float = 90):
        self.rizin = which_any(["rizin", "rz-bin"])
        self.budget = budget
        self.deep = deep
        self.timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self.rizin and Path(self.rizin).name == "rizin")

    def _script(self) -> str:
        analysis = "aaa" if self.deep else "aa"
        sections = [
            ("meta", "ij"),
            ("functions", "aflj"),
            ("xrefs", "axj"),
            ("strings", "izzj"),
            ("imports", "iij"),
            ("symbols", "isj"),
            ("relocs", "irj"),
            ("sections", "iSj"),
        ]
        out = ["e scr.color=false", "e scr.utf8=false", analysis]
        for name, cmd in sections:
            out.append(f"?e {MARK}{name}")
            out.append(cmd)
        out.append("q")
        return "\n".join(out) + "\n"

    def _parse_sections(self, stdout: str) -> dict[str, Any]:
        chunks: dict[str, str] = {}
        current = None
        buf: list[str] = []
        for line in stdout.splitlines():
            if line.startswith(MARK):
                if current is not None:
                    chunks[current] = "\n".join(buf)
                current = line[len(MARK):].strip()
                buf = []
            elif current is not None:
                buf.append(line)
        if current is not None:
            chunks[current] = "\n".join(buf)
        return {
            "meta": _json_from(chunks.get("meta", ""), {}),
            "functions": _json_from(chunks.get("functions", ""), []),
            "xrefs": _json_from(chunks.get("xrefs", ""), []),
            "strings": _json_from(chunks.get("strings", ""), []),
            "imports": _json_from(chunks.get("imports", ""), []),
            "symbols": _json_from(chunks.get("symbols", ""), []),
            "relocs": _json_from(chunks.get("relocs", ""), []),
            "sections": _json_from(chunks.get("sections", ""), []),
        }

    def analyze(self, path: str | Path) -> ModuleAnalysis:
        path = Path(path)
        module = ModuleAnalysis(path=str(path), name=path.name, sha256=sha256_file(path))
        if not self.available:
            module.errors.append("rizin executable not found")
            return module

        with tempfile.NamedTemporaryFile("w", suffix=".rz", delete=False) as sf:
            sf.write(self._script())
            script_path = sf.name
        try:
            rr = run([self.rizin, "-2", "-q", "-i", script_path, str(path)],
                     timeout=self.budget.clamp(self.timeout))
        finally:
            Path(script_path).unlink(missing_ok=True)
        if rr.returncode != 0:
            module.errors.append(f"rizin rc={rr.returncode}: {rr.stderr[-1000:]}")
        data = self._parse_sections(rr.stdout)
        self._populate(module, data)
        module.metadata["rizin_elapsed"] = rr.elapsed
        module.metadata["rizin_timed_out"] = rr.timed_out
        return module

    def _populate(self, m: ModuleAnalysis, d: dict[str, Any]) -> None:
        meta = d.get("meta") or {}
        bininfo = meta.get("bin") or {}
        core = meta.get("core") or {}
        m.arch = str(bininfo.get("arch") or core.get("arch") or "")
        m.bits = _num(bininfo.get("bits") or core.get("bits"))
        m.entry = _num(bininfo.get("baddr") or bininfo.get("entry"))
        m.image_base = _num(bininfo.get("baddr") or 0)
        m.metadata["rizin_meta"] = meta

        funcs: list[FunctionNode] = []
        for row in d.get("functions") or []:
            addr = _num(row.get("offset") or row.get("addr"))
            size = _num(row.get("realsz") or row.get("size") or row.get("linearSize"))
            name = str(row.get("name") or row.get("realname") or f"fcn.{addr:x}")
            off = addr - m.image_base if m.image_base and addr >= m.image_base else addr
            fn = FunctionNode(m.name, addr, off, name, size=size, end=addr + max(size, 1))
            tags = classify(name)
            fn.tags = sorted(tags)
            fn.score += score_tags(tags, source="symbol") if tags else 0
            funcs.append(fn)
        funcs.sort(key=lambda x: x.address)
        m.functions = funcs

        strings: list[StringRef] = []
        for row in d.get("strings") or []:
            addr = _num(row.get("vaddr") or row.get("paddr"))
            value = str(row.get("string") or row.get("name") or "")
            sr = StringRef(
                address=addr,
                value=value,
                section=str(row.get("section") or ""),
                length=_num(row.get("length") or row.get("size")),
                tags=sorted(classify(value)),
            )
            strings.append(sr)
        m.strings = strings

        imports: list[ImportRef] = []
        for row in d.get("imports") or []:
            name = str(row.get("name") or row.get("pltname") or "")
            imp = ImportRef(
                name=name,
                address=_num(row.get("vaddr") or row.get("addr")) or None,
                plt=_num(row.get("plt") or row.get("vaddr")) or None,
                library=str(row.get("libname") or row.get("lib") or ""),
                tags=sorted(classify(name)),
            )
            imports.append(imp)
        m.imports = imports

        symbols: list[SymbolRef] = []
        for row in d.get("symbols") or []:
            addr = _num(row.get("vaddr") or row.get("addr"))
            name = str(row.get("name") or row.get("realname") or "")
            symbols.append(SymbolRef(
                name=name,
                address=addr,
                size=_num(row.get("size")),
                bind=str(row.get("bind") or ""),
                type=str(row.get("type") or ""),
                imported=bool(row.get("is_imported") or row.get("imported")),
                exported=bool(row.get("is_exported") or row.get("exported")),
            ))
        m.symbols = symbols
        m.relocations = list(d.get("relocs") or [])
        m.sections = list(d.get("sections") or [])

        self._correlate_xrefs(m, list(d.get("xrefs") or []))
        self._attach_symbol_names(m)

    def _correlate_xrefs(self, m: ModuleAnalysis, xrefs: list[dict[str, Any]]) -> None:
        if not m.functions:
            return
        starts = [f.address for f in m.functions]
        by_addr = {f.address: f for f in m.functions}
        strings_by_addr = {s.address: s for s in m.strings}
        imports_by_addr: dict[int, ImportRef] = {}
        for i in m.imports:
            if i.address is not None:
                imports_by_addr[i.address] = i
            if i.plt is not None:
                imports_by_addr[i.plt] = i

        def containing(addr: int) -> FunctionNode | None:
            idx = bisect_right(starts, addr) - 1
            if idx < 0:
                return None
            fn = m.functions[idx]
            if fn.address <= addr < fn.end:
                return fn
            return None

        symbol_by_addr = {s.address: s.name for s in m.symbols if s.address}
        for xr in xrefs:
            frm = _num(xr.get("from") or xr.get("from_addr") or xr.get("at"))
            to = _num(xr.get("to") or xr.get("to_addr") or xr.get("addr"))
            typ = str(xr.get("type") or xr.get("kind") or "").upper()
            src_fn = containing(frm)
            if not src_fn:
                continue
            dst_fn = containing(to)
            xrow = {
                "from": frm, "from_hex": hex(frm), "to": to, "to_hex": hex(to), "type": typ,
                "from_function": src_fn.address, "from_function_name": src_fn.name,
                "to_function": dst_fn.address if dst_fn else None,
                "to_function_name": dst_fn.name if dst_fn else "",
                "to_symbol": symbol_by_addr.get(to, ""),
                "to_string": strings_by_addr[to].value[:512] if to in strings_by_addr else "",
                "to_import": imports_by_addr[to].name if to in imports_by_addr else "",
            }
            src_fn.xrefs_from.append(xrow)
            if dst_fn:
                dst_fn.xrefs_to.append(xrow)
            if dst_fn and dst_fn.address != src_fn.address and ("CALL" in typ or "CODE" in typ or typ in {"C", "J"}):
                if dst_fn.address not in src_fn.callees:
                    src_fn.callees.append(dst_fn.address)
                if src_fn.address not in dst_fn.callers:
                    dst_fn.callers.append(src_fn.address)
            s = strings_by_addr.get(to)
            if s:
                if s.address not in src_fn.string_refs:
                    src_fn.string_refs.append(s.address)
                if src_fn.address not in s.refs_from:
                    s.refs_from.append(src_fn.address)
                tags = set(s.tags)
                src_fn.tags = sorted(set(src_fn.tags) | tags)
                src_fn.score += score_tags(tags, source="string") if tags else 0
            imp = imports_by_addr.get(to)
            if imp:
                if imp.name not in src_fn.imports:
                    src_fn.imports.append(imp.name)
                if src_fn.address not in imp.refs_from:
                    imp.refs_from.append(src_fn.address)
                tags = set(imp.tags)
                src_fn.tags = sorted(set(src_fn.tags) | tags)
                src_fn.score += score_tags(tags, source="import") if tags else 0

        for f in m.functions:
            f.callers.sort()
            f.callees.sort()
            f.string_refs.sort()
            f.arm64_profile.setdefault("xref_out", len(f.xrefs_from))
            f.arm64_profile.setdefault("xref_in", len(f.xrefs_to))

    def _attach_symbol_names(self, m: ModuleAnalysis) -> None:
        fn_by_addr = {f.address: f for f in m.functions}
        for s in m.symbols:
            fn = fn_by_addr.get(s.address)
            if not fn:
                continue
            if s.name and s.name not in fn.symbols:
                fn.symbols.append(s.name)
            tags = classify(s.name)
            if tags:
                fn.tags = sorted(set(fn.tags) | tags)
                fn.score += score_tags(tags, source="symbol")

    def enrich_function(self, module: ModuleAnalysis, fn: FunctionNode, *, timeout: float = 12) -> None:
        if not self.available:
            return
        commands = {
            "disasm": f"pdf @ {fn.address}",
            "pseudocode": f"pdc @ {fn.address}",
            "insns": f"pdj {max(8, min(512, (fn.size // 4) + 4))} @ {fn.address}",
            "blocks": f"afbj @ {fn.address}",
        }
        for kind, cmd in commands.items():
            rr = run([self.rizin, "-2", "-q", "-e", "scr.color=false", "-A", "-c", cmd, module.path],
                     timeout=self.budget.clamp(timeout))
            text = rr.stdout.strip()
            if kind == "disasm":
                fn.disasm = text[-24000:]
            elif kind == "pseudocode":
                fn.pseudocode = text[-24000:]
            elif kind == "blocks":
                rows = _json_from(text, [])
                if isinstance(rows, list):
                    edges = 0
                    for row in rows:
                        edges += int(bool(row.get("jump"))) + int(bool(row.get("fail")))
                    blocks = len(rows)
                    fn.arm64_profile.update({"basic_blocks": blocks, "cfg_edges": edges,
                                             "cyclomatic_approx": max(1, edges - blocks + 2) if blocks else 0})
            else:
                rows = _json_from(text, [])
                if isinstance(rows, list):
                    counts = {"direct_call":0,"indirect_call":0,"branch":0,"conditional_branch":0,"ret":0,"svc":0,
                              "pac_aut":0,"bti":0,"adrp":0,"load":0,"store":0,"compare":0}
                    for row in rows:
                        op = str(row.get("opcode") or row.get("disasm") or "").strip().lower()
                        mn = op.split(None, 1)[0] if op else ""
                        if mn == "bl": counts["direct_call"] += 1
                        elif mn == "blr": counts["indirect_call"] += 1
                        elif mn in {"b", "br"}: counts["branch"] += 1
                        elif mn.startswith("b.") or mn in {"cbz","cbnz","tbz","tbnz"}: counts["conditional_branch"] += 1
                        elif mn == "ret": counts["ret"] += 1
                        elif mn == "svc": counts["svc"] += 1
                        elif mn.startswith("pac") or mn.startswith("aut"): counts["pac_aut"] += 1
                        elif mn.startswith("bti"): counts["bti"] += 1
                        elif mn == "adrp": counts["adrp"] += 1
                        elif mn.startswith("ldr") or mn.startswith("ldp"): counts["load"] += 1
                        elif mn.startswith("str") or mn.startswith("stp"): counts["store"] += 1
                        elif mn in {"cmp","cmn","ccmp","tst"}: counts["compare"] += 1
                    fn.arm64_profile.update({"instruction_count": len(rows), **counts})
                    fn.arm64_profile["indirect_control_flow"] = counts["indirect_call"] + counts["branch"]
                    fn.arm64_profile["has_syscall"] = bool(counts["svc"])
                    fn.arm64_profile["has_pac_bti"] = bool(counts["pac_aut"] or counts["bti"])
