from __future__ import annotations

from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from .categories import classify, score_tags
from .model import AnalysisCase, Evidence, FunctionNode, JNIMapping, ModuleAnalysis


def parse_addr(v: Any) -> int | None:
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v, 0)
        except ValueError:
            return None
    return None


def decode_jni_symbol(name: str) -> tuple[str, str] | None:
    if not name.startswith("Java_"):
        return None
    raw = name[5:]
    if "__" in raw:
        raw, _sig = raw.split("__", 1)
    parts = raw.split("_")
    if len(parts) < 2:
        return None
    # JNI escaping (_1, _2, _3) makes exact decoding nontrivial. Preserve a useful
    # approximation and keep the raw symbol in evidence.
    method = parts[-1].replace("_1", "_")
    cls = ".".join(parts[:-1]).replace("_1", "_")
    return cls, method


class Correlator:
    def __init__(self, case: AnalysisCase):
        self.case = case
        self.modules = {m.name: m for m in case.modules}
        self.dynamic = {m.name: m for m in case.dynamic_modules}

    def run(self) -> None:
        self._static_jni_exports()
        self._dynamic_events()
        self._propagate_context()
        self._build_topology()
        self._summary()

    def _static_jni_exports(self) -> None:
        native_decls = defaultdict(list)
        for row in self.case.java_findings:
            if row.get("kind") == "java-native-declaration":
                native_decls[row.get("method", "")].append(row)
        for m in self.case.modules:
            for sym in m.symbols:
                dec = decode_jni_symbol(sym.name)
                if not dec:
                    continue
                cls, method = dec
                j = JNIMapping(cls, method, "", m.name, native_address=sym.address,
                               native_offset=(sym.address - m.image_base if m.image_base else sym.address),
                               native_symbol=sym.name, source="exported-jni", confidence=0.9)
                m.jni.append(j)
                fn = m.function_by_addr(sym.address)
                if fn:
                    if j.java_fqmn not in fn.jni_methods:
                        fn.jni_methods.append(j.java_fqmn)
                    fn.tags = sorted(set(fn.tags) | {"jni"})
                    fn.score += score_tags({"jni"}, source="jni")
                    fn.evidence.append(Evidence("symbol", "jni-export", sym.name, 0.9))
                for decl in native_decls.get(method, []):
                    if fn:
                        fn.evidence.append(Evidence("jadx", "java-native-declaration", decl, 0.6,
                                                    "name-level match; class mangling may be obfuscated"))

    def _module_for_runtime(self, addr: int):
        for dm in self.case.dynamic_modules:
            if dm.base <= addr < dm.end:
                return dm
        return None

    def _static_function_from_runtime(self, module_name: str, runtime_addr: int) -> tuple[ModuleAnalysis, FunctionNode] | None:
        dm = self.dynamic.get(module_name)
        sm = self.modules.get(module_name)
        if not dm or not sm:
            return None
        off = runtime_addr - dm.base
        static_addr = (sm.image_base + off) if sm.image_base else off
        fn = sm.function_by_addr(static_addr)
        return (sm, fn) if fn else None

    def _dynamic_events(self) -> None:
        for ev in self.case.dynamic_events:
            kind = ev.get("event")
            if kind == "module":
                continue
            if kind == "register-natives":
                for meth in ev.get("methods") or []:
                    fnptr = parse_addr(meth.get("function"))
                    base = parse_addr(meth.get("module_base"))
                    modname = meth.get("module") or ""
                    if fnptr is None:
                        continue
                    sm = self.modules.get(modname)
                    off = (fnptr - base) if base is not None else None
                    static_addr = ((sm.image_base + off) if sm and off is not None and sm.image_base else off)
                    fn = sm.function_by_addr(static_addr) if sm and static_addr is not None else None
                    j = JNIMapping("<RegisterNatives>", meth.get("name", ""), meth.get("signature", ""),
                                   modname, native_address=static_addr, native_offset=off,
                                   source="frida-register-natives", confidence=1.0)
                    if sm:
                        sm.jni.append(j)
                    if fn:
                        fn.jni_methods.append(j.java_fqmn)
                        fn.tags = sorted(set(fn.tags) | {"jni"})
                        fn.score += score_tags({"jni"}, source="dynamic")
                        fn.dynamic_hits.append(ev)
                        fn.evidence.append(Evidence("frida", "RegisterNatives", meth, 1.0))
                continue

            ra = parse_addr(ev.get("return_address"))
            if ra is None:
                continue
            dm = self._module_for_runtime(ra)
            if not dm:
                continue
            mapped = self._static_function_from_runtime(dm.name, ra)
            if not mapped:
                continue
            sm, fn = mapped
            text = " ".join(str(ev.get(k, "")) for k in ("symbol", "path", "api", "event"))
            tags = classify(text)
            fn.tags = sorted(set(fn.tags) | tags)
            fn.score += score_tags(tags or {"dynamic"}, source="dynamic")
            fn.dynamic_hits.append(ev)
            fn.evidence.append(Evidence("frida", kind or "dynamic", ev, 1.0))

    def _propagate_context(self) -> None:
        """One-hop conservative tag propagation across real callgraph edges."""
        for m in self.case.modules:
            by_addr = {f.address: f for f in m.functions}
            increments: dict[int, tuple[set[str], float]] = {}
            for fn in m.functions:
                if not fn.tags:
                    continue
                for target in fn.callees:
                    dst = by_addr.get(target)
                    if not dst:
                        continue
                    # Propagate only stronger semantic tags, and score weakly.
                    tags = set(fn.tags) & {"auth", "tls", "crypto", "integrity", "jni", "loader", "antidebug", "ipc", "network"}
                    if tags:
                        old_tags, old_score = increments.get(dst.address, (set(), 0.0))
                        increments[dst.address] = (old_tags | tags, old_score + 0.35 * len(tags))
            for addr, (tags, sc) in increments.items():
                fn = by_addr[addr]
                fn.tags = sorted(set(fn.tags) | tags)
                fn.score += sc

    def _build_topology(self) -> None:
        edges: list[dict] = []
        # Java source call edges are conservative: only emit a call when a method
        # name resolves uniquely in the decompiled source set.
        methods = [x for x in self.case.java_findings if x.get("kind") == "java-method"]
        by_name = defaultdict(list)
        for row in methods:
            by_name[row.get("method", "")].append(row)
        for row in methods:
            src = f"{row.get('class')}->{row.get('method')}"
            for called in row.get("calls") or []:
                hits = by_name.get(called, [])
                if len(hits) == 1:
                    dst = f"{hits[0].get('class')}->{hits[0].get('method')}"
                    edges.append({"kind":"java-call-approx","module":"<java>","from":src,"to":dst,"confidence":0.65})
        for m in self.case.modules:
            by_addr = {f.address: f for f in m.functions}
            for f in m.functions:
                for dst in f.callees:
                    d = by_addr.get(dst)
                    edges.append({
                        "kind": "call", "module": m.name,
                        "from": f.address, "from_hex": hex(f.address), "from_name": f.name,
                        "to": dst, "to_hex": hex(dst), "to_name": d.name if d else "",
                    })
                for imp in f.imports:
                    edges.append({"kind": "import-call", "module": m.name, "from": f.address,
                                  "from_hex": hex(f.address), "from_name": f.name, "to_name": imp})
                for j in f.jni_methods:
                    edges.append({"kind": "jni", "module": m.name, "from": j,
                                  "to": f.address, "to_hex": hex(f.address), "to_name": f.name})
        self.case.topology = edges

    def _summary(self) -> None:
        ranked = []
        tag_counts = defaultdict(int)
        for m in self.case.modules:
            for f in m.functions:
                for t in f.tags:
                    tag_counts[t] += 1
                if f.score > 0:
                    ranked.append((f.score, m.name, f.offset, f.name, list(f.tags)))
        ranked.sort(reverse=True)
        self.case.summary = {
            "modules": len(self.case.modules),
            "functions": sum(len(m.functions) for m in self.case.modules),
            "strings": sum(len(m.strings) for m in self.case.modules),
            "imports": sum(len(m.imports) for m in self.case.modules),
            "symbols": sum(len(m.symbols) for m in self.case.modules),
            "jni_mappings": sum(len(m.jni) for m in self.case.modules),
            "dynamic_events": len(self.case.dynamic_events),
            "tag_counts": dict(sorted(tag_counts.items())),
            "top_functions": [
                {"score": round(sc, 2), "module": mod, "offset": off, "offset_hex": hex(off), "name": name, "tags": tags}
                for sc, mod, off, name, tags in ranked[:100]
            ],
        }

    def ranked_functions(self, *, tags: set[str] | None = None, limit: int = 50) -> list[tuple[ModuleAnalysis, FunctionNode]]:
        rows = []
        for m in self.case.modules:
            for f in m.functions:
                if tags and not (set(f.tags) & tags):
                    continue
                rows.append((m, f))
        rows.sort(key=lambda mf: (-mf[1].score, mf[0].name, mf[1].address))
        return rows[:limit]
