from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import platform
import re
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .cache import ModuleCache
from .correlate import Correlator
from .engines.android import AndroidEngine
from .engines.arm64 import Arm64Engine
from .engines.elf import LiefEngine
from .engines.ghidra import GhidraEngine
from .engines.java import JavaEngine
from .engines.live import FridaEngine
from .engines.rizin import RizinEngine
from .model import AnalysisCase, FunctionNode, ModuleAnalysis
from .reporting import write_case
from .runner import Budget, run, sha256_file, which_any
from .serde import load_case


def eprint(*a, **kw):
    print(*a, file=sys.stderr, **kw)


def now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s)[:100]


def default_case_root() -> Path:
    lab = Path(os.environ.get("ANDROID_CTF_LAB", str(Path.home() / "AndroidCTFMax")))
    return lab / "cases-remix"


def resolve_case_dir(args, target: str) -> Path:
    if getattr(args, "out", None):
        p = Path(args.out).expanduser().resolve()
    else:
        p = default_case_root() / f"{now_stamp()}_{safe_name(args.mode)}_{safe_name(target)}"
    p.mkdir(parents=True, exist_ok=True)
    return p


def choose_native_libs(paths: list[str], all_abis: bool) -> list[str]:
    if all_abis:
        return paths
    arm64 = [p for p in paths if "/arm64-v8a/" in p or "/arm64/" in p]
    return arm64 or paths


def parse_offset_hooks(specs: list[str] | None) -> list[dict]:
    out=[]
    for spec in specs or []:
        # MODULE@0xOFFSET[:label]
        if "@" not in spec:
            raise SystemExit(f"bad --offset hook {spec!r}; expected MODULE@0xOFFSET[:label]")
        module, rest=spec.split("@",1)
        label=""
        if ":" in rest:
            off_s,label=rest.split(":",1)
        else:
            off_s=rest
        off=int(off_s,0)
        out.append({"module":module,"offset":hex(off),"label":label or f"{module}+{off:#x}"})
    return out


def analyze_module(path: str, *, budget: Budget, deep: bool, cache: ModuleCache, no_cache: bool) -> ModuleAnalysis:
    digest = sha256_file(path)
    mode = "deep" if deep else "fast"
    if not no_cache:
        cached = cache.get(digest, mode, path)
        if cached:
            return cached
    rz = RizinEngine(budget=budget, deep=deep, timeout=100 if deep else 55)
    m = rz.analyze(path)
    LiefEngine().enrich(m)
    if not no_cache:
        cache.put(m, mode)
    return m


def cmd_doctor(args) -> int:
    budget = Budget(30)
    android = AndroidEngine(serial=args.serial, budget=budget)
    tools = ["adb", "rizin", "rabin2", "r2", "jadx", "apktool", "apksigner", "llvm-readelf", "nm", "objdump", "strings", "tcpdump", "mitmdump"]
    print(f"REMIX {__version__}")
    print(f"host={platform.platform()} python={sys.version.split()[0]}")
    for t in tools:
        print(f"{t:14} {which_any([t]) or '-'}")
    print(f"android        {json.dumps(android.doctor(), sort_keys=True)}")
    print(f"LIEF           {'yes' if LiefEngine().available else 'no (optional)'}")
    print(f"Capstone       {'yes' if Arm64Engine().available else 'no (optional)'}")
    gh = GhidraEngine(budget=budget, script_dir=Path(__file__).resolve().parent.parent / "ghidra_scripts")
    print(f"Ghidra         {gh.headless or '-'}")
    fr = FridaEngine(budget=budget)
    for p in fr.python_candidates():
        rr = run([str(p), "-c", "import frida; print(frida.__version__)"], timeout=5)
        print(f"Frida Python   {p} -> {(rr.stdout or rr.stderr).strip()}")
    return 0


def cmd_analyze(args) -> int:
    budget = Budget(args.budget if args.budget > 0 else None)
    android = AndroidEngine(serial=args.serial, budget=budget)
    if args.package:
        target = args.package
    elif args.apk:
        target = Path(args.apk).name
    else:
        target = Path(args.elf).name
    case_dir = resolve_case_dir(args, target)
    case = AnalysisCase(str(case_dir), target, args.mode, datetime.now(timezone.utc).isoformat())
    print(f"CASE={case_dir}")

    # Phase 1: deterministic acquisition.
    try:
        if args.package:
            if not android.available:
                raise RuntimeError("adb unavailable")
            case.artifact = android.acquire_package(args.package, case_dir)
        else:
            case.artifact = android.acquire_file(args.apk or args.elf, case_dir)
    except Exception as e:
        case.errors.append(f"acquisition: {e}")
        write_case(case)
        eprint(f"[FAIL] acquisition: {e}")
        return 2
    print(f"[OK] artifact apks={len(case.artifact.local_apks)} native={len(case.artifact.native_libs)} dex={len(case.artifact.dex_files)}")

    # Phase 2: fast Java/Dex semantic surface. Full source decompile is deferred.
    java = JavaEngine(budget=budget, timeout=min(args.java_timeout, max(20, int(budget.remaining or args.java_timeout))))
    try:
        case.java_findings.extend(java.fast_dex_strings(case.artifact.dex_files))
    except Exception as e:
        case.warnings.append(f"DEX string indexing: {e}")

    # Phase 3: all native bulk indexes. Each ELF is one Rizin analysis process.
    libs = choose_native_libs(case.artifact.native_libs, args.all_abis)
    cache = ModuleCache(version=__version__)
    workers = max(1, min(args.jobs, len(libs) or 1))
    deep_native = args.mode in {"full", "deep"}
    modules: list[ModuleAnalysis] = []
    if libs:
        print(f"[RUN] native-index libs={len(libs)} jobs={workers} deep={deep_native}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(analyze_module, p, budget=budget, deep=deep_native, cache=cache, no_cache=args.no_cache): p for p in libs}
            for fut in concurrent.futures.as_completed(futs):
                p = futs[fut]
                try:
                    m = fut.result()
                    modules.append(m)
                    cache_flag = " cache" if m.metadata.get("cache_hit") else ""
                    print(f"[OK] {m.name}: fn={len(m.functions)} str={len(m.strings)} imp={len(m.imports)}{cache_flag}")
                except Exception as e:
                    case.warnings.append(f"native {Path(p).name}: {e}")
                    eprint(f"[WARN] {Path(p).name}: {e}")
    case.modules = sorted(modules, key=lambda m: m.name)

    # Phase 4: Java source only when it can add real JNI/call-site context.
    if args.mode in {"full", "deep"} and case.artifact.local_apks and not args.no_jadx:
        try:
            source_root = java.decompile(case.artifact.local_apks, case_dir / "java", threads=max(1, args.jobs))
            if source_root:
                findings = java.index_sources(source_root)
                case.java_findings.extend(findings)
                print(f"[OK] JADX semantic findings={len(findings)}")
            else:
                case.warnings.append("JADX produced no Java sources")
        except TimeoutError:
            case.warnings.append("JADX skipped: total analysis budget exhausted")
        except Exception as e:
            case.warnings.append(f"JADX: {e}")

    # Phase 5: root-only live snapshot is non-instrumented evidence and gives ASLR bases.
    if args.package and args.live_root:
        try:
            case.dynamic_modules = android.root_snapshot(args.package, case_dir, launch=not args.no_launch)
            anomaly_file = case_dir / "live-root" / "memory_anomalies.json"
            if anomaly_file.exists() and case.artifact:
                try: case.artifact.metadata["runtime_memory_anomalies"] = json.loads(anomaly_file.read_text())
                except Exception: pass
            print(f"[OK] root-live modules={len(case.dynamic_modules)} anomalies={len(case.artifact.metadata.get('runtime_memory_anomalies', [])) if case.artifact else 0}")
        except Exception as e:
            case.warnings.append(f"root snapshot: {e}")

    # Phase 6: explicit instrumentation, never silently mixed with baseline evidence.
    # Correlate static evidence first so --trace-top hooks exact ranked offsets instead
    # of spraying generic hooks across every function.
    preliminary = Correlator(case)
    preliminary.run()
    if args.package and args.instrument:
        try:
            offset_hooks = parse_offset_hooks(args.offset_hook)
            if args.trace_top > 0:
                focus_tags=set(x for x in args.focus.split(",") if x) if args.focus else None
                for m, fn in preliminary.ranked_functions(tags=focus_tags, limit=args.trace_top):
                    offset_hooks.append({"module":m.name,"offset":hex(fn.offset),"label":f"rank:{fn.name}"})
            fr = FridaEngine(budget=budget)
            evfile = fr.capture(args.package, case_dir, duration=args.instrument_duration,
                                endpoint=args.frida_endpoint, spawn=args.spawn,
                                prefer=args.frida_prefer, patterns=args.hook if args.hook else None,
                                offset_hooks=offset_hooks)
            if evfile:
                case.dynamic_events = fr.read_events(evfile)
                print(f"[OK] instrument events={len(case.dynamic_events)}")
            else:
                case.warnings.append("Frida environment/route unavailable")
        except Exception as e:
            case.warnings.append(f"Frida instrumentation: {e}")

    # Correlation happens before expensive targeted decompilation.
    corr = Correlator(case)
    corr.run()

    # Phase 7: targeted Rizin pseudocode/disassembly only for high-value functions.
    topn = args.top_decompile
    if topn < 0:
        topn = {"fast": 0, "balanced": 6, "full": 16, "deep": 32}[args.mode]
    if topn:
        rows = corr.ranked_functions(tags=set(args.focus.split(",")) if args.focus else None, limit=topn)
        rz = RizinEngine(budget=budget, deep=True, timeout=25)
        for m, fn in rows:
            try:
                rz.enrich_function(m, fn, timeout=args.function_timeout)
            except TimeoutError:
                case.warnings.append("targeted decompilation stopped: budget exhausted")
                break
            except Exception as e:
                case.warnings.append(f"targeted decompile {m.name}+{fn.offset:#x}: {e}")
        print(f"[OK] targeted-dossiers requested={topn}")

    # Phase 8: optional Ghidra consensus, only on already-ranked offsets.
    if args.ghidra_top > 0:
        gh = GhidraEngine(budget=budget, script_dir=Path(__file__).resolve().parent.parent / "ghidra_scripts")
        if gh.available:
            bymod: dict[str, list[int]] = {}
            for m, fn in corr.ranked_functions(tags=set(args.focus.split(",")) if args.focus else None, limit=args.ghidra_top):
                bymod.setdefault(m.name, []).append(fn.offset)
            for m in case.modules:
                if m.name in bymod:
                    try:
                        gh.enrich(m, bymod[m.name], case_dir=case_dir, timeout=args.ghidra_timeout)
                    except TimeoutError:
                        case.warnings.append("Ghidra consensus stopped: budget exhausted")
                        break
                    except Exception as e:
                        case.warnings.append(f"Ghidra {m.name}: {e}")
        else:
            case.warnings.append("Ghidra headless requested but not found")

    Correlator(case).run()
    write_case(case)
    print(f"REPORT={case_dir / 'REPORT.md'}")
    print(f"DB={case_dir / 'case.sqlite'}")
    print(f"TOP={len(case.summary.get('top_functions', []))} functions-ranked")
    return 0


def _select_module(case: AnalysisCase, name: str | None) -> ModuleAnalysis:
    if name:
        exact = [m for m in case.modules if m.name == name]
        if exact:
            return exact[0]
        fuzzy = [m for m in case.modules if name.lower() in m.name.lower()]
        if len(fuzzy) == 1:
            return fuzzy[0]
        if not fuzzy:
            raise SystemExit(f"module not found: {name}")
        raise SystemExit("module ambiguous: " + ", ".join(m.name for m in fuzzy))
    if len(case.modules) == 1:
        return case.modules[0]
    raise SystemExit("--module is required; modules: " + ", ".join(m.name for m in case.modules))


def _find_fn(m: ModuleAnalysis, args) -> FunctionNode:
    if args.offset is not None:
        off = int(args.offset, 0)
        fn = m.function_by_offset(off)
        if fn: return fn
    if args.address is not None:
        a = int(args.address, 0)
        fn = m.function_by_addr(a)
        if fn: return fn
    if args.symbol:
        hits = [f for f in m.functions if args.symbol.lower() in f.name.lower() or any(args.symbol.lower() in s.lower() for s in f.symbols)]
        if len(hits) == 1: return hits[0]
        if hits: return sorted(hits, key=lambda f: -f.score)[0]
    raise SystemExit("function not found")


def function_dossier(m: ModuleAnalysis, fn: FunctionNode) -> dict:
    by_addr = {f.address: f for f in m.functions}
    str_by = {s.address: s for s in m.strings}
    return {
        **fn.to_dict(),
        "callers_detail": [{"address": a, "address_hex": hex(a), "name": by_addr[a].name if a in by_addr else ""} for a in fn.callers],
        "callees_detail": [{"address": a, "address_hex": hex(a), "name": by_addr[a].name if a in by_addr else ""} for a in fn.callees],
        "strings_detail": [{"address": a, "address_hex": hex(a), "value": str_by[a].value, "tags": str_by[a].tags} for a in fn.string_refs if a in str_by],
    }


def cmd_fn(args) -> int:
    case = load_case(args.case)
    m = _select_module(case, args.module)
    fn = _find_fn(m, args)
    d = function_dossier(m, fn)
    if args.json:
        print(json.dumps(d, indent=2, sort_keys=True))
        return 0
    print(f"{m.name}+{fn.offset:#x}  {fn.name}")
    print(f"address={fn.address:#x} size={fn.size} score={fn.score:.2f} tags={','.join(fn.tags) or '-'}")
    print("symbols=" + (", ".join(fn.symbols) or "-"))
    print("JNI=" + (", ".join(fn.jni_methods) or "-"))
    print("imports=" + (", ".join(fn.imports) or "-"))
    print("CALLERS")
    for x in d["callers_detail"][:80]: print(f"  {x['address_hex']:>14} {x['name']}")
    print("CALLEES")
    for x in d["callees_detail"][:80]: print(f"  {x['address_hex']:>14} {x['name']}")
    print("STRINGS")
    for x in d["strings_detail"][:120]: print(f"  {x['address_hex']:>14} [{','.join(x['tags'])}] {x['value'][:300]}")
    if fn.dynamic_hits:
        print("DYNAMIC")
        for x in fn.dynamic_hits[:40]: print("  " + json.dumps(x, sort_keys=True)[:1000])
    if fn.pseudocode:
        print("PSEUDOCODE\n" + fn.pseudocode)
    elif fn.disasm:
        print("DISASM\n" + fn.disasm)
    return 0


def cmd_query(args) -> int:
    case = load_case(args.case)
    tags = set(args.tag or [])
    needle = (args.contains or "").lower()
    rows = []
    for m in case.modules:
        str_by = {s.address: s for s in m.strings}
        for f in m.functions:
            if tags:
                have = set(f.tags)
                if args.all_tags and not tags.issubset(have):
                    continue
                if not args.all_tags and not (tags & have):
                    continue
            if f.score < args.min_score:
                continue
            hay = " ".join([f.name, *f.symbols, *f.imports, *(str_by[a].value for a in f.string_refs if a in str_by)]).lower()
            if needle and needle not in hay:
                continue
            rows.append((f.score, m.name, f))
    rows.sort(key=lambda x: -x[0])
    for score, mod, f in rows[:args.limit]:
        print(f"{score:7.2f} {mod}+{f.offset:#x} {f.name} [{','.join(f.tags)}]")
    return 0


def cmd_graph(args) -> int:
    case = load_case(args.case)
    m = _select_module(case, args.module)
    fn = _find_fn(m, args)
    by = {f.address: f for f in m.functions}
    seen = {fn.address}; frontier = [(fn.address, 0)]
    while frontier:
        addr, depth = frontier.pop(0)
        cur = by.get(addr)
        if not cur: continue
        indent = "  " * depth
        print(f"{indent}{m.name}+{cur.offset:#x} {cur.name} [{','.join(cur.tags)}]")
        if depth >= args.depth: continue
        nxt = cur.callers if args.direction == "up" else cur.callees if args.direction == "down" else cur.callers + cur.callees
        for a in nxt:
            if a not in seen:
                seen.add(a); frontier.append((a, depth + 1))
    return 0


def cmd_module(args) -> int:
    case = load_case(args.case)
    m = _select_module(case, args.module)
    payload = {
        "name": m.name, "path": m.path, "sha256": m.sha256, "arch": m.arch, "bits": m.bits,
        "image_base": m.image_base, "image_base_hex": hex(m.image_base), "entry": m.entry,
        "functions": len(m.functions), "strings": len(m.strings), "imports": len(m.imports),
        "symbols": len(m.symbols), "jni": len(m.jni), "metadata": m.metadata, "errors": m.errors,
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True)); return 0
    print(f"{m.name} sha256={m.sha256} arch={m.arch}/{m.bits} base={m.image_base:#x} entry={m.entry:#x}")
    print(f"functions={len(m.functions)} strings={len(m.strings)} imports={len(m.imports)} symbols={len(m.symbols)} jni={len(m.jni)}")
    sec = m.metadata.get("security") or {}
    print(f"PIE={sec.get('pie')} RELRO={sec.get('relro_segment')} NX_STACK={sec.get('nx_stack')} RWX={sec.get('rwx_segment_count')}")
    print("DT_NEEDED=" + ",".join(m.metadata.get("libraries") or []))
    for key in ("constructors","destructors","pltgot_relocations","cxx_type_topology","native_anchors"):
        rows=m.metadata.get(key) or []
        print(f"{key}={len(rows)}")
        for row in rows[:args.limit]: print("  " + json.dumps(row, sort_keys=True))
    return 0


def cmd_refs(args) -> int:
    case = load_case(args.case); m = _select_module(case, args.module); fn = _find_fn(m, args)
    rows=[]
    if args.direction in {"out","both"}:
        rows += [("OUT", x) for x in fn.xrefs_from]
    if args.direction in {"in","both"}:
        rows += [("IN", x) for x in fn.xrefs_to]
    needle=(args.contains or "").lower()
    typ=(args.type or "").upper()
    shown=0
    for direction, x in rows:
        if typ and typ not in str(x.get("type", "")).upper(): continue
        hay=" ".join(str(x.get(k, "")) for k in ("type","to_hex","to_function_name","to_symbol","to_import","to_string")).lower()
        if needle and needle not in hay: continue
        print(f"{direction:3} {x.get('from_hex','')} -> {x.get('to_hex','')} type={x.get('type','')} fn={x.get('to_function_name','')} sym={x.get('to_symbol','')} imp={x.get('to_import','')} str={x.get('to_string','')[:160]}")
        shown += 1
        if shown >= args.limit: break
    print(f"shown={shown} total_in={len(fn.xrefs_to)} total_out={len(fn.xrefs_from)}")
    return 0


def cmd_symbols(args) -> int:
    case=load_case(args.case); modules=[_select_module(case,args.module)] if args.module else case.modules
    rows=[]; needle=(args.contains or "").lower(); tags=set(args.tag or [])
    for m in modules:
        for sy in m.symbols:
            if needle and needle not in (sy.name+" "+sy.demangled).lower(): continue
            if args.imported and not sy.imported: continue
            if args.exported and not sy.exported: continue
            if args.type and args.type.lower() not in sy.type.lower(): continue
            if tags and not (tags & set(sy.tags)): continue
            rows.append((m,sy))
    rows.sort(key=lambda ms:(ms[0].name, ms[1].address, ms[1].name))
    for m,sy in rows[:args.limit]:
        print(f"{m.name} {sy.address:#x} size={sy.size:<6} {sy.bind}/{sy.type}/{sy.visibility} {'I' if sy.imported else '-'}{'E' if sy.exported else '-'} {sy.name} {sy.demangled} [{','.join(sy.tags)}]")
    print(f"matches={len(rows)}")
    return 0


def cmd_strings(args) -> int:
    case=load_case(args.case); modules=[_select_module(case,args.module)] if args.module else case.modules
    needle=(args.contains or "").lower(); tags=set(args.tag or []); rows=[]
    for m in modules:
        by={f.address:f for f in m.functions}
        for st in m.strings:
            if needle and needle not in st.value.lower(): continue
            if tags and not (tags & set(st.tags)): continue
            rows.append((m,st,by))
    rows.sort(key=lambda x:(x[0].name,x[1].address))
    for m,st,by in rows[:args.limit]:
        refs=""
        if args.with_refs:
            refs=" refs="+",".join(f"{by[a].offset:#x}:{by[a].name}" if a in by else hex(a) for a in st.refs_from[:20])
        print(f"{m.name} {st.address:#x} [{','.join(st.tags)}] {st.value[:500]}{refs}")
    print(f"matches={len(rows)}")
    return 0


def cmd_jni(args) -> int:
    case=load_case(args.case); modules=[_select_module(case,args.module)] if args.module else case.modules
    needle=(args.contains or "").lower(); rows=[]
    for m in modules:
        for j in m.jni:
            hay=f"{j.java_class} {j.java_method} {j.signature} {j.native_symbol} {j.source}".lower()
            if needle and needle not in hay: continue
            rows.append((m,j))
    rows.sort(key=lambda mj:(mj[0].name,mj[1].native_offset if mj[1].native_offset is not None else -1,mj[1].java_method))
    for m,j in rows[:args.limit]:
        off="?" if j.native_offset is None else hex(j.native_offset)
        addr="?" if j.native_address is None else hex(j.native_address)
        print(f"{m.name}+{off} addr={addr} {j.java_fqmn} symbol={j.native_symbol} source={j.source} confidence={j.confidence:.2f}")
    print(f"matches={len(rows)}")
    return 0


def _find_by_spec(m: ModuleAnalysis, spec: str) -> FunctionNode:
    if spec.startswith("0x") or spec.isdigit():
        n=int(spec,0); fn=m.function_by_offset(n) or m.function_by_addr(n)
        if fn: return fn
    hits=[f for f in m.functions if spec.lower() in f.name.lower() or any(spec.lower() in x.lower() for x in f.symbols)]
    if not hits: raise SystemExit(f"function not found: {spec}")
    return sorted(hits,key=lambda f:-f.score)[0]


def cmd_path(args) -> int:
    case=load_case(args.case); m=_select_module(case,args.module)
    src=_find_by_spec(m,args.from_fn); dst=_find_by_spec(m,args.to_fn)
    by={f.address:f for f in m.functions}; queue=[src.address]; prev={src.address:None}
    while queue:
        cur=queue.pop(0)
        if cur==dst.address: break
        fn=by.get(cur)
        if not fn: continue
        for nxt in fn.callees:
            if nxt in by and nxt not in prev:
                prev[nxt]=cur; queue.append(nxt)
                if len(prev) > args.max_nodes: break
    if dst.address not in prev:
        print("NO_CALL_PATH"); return 1
    chain=[]; cur=dst.address
    while cur is not None:
        chain.append(cur); cur=prev[cur]
    chain.reverse()
    for i,a in enumerate(chain):
        f=by[a]; print(f"{i:02d} {m.name}+{f.offset:#x} {f.name} [{','.join(f.tags)}]")
    print(f"hops={len(chain)-1}")
    return 0


def cmd_trace(args) -> int:
    if args.case:
        case = load_case(args.case)
        if not case.artifact or not case.artifact.package:
            raise SystemExit("case has no Android package; use --package")
        package = case.artifact.package
        case_dir = Path(case.case_dir)
    else:
        package = args.package
        if not package:
            raise SystemExit("--case or --package required")
        # A trace without an existing case gets a fast static case first so runtime
        # addresses can be normalized instead of emitted as orphan pointers.
        ns = argparse.Namespace(**vars(args))
        ns.mode = "fast"; ns.out = args.out; ns.apk = None; ns.elf = None
        ns.live_root = True; ns.instrument = False; ns.no_jadx = True; ns.no_cache = False
        ns.all_abis = False; ns.jobs = args.jobs; ns.java_timeout = 30; ns.top_decompile = 0
        ns.focus = ""; ns.ghidra_top = 0; ns.ghidra_timeout = 60; ns.function_timeout = 8
        ns.budget = max(args.duration + 90, args.budget); ns.serial = args.serial; ns.package = package; ns.no_launch = False
        rc = cmd_analyze(ns)
        if rc: return rc
        # Find newest matching case when --out omitted.
        case_dir = Path(args.out) if args.out else sorted(default_case_root().glob(f"*_fast_{safe_name(package)}"))[-1]
        case = load_case(case_dir)

    budget = Budget(args.budget if args.budget > 0 else args.duration + 45)
    android = AndroidEngine(serial=args.serial, budget=budget)
    try:
        case.dynamic_modules = android.root_snapshot(package, case.case_dir, launch=not args.no_launch)
    except Exception as e:
        case.warnings.append(f"pre-trace root snapshot: {e}")
    fr = FridaEngine(budget=budget)
    evfile = fr.capture(package, case.case_dir, duration=args.duration, endpoint=args.frida_endpoint,
                        spawn=args.spawn, prefer=args.frida_prefer, patterns=args.hook or None,
                        offset_hooks=parse_offset_hooks(args.offset_hook))
    if not evfile:
        raise SystemExit("no usable Frida Python environment/route")
    case.dynamic_events = fr.read_events(evfile)
    Correlator(case).run(); write_case(case)
    print(f"EVENTS={len(case.dynamic_events)}")
    print(f"REPORT={Path(case.case_dir) / 'REPORT.md'}")
    return 0


def cmd_diff(args) -> int:
    a = load_case(args.left); b = load_case(args.right)
    amap = {(m.name, f.offset): f for m in a.modules for f in m.functions}
    bmap = {(m.name, f.offset): f for m in b.modules for f in m.functions}
    keys = sorted(set(amap) | set(bmap))
    changes = []
    for k in keys:
        fa, fb = amap.get(k), bmap.get(k)
        if fa is None:
            changes.append(("ADD", k, None, fb))
        elif fb is None:
            changes.append(("DEL", k, fa, None))
        elif fa.name != fb.name or fa.size != fb.size or set(fa.tags) != set(fb.tags) or set(fa.imports) != set(fb.imports):
            changes.append(("CHG", k, fa, fb))
    for kind, (mod, off), fa, fb in changes[:args.limit]:
        print(f"{kind:3} {mod}+{off:#x} {fa.name if fa else '-'} -> {fb.name if fb else '-'}")
        if kind == "CHG" and args.verbose:
            print(f"    size {fa.size}->{fb.size} tags {fa.tags}->{fb.tags}")
            print(f"    imports {fa.imports}->{fb.imports}")
    print(f"changes={len(changes)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="remix", description="Correlated Android/ARM64 reverse-engineering engine")
    p.add_argument("--version", action="version", version=f"REMIX {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor", help="verify host/device analysis engines")
    d.add_argument("--serial", default=os.environ.get("ADB_SERIAL", "emulator-5554")); d.set_defaults(func=cmd_doctor)

    a = sub.add_parser("analyze", help="build a correlated function/xref/JNI/PLT/ARM64 evidence case")
    tgt = a.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--package"); tgt.add_argument("--apk"); tgt.add_argument("--elf")
    a.add_argument("--serial", default=os.environ.get("ADB_SERIAL", "emulator-5554"))
    a.add_argument("--mode", choices=["fast", "balanced", "full", "deep"], default="balanced")
    a.add_argument("--out"); a.add_argument("--budget", type=int, default=240, help="hard total wall-clock budget; 0=unbounded")
    a.add_argument("--jobs", type=int, default=min(4, os.cpu_count() or 2)); a.add_argument("--all-abis", action="store_true")
    a.add_argument("--no-cache", action="store_true"); a.add_argument("--no-jadx", action="store_true")
    a.add_argument("--java-timeout", type=int, default=120); a.add_argument("--function-timeout", type=int, default=10)
    a.add_argument("--top-decompile", type=int, default=-1, help="-1=mode default; 0=none")
    a.add_argument("--focus", default="", help="comma-separated semantic tags: auth,tls,jni,crypto,integrity,...")
    a.add_argument("--live-root", action=argparse.BooleanOptionalAction, default=True)
    a.add_argument("--no-launch", action="store_true")
    a.add_argument("--instrument", action="store_true", help="explicitly add Frida runtime evidence after root baseline")
    a.add_argument("--instrument-duration", type=int, default=18); a.add_argument("--frida-endpoint")
    a.add_argument("--frida-prefer", choices=["stock", "phantom", "florida"], default="stock"); a.add_argument("--spawn", action="store_true")
    a.add_argument("--hook", action="append", help="runtime import/export symbol to observe; repeatable")
    a.add_argument("--offset-hook", action="append", help="exact runtime hook MODULE@0xOFFSET[:label]; repeatable")
    a.add_argument("--trace-top", type=int, default=0, help="when --instrument is set, hook top N statically-ranked native functions")
    a.add_argument("--ghidra-top", type=int, default=0, help="second-opinion headless decompile for top N ranked functions")
    a.add_argument("--ghidra-timeout", type=int, default=150)
    a.set_defaults(func=cmd_analyze)

    f = sub.add_parser("fn", help="print one correlated function dossier")
    f.add_argument("--case", required=True); f.add_argument("--module")
    g = f.add_mutually_exclusive_group(required=True); g.add_argument("--offset"); g.add_argument("--address"); g.add_argument("--symbol")
    f.add_argument("--json", action="store_true"); f.set_defaults(func=cmd_fn)

    q = sub.add_parser("query", help="rank functions by semantic tags/keywords")
    q.add_argument("--case", required=True); q.add_argument("--tag", action="append"); q.add_argument("--all-tags", action="store_true")
    q.add_argument("--contains"); q.add_argument("--min-score", type=float, default=0); q.add_argument("--limit", type=int, default=100); q.set_defaults(func=cmd_query)

    g = sub.add_parser("graph", help="walk callers/callees around a function")
    g.add_argument("--case", required=True); g.add_argument("--module")
    s = g.add_mutually_exclusive_group(required=True); s.add_argument("--offset"); s.add_argument("--address"); s.add_argument("--symbol")
    g.add_argument("--depth", type=int, default=2); g.add_argument("--direction", choices=["up", "down", "both"], default="both"); g.set_defaults(func=cmd_graph)

    mo = sub.add_parser("module", help="show loader/security/constructor/PLT/RTTI topology for one ELF")
    mo.add_argument("--case", required=True); mo.add_argument("--module"); mo.add_argument("--limit", type=int, default=30); mo.add_argument("--json", action="store_true"); mo.set_defaults(func=cmd_module)

    rf = sub.add_parser("refs", help="show incoming/outgoing code/data/string/import xrefs for one function")
    rf.add_argument("--case", required=True); rf.add_argument("--module")
    rfg=rf.add_mutually_exclusive_group(required=True); rfg.add_argument("--offset"); rfg.add_argument("--address"); rfg.add_argument("--symbol")
    rf.add_argument("--direction", choices=["in","out","both"], default="both"); rf.add_argument("--type"); rf.add_argument("--contains"); rf.add_argument("--limit", type=int, default=200); rf.set_defaults(func=cmd_refs)

    sy = sub.add_parser("symbols", help="query native symbols/demangled names/types/visibility")
    sy.add_argument("--case", required=True); sy.add_argument("--module"); sy.add_argument("--contains"); sy.add_argument("--tag", action="append")
    sy.add_argument("--imported", action="store_true"); sy.add_argument("--exported", action="store_true"); sy.add_argument("--type"); sy.add_argument("--limit", type=int, default=300); sy.set_defaults(func=cmd_symbols)

    st = sub.add_parser("strings", help="query native strings and their referring functions")
    st.add_argument("--case", required=True); st.add_argument("--module"); st.add_argument("--contains"); st.add_argument("--tag", action="append"); st.add_argument("--with-refs", action="store_true"); st.add_argument("--limit", type=int, default=300); st.set_defaults(func=cmd_strings)

    jn = sub.add_parser("jni", help="query static and dynamic Java↔native mappings")
    jn.add_argument("--case", required=True); jn.add_argument("--module"); jn.add_argument("--contains"); jn.add_argument("--limit", type=int, default=300); jn.set_defaults(func=cmd_jni)

    pa = sub.add_parser("path", help="find shortest static call path between two native functions")
    pa.add_argument("--case", required=True); pa.add_argument("--module"); pa.add_argument("--from", dest="from_fn", required=True); pa.add_argument("--to", dest="to_fn", required=True); pa.add_argument("--max-nodes", type=int, default=100000); pa.set_defaults(func=cmd_path)

    t = sub.add_parser("trace", help="correlate runtime RegisterNatives/import calls back to static functions")
    t.add_argument("--case"); t.add_argument("--package"); t.add_argument("--serial", default=os.environ.get("ADB_SERIAL", "emulator-5554"))
    t.add_argument("--out"); t.add_argument("--duration", type=int, default=18); t.add_argument("--budget", type=int, default=120); t.add_argument("--jobs", type=int, default=3)
    t.add_argument("--frida-endpoint"); t.add_argument("--frida-prefer", choices=["stock", "phantom", "florida"], default="stock")
    t.add_argument("--spawn", action="store_true"); t.add_argument("--no-launch", action="store_true"); t.add_argument("--hook", action="append")
    t.add_argument("--offset-hook", action="append", help="MODULE@0xOFFSET[:label]; repeatable"); t.set_defaults(func=cmd_trace)

    df = sub.add_parser("diff", help="function-level semantic diff between two REMIX cases")
    df.add_argument("--left", required=True); df.add_argument("--right", required=True); df.add_argument("--limit", type=int, default=300); df.add_argument("--verbose", action="store_true"); df.set_defaults(func=cmd_diff)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        eprint("interrupted")
        return 130
    except TimeoutError as e:
        eprint(f"budget exhausted: {e}")
        return 124


if __name__ == "__main__":
    raise SystemExit(main())
