from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from . import __version__
from . import cli as legacy
from .deep import consensus, validate_refs
from .decompile import decompile as run_decompile
from .kotlinmeta import recover as recover_kotlin, write_mapping
from .fingerprint import fingerprint
from .flow import FlowEngine, load_plan, recipe_plan
from .recipes import RECIPES
from .registry import discover_engines
from .reporting import write_case
from .selector import expand, select
from .serde import load_case
from .signatures import FunctionSignature, make_signature, match_signature

NEW_COMMANDS={"engines","fingerprint","decompile","kotlin-names","select","slice","validate","sig","match","flow","recipe","auto"}


def _json(obj):
    def conv(x): return x.to_dict() if hasattr(x,"to_dict") else x
    print(json.dumps(obj,indent=2,sort_keys=True,default=conv))



def cmd_decompile(a):
    result=run_decompile(a.input,a.out,engine=a.engine,timeout=a.timeout,threads=a.threads,deobf=not a.no_deobf)
    if a.json: return _json(result) or 0
    for r in result["runs"]:
        print(f"{r.get('engine','?'):12} status={r.get('status','ran')} rc={r.get('rc','-')} elapsed={r.get('elapsed',0):.2f}s {r.get('reason','')}")
    print("OUT="+result["out"]); print("COMPARISON="+json.dumps(result["comparison"],sort_keys=True))
    return 0


def cmd_kotlin_names(a):
    result=recover_kotlin(a.sources)
    write_mapping(result,a.out)
    if a.json:return _json(result) or 0
    print(f"RECOVERED={result['count']}")
    print(f"OUT={a.out}")
    for obf,real in list(sorted(result['mapping'].items()))[:a.limit]: print(f"{obf} -> {real}")
    return 0

def _split_stepspec(text):
    parts=[];buf=[];quote=None;depth=0
    for ch in text:
        if quote:
            buf.append(ch)
            if ch==quote:quote=None
            continue
        if ch in "\"'":quote=ch;buf.append(ch);continue
        if ch in "[({":depth+=1
        elif ch in "]) }".replace(" ",""):depth=max(0,depth-1)
        if ch==';' and depth==0:
            parts.append(''.join(buf));buf=[]
        else:buf.append(ch)
    if buf:parts.append(''.join(buf))
    return [x.strip() for x in parts if x.strip()]

def _coerce_step(v):
    v=v.strip()
    if v.lower() in {'true','false'}:return v.lower()=='true'
    if v.startswith(('[','{','"')):
        try:return json.loads(v)
        except Exception:pass
    try:return int(v,0)
    except Exception:
        try:return float(v)
        except Exception:pass
    if ',' in v:return [x.strip() for x in v.split(',') if x.strip()]
    if len(v)>=2 and v[0]==v[-1] and v[0] in "\"'":return v[1:-1]
    return v

def parse_inline_step(text):
    text=text.strip()
    if text.startswith('{'):return json.loads(text)
    d={}
    for part in _split_stepspec(text):
        if '=' not in part:raise ValueError(f"step field must be key=value: {part}")
        k,v=part.split('=',1);d[k.strip()]=_coerce_step(v)
    if 'op' not in d:raise ValueError('inline step requires op=...')
    return d

def _auto_plan(case,top=48,deep=False):
    em={x.spec.name:x for x in discover_engines(with_versions=False)}
    validators=['rizin','lief']
    for name in ('radare2','ghidra'):
        if em.get(name) and em[name].available:validators.append(name)
    if deep and em.get('angr') and em['angr'].available:validators.append('angr')
    steps=[
      {'id':'hot','op':'select','where':'score>=4 OR tag:jni OR tag:loader OR tag:integrity OR tag:antidebug OR tag:crypto OR tag:tls','limit':top},
      {'id':'slice','op':'expand','from':'hot','direction':'both','depth':1,'limit':top*3},
      {'id':'rizin-enrich','op':'enrich','engine':'rizin','from':'slice','limit':min(top,40),'continue_on_error':True},
    ]
    if em.get('ghidra') and em['ghidra'].available:
        steps.append({'id':'ghidra-enrich','op':'enrich','engine':'ghidra','from':'hot','limit':min(top,12),'timeout':150,'continue_on_error':True})
    for scanner in ('capa','floss'):
        if em.get(scanner) and em[scanner].available:
            steps.append({'id':f'{scanner}-scan','op':'scan','engine':scanner,'from':'hot','timeout':120,'continue_on_error':True})
    steps += [
      {'id':'validate','op':'validate','engines':validators,'from':'hot','limit':min(top,24),'timeout':90,'continue_on_error':True},
      {'id':'consensus','op':'consensus','from':'validate','policy':'weighted'},
      {'id':'emit-functions','op':'emit','from':'hot','format':'json'},
      {'id':'emit-consensus','op':'emit','from':'consensus','format':'json'},
    ]
    return {'name':'auto-v3','steps':steps}

def cmd_auto(a):
    c=_ensure_case(a)
    if c is None:return 2
    plan=_auto_plan(c,top=a.top,deep=a.deep_validators)
    if a.print_plan:print(json.dumps(plan,indent=2,sort_keys=True))
    engine=FlowEngine(c,out_dir=a.flow_out,budget=a.budget,jobs=a.jobs)
    result=engine.run(plan)
    print(f"CASE={result.case_dir}");print(f"FLOW={Path(result.output_dir)/'flow.json'}")
    for r in result.provenance:print(f"{r.status.upper():5} {r.id:18} op={r.op:10} engine={r.engine or '-':10} in={r.input_count} out={r.output_count} {r.elapsed:.2f}s {r.error}")
    return 0

def cmd_engines(a):
    rows=discover_engines(with_versions=not a.no_version)
    if a.capability: rows=[x for x in rows if a.capability in x.spec.capabilities]
    if a.available: rows=[x for x in rows if x.available]
    if a.json:return _json([x.to_dict() for x in rows]) or 0
    for x in rows:
        caps=",".join(x.spec.capabilities)
        print(f"{'YES' if x.available else 'NO ':3} {x.spec.name:16} cost={x.spec.cost} conf={x.spec.confidence:.2f} {'INTRUSIVE' if x.spec.intrusive else 'clean':9} {caps}")
        if a.verbose:
            print(f"    executable={x.executable or '-'} python={x.python_module or '-'} family={x.spec.independent_family or '-'}")
            if x.version: print(f"    version={x.version}")
            if x.reason: print(f"    note={x.reason}")
    return 0


def cmd_fingerprint(a):
    fp=fingerprint(a.apk,use_apkid=not a.no_apkid)
    if a.out:Path(a.out).write_text(json.dumps(fp.to_dict(),indent=2,sort_keys=True))
    if a.json:return _json(fp.to_dict()) or 0
    print(f"kind={fp.kind} sha256={fp.sha256}")
    for key,val in [("framework",fp.framework),("http",fp.http_stacks),("di",fp.di),("serialization",fp.serialization),("protections",fp.protections),("abis",fp.abis)]:
        print(f"{key}={','.join(val) if val else '-'}")
    print(f"obfuscation={fp.obfuscation.get('level')} score={fp.obfuscation.get('score')}")
    print(f"dex={len(fp.dex_files)} native_libs={len(fp.native_libraries)} splits={len(fp.split_apks)}")
    print("route="+" -> ".join(fp.recommended_route))
    return 0


def _print_refs(rows,json_mode=False):
    if json_mode:return _json([{"id":r.id,"module":r.module.name,"offset":r.function.offset,"offset_hex":hex(r.function.offset),"address":r.function.address,"name":r.function.name,"score":r.function.score,"tags":r.function.tags,"imports":r.function.imports,"jni":r.function.jni_methods,"arm64":r.function.arm64_profile} for r in rows]) or 0
    for r in rows: print(f"{r.function.score:7.2f} {r.id:32} {r.function.name} [{','.join(r.function.tags)}]")
    print(f"matches={len(rows)}")
    return 0


def cmd_select(a):return _print_refs(select(load_case(a.case),a.where or "",limit=a.limit,sort=a.sort),a.json)

def cmd_slice(a):
    c=load_case(a.case); seed=select(c,a.where or "",limit=a.seed_limit)
    rows=expand(seed,c,direction=a.direction,depth=a.depth,include_xrefs=not a.calls_only)
    if a.filter: allow={(r.module.name,r.function.address) for r in select(c,a.filter,limit=None)}; rows=[r for r in rows if (r.module.name,r.function.address) in allow]
    if a.limit: rows=rows[:a.limit]
    return _print_refs(rows,a.json)


def cmd_validate(a):
    c=load_case(a.case); refs=select(c,a.where or "",limit=a.limit)
    engines=a.engine or ["rizin","lief","radare2","ghidra"]
    obs=validate_refs(refs,engines,timeout=a.timeout,max_functions=a.limit)
    cons=consensus(obs,policy=a.policy,tolerance=a.tolerance)
    payload={"observations":[x.to_dict() for x in obs],"consensus":[x.to_dict() for x in cons]}
    if a.out:Path(a.out).write_text(json.dumps(payload,indent=2,sort_keys=True))
    if a.json:return _json(payload) or 0
    for x in cons: print(f"{x.score:.3f} {x.function_id:34} engines={','.join(x.engines)} conflicts={','.join(x.conflicts) or '-'}")
    return 0


def cmd_sig(a):
    c=load_case(a.case); rows=select(c,a.where or "",limit=a.limit)
    sigs=[make_signature(x).to_dict() for x in rows]
    payload=sigs[0] if a.limit==1 and len(sigs)==1 else sigs
    if a.out:Path(a.out).write_text(json.dumps(payload,indent=2,sort_keys=True))
    return _json(payload) if a.json or not a.out else 0


def cmd_match(a):
    raw=json.loads(Path(a.signature).read_text()); raw=raw[0] if isinstance(raw,list) else raw
    sig=FunctionSignature(**{k:v for k,v in raw.items() if k in FunctionSignature.__dataclass_fields__})
    rows=match_signature(sig,load_case(a.case),threshold=a.threshold,limit=a.limit)
    if a.json:return _json(rows) or 0
    for r in rows:print(f"{r['score']:.4f} {r['module']}+{r['offset_hex']} {r['name']} {r['parts']}")
    return 0


def _ensure_case(a):
    if a.case:return load_case(a.case)
    out=Path(a.out or (Path.home()/"AndroidCTFMax"/"cases-remix"/f"flow-{os.getpid()}"))
    argv=["analyze"]
    if a.package:argv += ["--package",a.package,"--serial",a.serial]
    elif a.apk:argv += ["--apk",a.apk]
    elif a.elf:argv += ["--elf",a.elf]
    else:raise SystemExit("flow requires --case or one of --package/--apk/--elf")
    argv += ["--mode",a.mode,"--out",str(out),"--budget",str(a.analysis_budget),"--jobs",str(a.jobs)]
    if a.package and not a.live_root:argv += ["--no-live-root"]
    if a.no_jadx:argv += ["--no-jadx"]
    rc=legacy.main(argv)
    if rc:return None
    return load_case(out)


def cmd_flow(a):
    c=_ensure_case(a)
    if c is None:return 2
    plan=recipe_plan(a.recipe) if a.recipe else ({'name':'inline','steps':[parse_inline_step(x) for x in a.step]} if a.step else load_plan(a.plan))
    engine=FlowEngine(c,out_dir=a.flow_out,budget=a.budget,jobs=a.jobs)
    result=engine.run(plan)
    print(f"CASE={result.case_dir}")
    print(f"FLOW={Path(result.output_dir)/'flow.json'}")
    for r in result.provenance: print(f"{r.status.upper():5} {r.id:18} op={r.op:10} engine={r.engine or '-':10} in={r.input_count} out={r.output_count} {r.elapsed:.2f}s {r.error}")
    return 0


def cmd_recipe(a):
    if a.action=="list":
        for n,r in RECIPES.items():print(f"{n:24} {r['description']}")
        return 0
    if a.name not in RECIPES:raise SystemExit(f"unknown recipe: {a.name}")
    return _json(recipe_plan(a.name)) or 0


def build_new_parser():
    p=argparse.ArgumentParser(prog="remix",description="REMIX V3 composable reverse-engineering control plane")
    p.add_argument("--version",action="version",version=f"REMIX {__version__}")
    sub=p.add_subparsers(dest="cmd",required=True)
    e=sub.add_parser("engines");e.add_argument("--capability");e.add_argument("--available",action="store_true");e.add_argument("--json",action="store_true");e.add_argument("--verbose",action="store_true");e.add_argument("--no-version",action="store_true");e.set_defaults(func=cmd_engines)
    f=sub.add_parser("fingerprint");f.add_argument("--apk",required=True);f.add_argument("--json",action="store_true");f.add_argument("--out");f.add_argument("--no-apkid",action="store_true");f.set_defaults(func=cmd_fingerprint)
    dc=sub.add_parser("decompile");dc.add_argument("input");dc.add_argument("--out",required=True);dc.add_argument("--engine",choices=["jadx","vineflower","both"],default="jadx");dc.add_argument("--timeout",type=int,default=240);dc.add_argument("--threads",type=int,default=0);dc.add_argument("--no-deobf",action="store_true");dc.add_argument("--json",action="store_true");dc.set_defaults(func=cmd_decompile)
    kn=sub.add_parser("kotlin-names");kn.add_argument("--sources",required=True);kn.add_argument("--out",required=True);kn.add_argument("--limit",type=int,default=100);kn.add_argument("--json",action="store_true");kn.set_defaults(func=cmd_kotlin_names)
    s=sub.add_parser("select");s.add_argument("--case",required=True);s.add_argument("--where",default="");s.add_argument("--sort",choices=["score","offset","size"],default="score");s.add_argument("--limit",type=int,default=100);s.add_argument("--json",action="store_true");s.set_defaults(func=cmd_select)
    sl=sub.add_parser("slice");sl.add_argument("--case",required=True);sl.add_argument("--where",default="");sl.add_argument("--seed-limit",type=int,default=40);sl.add_argument("--direction",choices=["up","down","both"],default="both");sl.add_argument("--depth",type=int,default=2);sl.add_argument("--calls-only",action="store_true");sl.add_argument("--filter");sl.add_argument("--limit",type=int,default=250);sl.add_argument("--json",action="store_true");sl.set_defaults(func=cmd_slice)
    v=sub.add_parser("validate");v.add_argument("--case",required=True);v.add_argument("--where",default="score>=4");v.add_argument("--engine",action="append");v.add_argument("--limit",type=int,default=16);v.add_argument("--timeout",type=int,default=75);v.add_argument("--policy",choices=["weighted","majority","all"],default="weighted");v.add_argument("--tolerance",type=float,default=.20);v.add_argument("--out");v.add_argument("--json",action="store_true");v.set_defaults(func=cmd_validate)
    sg=sub.add_parser("sig");sg.add_argument("--case",required=True);sg.add_argument("--where",default="");sg.add_argument("--limit",type=int,default=1);sg.add_argument("--out");sg.add_argument("--json",action="store_true");sg.set_defaults(func=cmd_sig)
    mt=sub.add_parser("match");mt.add_argument("--signature",required=True);mt.add_argument("--case",required=True);mt.add_argument("--threshold",type=float,default=.55);mt.add_argument("--limit",type=int,default=30);mt.add_argument("--json",action="store_true");mt.set_defaults(func=cmd_match)
    fl=sub.add_parser("flow");src=fl.add_mutually_exclusive_group(required=True);src.add_argument("--case");src.add_argument("--package");src.add_argument("--apk");src.add_argument("--elf");pl=fl.add_mutually_exclusive_group(required=True);pl.add_argument("--plan");pl.add_argument("--recipe",choices=sorted(RECIPES));pl.add_argument("--step",action="append",help="repeatable inline step: id=hot;op=select;where=tag:crypto AND score>=6");fl.add_argument("--serial",default=os.environ.get("ADB_SERIAL","emulator-5554"));fl.add_argument("--mode",choices=["fast","balanced","full","deep"],default="balanced");fl.add_argument("--analysis-budget",type=int,default=120);fl.add_argument("--budget",type=int,default=300);fl.add_argument("--jobs",type=int,default=min(4,os.cpu_count() or 2));fl.add_argument("--out");fl.add_argument("--flow-out");fl.add_argument("--live-root",action=argparse.BooleanOptionalAction,default=True);fl.add_argument("--no-jadx",action="store_true");fl.set_defaults(func=cmd_flow)
    au=sub.add_parser("auto");asu=au.add_mutually_exclusive_group(required=True);asu.add_argument("--case");asu.add_argument("--package");asu.add_argument("--apk");asu.add_argument("--elf");au.add_argument("--serial",default=os.environ.get("ADB_SERIAL","emulator-5554"));au.add_argument("--mode",choices=["fast","balanced","full","deep"],default="balanced");au.add_argument("--analysis-budget",type=int,default=120);au.add_argument("--budget",type=int,default=300);au.add_argument("--jobs",type=int,default=min(4,os.cpu_count() or 2));au.add_argument("--out");au.add_argument("--flow-out");au.add_argument("--live-root",action=argparse.BooleanOptionalAction,default=True);au.add_argument("--no-jadx",action="store_true");au.add_argument("--top",type=int,default=48);au.add_argument("--deep-validators",action="store_true");au.add_argument("--print-plan",action="store_true");au.set_defaults(func=cmd_auto)
    r=sub.add_parser("recipe");r.add_argument("action",choices=["list","show"]);r.add_argument("name",nargs="?");r.set_defaults(func=cmd_recipe)
    return p


def main(argv=None):
    argv=list(sys.argv[1:] if argv is None else argv)
    if not argv:return build_new_parser().print_help() or 0
    if argv[0] in {"-h","--help"}:
        build_new_parser().print_help();print("\nLegacy V2.1 commands remain available: doctor analyze fn query graph module refs symbols strings jni path trace diff")
        return 0
    if argv[0] in {"--version"}:return build_new_parser().parse_args(argv).func if False else (print(f"REMIX {__version__}") or 0)
    if argv[0] not in NEW_COMMANDS:return legacy.main(argv)
    a=build_new_parser().parse_args(argv);return int(a.func(a) or 0)

if __name__=="__main__":raise SystemExit(main())
