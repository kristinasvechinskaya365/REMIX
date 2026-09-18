from __future__ import annotations

import importlib
import json
import math
import re
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .model import AnalysisCase
from .registry import engine_map
from .selector import FunctionRef


@dataclass(slots=True)
class EngineObservation:
    engine: str
    family: str
    function_id: str
    status: str
    confidence: float
    claims: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    elapsed: float = 0.0
    error: str = ""

    def to_dict(self): return asdict(self)


@dataclass(slots=True)
class Consensus:
    function_id: str
    score: float
    engines: list[str]
    families: list[str]
    agreements: dict[str, Any]
    conflicts: dict[str, Any]
    observations: list[dict[str, Any]]

    def to_dict(self): return asdict(self)


def _json_tail(text: str, default=None):
    default={} if default is None else default
    text=text.strip()
    if not text: return default
    try: return json.loads(text)
    except Exception:
        for i,c in enumerate(text):
            if c in "[{":
                try: return json.loads(text[i:])
                except Exception: pass
    return default


def _run(argv:list[str],timeout:int=45)->tuple[int,str,str,float]:
    t=time.monotonic()
    try:
        cp=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout)
        return cp.returncode,cp.stdout,cp.stderr,time.monotonic()-t
    except subprocess.TimeoutExpired as e:
        out=e.stdout.decode() if isinstance(e.stdout,bytes) else (e.stdout or "")
        err=e.stderr.decode() if isinstance(e.stderr,bytes) else (e.stderr or "")
        return 124,out,err,time.monotonic()-t


def observe_existing(ref:FunctionRef,engine:str)->EngineObservation:
    f=ref.function; m=ref.module
    family={"rizin":"rizin","ghidra":"ghidra","lief":"lief"}.get(engine,engine)
    claims={}
    if engine=="rizin":
        claims={"exists":True,"size":f.size,"callers":len(f.callers),"callees":len(f.callees),
                "imports":sorted(f.imports),"strings":len(f.string_refs)}
        ok=not any("rizin" in x.lower() for x in m.errors)
        return EngineObservation(engine,family,ref.id,"ok" if ok else "partial",.82 if ok else .45,claims,{},0,"; ".join(m.errors))
    if engine=="ghidra":
        rows=[e.value for e in f.evidence if e.source=="ghidra"]
        claims={"exists":bool(rows),"pseudocode":bool(f.pseudocode)}
        if rows:
            row=rows[-1]
            for key in ("name","size","callers","callees","blocks"):
                if key in row: claims[key]=row[key]
        return EngineObservation(engine,family,ref.id,"ok" if rows else "missing",.94 if rows else 0,claims,{"evidence":rows[-1:]})
    if engine=="lief":
        # LIEF is loader/format evidence, not a disassembler. It can independently
        # confirm that a candidate lies in an executable LOAD segment and whether a
        # dynamic symbol starts there, but it must not manufacture a function boundary.
        syms=[s for s in m.symbols if s.address==f.address and (s.exported or s.type.upper() in {"FUNC","GNU_IFUNC"})]
        exec_ranges=[]
        for seg in m.metadata.get("segments_lief") or []:
            flags=int(seg.get("flags_value") or 0); start=int(seg.get("virtual_address") or 0); size=int(seg.get("virtual_size") or 0)
            if flags & 1: exec_ranges.append((start,start+size))
        in_exec=any(a<=f.address<b for a,b in exec_ranges) if exec_ranges else None
        claims={"address_in_executable_segment":in_exec,"symbol_at_start":bool(syms),"symbol":syms[0].name if syms else ""}
        ok=(m.metadata.get("lief")=="ok")
        return EngineObservation(engine,family,ref.id,"ok" if ok else "missing",.90 if ok else 0,claims,{"exec_ranges":exec_ranges[:16]})
    return EngineObservation(engine,family,ref.id,"unsupported",0,{},{},0,"unknown existing engine")


def observe_radare2(ref:FunctionRef,timeout:int=40)->EngineObservation:
    st=engine_map().get("radare2"); start=time.monotonic()
    if not st or not st.available or not st.executable:
        return EngineObservation("radare2","radare",ref.id,"unavailable",0,error="radare2 not found")
    addr=ref.function.address
    cmd=f"aaa;afij @ {addr};axfj @ {addr}"
    rc,out,err,elapsed=_run([st.executable,"-2","-q","-c",cmd,ref.module.path],timeout)
    # Multiple JSON values may be concatenated; use a delimiter in a second compact command if needed.
    rc1,o1,e1,el1=_run([st.executable,"-2","-q","-A","-c",f"afij @ {addr}",ref.module.path],timeout)
    rows=_json_tail(o1,[])
    row=rows[0] if isinstance(rows,list) and rows else {}
    claims={"exists":bool(row),"size":int(row.get("size") or row.get("realsz") or 0),
            "name":row.get("name","")}
    return EngineObservation("radare2","radare",ref.id,"ok" if row else "partial",.80 if row else .3,
                             claims,{"function":row,"stdout_tail":out[-2000:]},elapsed+el1,(err+"\n"+e1)[-1200:])


def observe_angr(ref:FunctionRef,timeout:int=90)->EngineObservation:
    start=time.monotonic()
    try:
        angr=importlib.import_module("angr")
    except Exception as e:
        return EngineObservation("angr","angr",ref.id,"unavailable",0,error=str(e))
    # angr is executed in-process. Caller should select a small high-value set.
    try:
        project=angr.Project(ref.module.path,auto_load_libs=False)
        obj=project.loader.main_object
        addr=obj.mapped_base + ref.function.offset
        cfg=project.analyses.CFGFast(normalize=True,data_references=True,force_complete_scan=False)
        fn=cfg.kb.functions.get(addr)
        if fn is None:
            # Function managers can use a nearby normalized address.
            candidates=[x for x in cfg.kb.functions.values() if x.addr<=addr<=(x.addr+max(x.size,1))]
            fn=candidates[0] if candidates else None
        if not fn:
            return EngineObservation("angr","angr",ref.id,"missing",.2,{"exists":False},elapsed=time.monotonic()-start)
        calls=[]
        try:
            calls=[int(x) for x in fn.get_call_sites()]
        except Exception: pass
        claims={"exists":True,"size":int(fn.size or 0),"blocks":len(list(fn.blocks)),"call_sites":len(calls),
                "returning":bool(fn.returning) if fn.returning is not None else None}
        return EngineObservation("angr","angr",ref.id,"ok",.93,claims,{},time.monotonic()-start)
    except Exception as e:
        return EngineObservation("angr","angr",ref.id,"error",0,error=str(e),elapsed=time.monotonic()-start)


def validate_refs(refs:Iterable[FunctionRef],engines:Iterable[str],*,timeout:int=75,max_functions:int=32)->list[EngineObservation]:
    out=[]
    for ref in list(refs)[:max_functions]:
        for engine in engines:
            if engine in {"rizin","ghidra","lief"}: out.append(observe_existing(ref,engine))
            elif engine=="radare2": out.append(observe_radare2(ref,timeout=min(timeout,45)))
            elif engine=="angr": out.append(observe_angr(ref,timeout=timeout))
            else: out.append(EngineObservation(engine,engine,ref.id,"unsupported",0,error="no validator adapter"))
    return out


def _norm_scalar(v):
    if isinstance(v,bool) or v is None: return v
    if isinstance(v,(int,float)): return float(v)
    if isinstance(v,str): return v.lower()
    return v


def consensus(observations:Iterable[EngineObservation],*,policy:str="weighted",tolerance:float=.20)->list[Consensus]:
    grouped={}
    for o in observations: grouped.setdefault(o.function_id,[]).append(o)
    results=[]
    for fid,obs in grouped.items():
        usable=[o for o in obs if o.confidence>0 and o.status in {"ok","partial"}]
        claims={}
        for o in usable:
            for k,v in o.claims.items(): claims.setdefault(k,[]).append((o,v))
        agree={}; conflicts={}; claim_votes=[]
        for key,vals in claims.items():
            if len(vals)<2: continue
            if all(isinstance(v,(int,float,bool)) or v is None for _,v in vals):
                nums=[float(v) for _,v in vals if isinstance(v,(int,float)) and not isinstance(v,bool)]
                bools=[v for _,v in vals if isinstance(v,bool) or v is None]
                if nums:
                    hi=max(nums); lo=min(nums); denom=max(1.0,abs(sum(nums)/len(nums)))
                    ok=(hi-lo)/denom<=tolerance
                    target=sum(nums)/len(nums)
                else:
                    ok=len(set(bools))<=1; target=bools[0] if bools else None
            else:
                norm=[json.dumps(_norm_scalar(v),sort_keys=True,default=str) for _,v in vals]
                ok=len(set(norm))==1; target=vals[0][1]
            weight=sum(o.confidence for o,_ in vals)
            claim_votes.append((weight,1.0 if ok else 0.0))
            entry={"value":target,"engines":[o.engine for o,_ in vals],"weight":round(weight,3)}
            (agree if ok else conflicts)[key]=entry if ok else {**entry,"values":{o.engine:v for o,v in vals}}
        families=sorted(set(o.family for o in usable))
        vote_weight=sum(w for w,_ in claim_votes)
        agreement_ratio=(sum(w*v for w,v in claim_votes)/vote_weight) if vote_weight else (1.0 if usable else 0.0)
        independence=min(1.0,len(families)/3)
        coverage=min(1.0,len(usable)/3)
        score=min(1.0, agreement_ratio*.60 + independence*.25 + coverage*.15) if usable else 0.0
        if policy=="all" and conflicts: score=0.0
        elif policy=="majority" and len(agree)<len(conflicts): score*=.5
        results.append(Consensus(fid,round(score,3),[o.engine for o in usable],families,agree,conflicts,[o.to_dict() for o in obs]))
    return sorted(results,key=lambda r:-r.score)


def scan_file(engine:str,path:str|Path,*,timeout:int=90)->dict:
    p=str(path); st=engine_map().get(engine); start=time.monotonic()
    if not st or not st.available:
        return {"engine":engine,"status":"unavailable","path":p,"elapsed":0}
    if engine=="capa" and st.executable:
        argv=[st.executable,"-j",p]
    elif engine=="floss" and st.executable:
        argv=[st.executable,"-j",p]
    elif engine=="apkid" and st.executable:
        argv=[st.executable,"-j",p]
    elif engine=="strings" and st.executable:
        argv=[st.executable,"-a",p]
    else:
        return {"engine":engine,"status":"unsupported","path":p,"elapsed":0}
    rc,out,err,elapsed=_run(argv,timeout)
    payload=_json_tail(out,None) if engine!="strings" else {"strings":out.splitlines()}
    return {"engine":engine,"status":"ok" if rc==0 else "error","path":p,"rc":rc,"elapsed":elapsed,
            "result":payload,"stderr":err[-2000:]}
