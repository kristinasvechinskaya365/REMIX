from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .deep import EngineObservation, Consensus, consensus, scan_file, validate_refs
from .engines.ghidra import GhidraEngine
from .engines.rizin import RizinEngine
from .model import AnalysisCase
from .recipes import RECIPES
from .registry import engine_map
from .reporting import write_case
from .runner import Budget
from .selector import FunctionRef, expand, select
from .serde import load_case
from .signatures import make_signature


@dataclass(slots=True)
class StepRecord:
    id: str
    op: str
    engine: str = ""
    status: str = "ok"
    elapsed: float = 0.0
    input_count: int = 0
    output_count: int = 0
    details: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def to_dict(self): return asdict(self)


@dataclass(slots=True)
class FlowResult:
    case_dir: str
    datasets: dict[str, Any]
    provenance: list[StepRecord]
    output_dir: str


def _count(x)->int:
    if x is None:return 0
    if isinstance(x,(list,tuple,set,dict)):return len(x)
    return 1


def _serializable(x):
    if isinstance(x,FunctionRef):
        return {"id":x.id,"module":x.module.name,"module_path":x.module.path,"offset":x.function.offset,
                "offset_hex":hex(x.function.offset),"address":x.function.address,"address_hex":hex(x.function.address),
                "end":x.function.end,"end_hex":hex(x.function.end or (x.function.address+max(1,x.function.size))),
                "size":x.function.size,"name":x.function.name,"score":x.function.score,"tags":x.function.tags}
    if isinstance(x,(EngineObservation,Consensus)): return x.to_dict()
    if hasattr(x,"to_dict"): return x.to_dict()
    if isinstance(x,list): return [_serializable(v) for v in x]
    if isinstance(x,dict): return {k:_serializable(v) for k,v in x.items()}
    return x


def _resolve_source(datasets:dict[str,Any],src):
    if src is None:return datasets.get("case")
    if isinstance(src,list):
        rows=[]
        for s in src:
            v=datasets.get(s,[]); rows.extend(v if isinstance(v,list) else [v])
        return rows
    return datasets.get(src)


def _record_get(row:Any,path:str):
    if isinstance(row,FunctionRef):
        base=_serializable(row)
    elif isinstance(row,(EngineObservation,Consensus)): base=row.to_dict()
    elif isinstance(row,dict): base=row
    else: return None
    cur=base
    for part in path.split("."):
        if not isinstance(cur,dict):return None
        cur=cur.get(part)
    return cur


def _record_match(row,criteria:dict)->bool:
    for field,cond in criteria.items():
        value=_record_get(row,field)
        if not isinstance(cond,dict):
            if str(value).lower()!=str(cond).lower():return False
            continue
        for op,rhs in cond.items():
            if op=="regex" and not re.search(str(rhs),str(value or ""),re.I):return False
            if op=="not_regex" and re.search(str(rhs),str(value or ""),re.I):return False
            if op=="contains":
                if isinstance(value,(list,tuple,set)):
                    if not any(str(rhs).lower() in str(v).lower() for v in value):return False
                elif str(rhs).lower() not in str(value or "").lower():return False
            if op in {"gt","gte","lt","lte"}:
                try:a=float(value);b=float(rhs)
                except Exception:return False
                if op=="gt" and not a>b:return False
                if op=="gte" and not a>=b:return False
                if op=="lt" and not a<b:return False
                if op=="lte" and not a<=b:return False
            if op=="eq" and value!=rhs:return False
            if op=="ne" and value==rhs:return False
    return True


def _template(s:str,item:Any,ctx:dict[str,str])->str:
    values=dict(ctx)
    if isinstance(item,FunctionRef): values.update(_serializable(item))
    elif isinstance(item,dict): values.update({k:v for k,v in item.items() if not isinstance(v,(dict,list))})
    elif isinstance(item,(EngineObservation,Consensus)): values.update(item.to_dict())
    def repl(m):
        key=m.group(1); v=values.get(key,"")
        return str(v)
    return re.sub(r"\$\{([A-Za-z0-9_.-]+)\}",repl,s)


def _external_one(argv:list[str],item,ctx,parser:str,timeout:int)->dict:
    cmd=[_template(x,item,ctx) for x in argv]
    t=time.monotonic()
    try:
        cp=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout)
        out=cp.stdout
        parsed:Any=out
        if parser=="json":
            try:parsed=json.loads(out)
            except Exception:parsed=None
        elif parser=="jsonl":
            parsed=[]
            for line in out.splitlines():
                try:parsed.append(json.loads(line))
                except Exception:pass
        elif parser=="lines": parsed=out.splitlines()
        return {"input":_serializable(item),"argv":cmd,"rc":cp.returncode,"elapsed":time.monotonic()-t,
                "stdout":out[-20000:] if parser=="text" else "","stderr":cp.stderr[-4000:],"result":parsed}
    except subprocess.TimeoutExpired:
        return {"input":_serializable(item),"argv":cmd,"rc":124,"elapsed":time.monotonic()-t,"timeout":True,"result":None}


class FlowEngine:
    def __init__(self,case:AnalysisCase,*,out_dir:str|Path|None=None,budget:int=300,jobs:int=4):
        self.case=case
        self.out=Path(out_dir or (Path(case.case_dir)/"flow")); self.out.mkdir(parents=True,exist_ok=True)
        self.budget=Budget(None if budget<=0 else budget)
        self.jobs=max(1,jobs)
        self.datasets={"case":case,"all":select(case,"",limit=None)}
        self.provenance:list[StepRecord]=[]
        self.engines=engine_map(with_versions=True)

    def _remaining_timeout(self,requested:int)->int:
        rem=self.budget.remaining
        if rem is None:return requested
        if rem<=0:raise TimeoutError("flow budget exhausted")
        return max(1,int(min(rem,requested)))

    def run(self,plan:dict)->FlowResult:
        for step in plan.get("steps",[]): self.run_step(step)
        write_case(self.case)
        manifest={"case":self.case.case_dir,"plan":plan,"provenance":[x.to_dict() for x in self.provenance],
                  "datasets":{k:{"type":type(v).__name__,"count":_count(v)} for k,v in self.datasets.items()}}
        (self.out/"flow.json").write_text(json.dumps(manifest,indent=2,sort_keys=True,default=str))
        return FlowResult(self.case.case_dir,self.datasets,self.provenance,str(self.out))

    def run_step(self,step:dict):
        sid=step.get("id") or f"step{len(self.provenance)+1}"; op=step.get("op","")
        rec=StepRecord(sid,op,str(step.get("engine",''))); t=time.monotonic()
        src=_resolve_source(self.datasets,step.get("from")); rec.input_count=_count(src)
        try:
            if op=="select":
                base=src if isinstance(src,list) and src and isinstance(src[0],FunctionRef) else None
                rows=select(self.case,step.get("where","") or "",limit=None,sort=step.get("sort","score"))
                if base is not None:
                    allow={(x.module.name,x.function.address) for x in base}; rows=[x for x in rows if (x.module.name,x.function.address) in allow]
                lim=step.get("limit"); result=rows[:int(lim)] if lim else rows
            elif op=="filter":
                rows=src if isinstance(src,list) else [src]
                result=[x for x in rows if _record_match(x,step.get("criteria") or {})]
                if step.get("limit"): result=result[:int(step["limit"])]
            elif op=="expand":
                rows=src if isinstance(src,list) else []
                result=expand(rows,self.case,direction=step.get("direction","both"),depth=int(step.get("depth",1)),include_xrefs=bool(step.get("xrefs",True)))
                if step.get("where"):
                    allow={(x.module.name,x.function.address) for x in select(self.case,step["where"],limit=None)}
                    result=[x for x in result if (x.module.name,x.function.address) in allow]
                if step.get("limit"): result=result[:int(step["limit"])]
            elif op=="enrich": result=self._enrich(src,step)
            elif op=="validate":
                engines=step.get("engines") or [step.get("engine","rizin")]
                lim=int(step.get("limit",32)); result=validate_refs(src or [],engines,timeout=self._remaining_timeout(int(step.get("timeout",75))),max_functions=lim)
            elif op=="consensus":
                observations=[]
                for x in (src if isinstance(src,list) else [src]):
                    if isinstance(x,EngineObservation):observations.append(x)
                    elif isinstance(x,dict) and "engine" in x and "function_id" in x: observations.append(EngineObservation(**{k:v for k,v in x.items() if k in EngineObservation.__dataclass_fields__}))
                result=consensus(observations,policy=step.get("policy","weighted"),tolerance=float(step.get("tolerance",.20)))
            elif op=="scan": result=self._scan(src,step)
            elif op=="signature":
                rows=src if isinstance(src,list) else []
                result=[make_signature(x) for x in rows[:int(step.get("limit",100))]]
            elif op=="external": result=self._external(src,step)
            elif op=="project":
                fields=step.get("fields") or []
                rows=src if isinstance(src,list) else [src]
                result=[{f:_record_get(x,f) for f in fields} for x in rows]
                if step.get("unique"):
                    seen=set(); uniq=[]
                    for x in result:
                        key=json.dumps(x,sort_keys=True,default=str)
                        if key not in seen:seen.add(key);uniq.append(x)
                    result=uniq
            elif op=="assert":
                rows=src if isinstance(src,list) else [src]
                ok_rows=[x for x in rows if _record_match(x,step.get("criteria") or {})]
                required=int(step.get("min_count",1))
                if len(ok_rows)<required: raise RuntimeError(step.get("message") or f"assertion failed: {len(ok_rows)} < {required}")
                result=ok_rows
            elif op=="emit": result=self._emit(src,step,sid)
            else: raise ValueError(f"unknown flow op: {op}")
            self.datasets[sid]=result; rec.output_count=_count(result)
        except Exception as e:
            rec.status="error"; rec.error=str(e)
            if not step.get("continue_on_error",False):
                rec.elapsed=time.monotonic()-t; self.provenance.append(rec); raise
            self.datasets[sid]=[]
        rec.elapsed=time.monotonic()-t
        if rec.engine and rec.engine in self.engines:
            st=self.engines[rec.engine]; rec.details={"engine_available":st.available,"engine_version":st.version,"engine_family":st.spec.independent_family}
        self.provenance.append(rec)
        return self.datasets.get(sid)

    def _enrich(self,src,step):
        refs=list(src or []); engine=step.get("engine","rizin"); limit=int(step.get("limit",32)); refs=refs[:limit]
        if engine=="rizin":
            rz=RizinEngine(budget=self.budget,deep=bool(step.get("deep",False)),timeout=self._remaining_timeout(int(step.get("timeout",60))))
            for r in refs: rz.enrich_function(r.module,r.function,timeout=min(15,self._remaining_timeout(15)))
        elif engine=="ghidra":
            gh=GhidraEngine(budget=self.budget,script_dir=Path(__file__).resolve().parent.parent/"ghidra_scripts")
            by={}
            for r in refs:by.setdefault(r.module.name,(r.module,[]))[1].append(r.function.offset)
            for _,(m,offs) in by.items():gh.enrich(m,offs,case_dir=self.case.case_dir,timeout=self._remaining_timeout(int(step.get("timeout",120))))
        else: raise ValueError(f"enrich engine unsupported: {engine}")
        return refs

    def _scan(self,src,step):
        engine=step.get("engine");
        if not engine:raise ValueError("scan requires engine")
        paths=[]
        if isinstance(src,list) and src and isinstance(src[0],FunctionRef): paths=sorted(set(x.module.path for x in src))
        elif isinstance(src,list): paths=[str(x) for x in src]
        elif src: paths=[str(src)]
        return [scan_file(engine,p,timeout=self._remaining_timeout(int(step.get("timeout",90)))) for p in paths]

    def _external(self,src,step):
        argv=step.get("argv")
        if not isinstance(argv,list) or not argv:raise ValueError("external requires argv array; shell strings are deliberately not accepted")
        rows=src if isinstance(src,list) else [src]
        if not step.get("foreach",True): rows=[src]
        parser=step.get("parser","text"); timeout=int(step.get("timeout",45))
        ctx={"case":self.case.case_dir,"out":str(self.out),"target":self.case.target}
        out=[]
        with ThreadPoolExecutor(max_workers=min(self.jobs,len(rows) or 1)) as pool:
            futs=[pool.submit(_external_one,argv,item,ctx,parser,self._remaining_timeout(timeout)) for item in rows]
            for f in as_completed(futs):out.append(f.result())
        return out

    def _emit(self,src,step,sid):
        fmt=step.get("format","json"); path=Path(step.get("path") or (self.out/f"{sid}.{ 'jsonl' if fmt=='jsonl' else 'txt' if fmt=='text' else 'json'}"))
        path.parent.mkdir(parents=True,exist_ok=True); payload=_serializable(src)
        if fmt=="json":path.write_text(json.dumps(payload,indent=2,sort_keys=True,default=str))
        elif fmt=="jsonl":
            rows=payload if isinstance(payload,list) else [payload]; path.write_text("\n".join(json.dumps(x,sort_keys=True,default=str) for x in rows)+"\n")
        else:
            rows=payload if isinstance(payload,list) else [payload]; path.write_text("\n".join(str(x) for x in rows)+"\n")
        return [{"path":str(path),"count":_count(src),"format":fmt}]


def load_plan(path:str|Path)->dict:
    return json.loads(Path(path).read_text())


def recipe_plan(name:str)->dict:
    if name not in RECIPES: raise KeyError(name)
    return {"name":name,**RECIPES[name]}
