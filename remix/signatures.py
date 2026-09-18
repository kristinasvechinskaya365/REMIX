from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict,dataclass
from typing import Any

from .model import AnalysisCase
from .selector import FunctionRef,all_functions


@dataclass(slots=True)
class FunctionSignature:
    module: str
    offset: int
    name_hint: str
    size: int
    size_bucket: int
    tags: list[str]
    imports: list[str]
    symbols: list[str]
    strings: list[str]
    arm64: dict[str,int|float]
    callers: int
    callees: int
    digest: str = ""

    def to_dict(self): return asdict(self)


def _norm_string(s:str)->str:
    s=re.sub(r"0x[0-9a-f]+","<hex>",s.lower())
    s=re.sub(r"\b\d{3,}\b","<num>",s)
    s=re.sub(r"[A-Fa-f0-9]{24,}","<blob>",s)
    return s[:300]


def make_signature(ref:FunctionRef)->FunctionSignature:
    f,m=ref.function,ref.module
    smap={s.address:s.value for s in m.strings}
    strings=sorted(set(_norm_string(smap[x]) for x in f.string_refs if x in smap))[:80]
    arm={k:v for k,v in sorted(f.arm64_profile.items()) if isinstance(v,(int,float))}
    sig=FunctionSignature(m.name,f.offset,f.name,f.size,int(round(f.size/32))*32,sorted(set(f.tags)),
                          sorted(set(x.split("@@")[0] for x in f.imports)),sorted(set(f.symbols)),strings,arm,
                          len(f.callers),len(f.callees))
    material=json.dumps({k:v for k,v in sig.to_dict().items() if k not in {"offset","name_hint","digest"}},sort_keys=True)
    sig.digest=hashlib.sha256(material.encode()).hexdigest()
    return sig


def _jaccard(a,b)->float:
    a=set(a); b=set(b)
    if not a and not b:return 1.0
    return len(a&b)/max(1,len(a|b))


def similarity(a:FunctionSignature,b:FunctionSignature)->tuple[float,dict[str,float]]:
    size=1.0-min(1.0,abs(a.size-b.size)/max(16,a.size,b.size))
    graph=1.0-min(1.0,(abs(a.callers-b.callers)+abs(a.callees-b.callees))/max(2,a.callers+a.callees+b.callers+b.callees))
    tags=_jaccard(a.tags,b.tags); imports=_jaccard(a.imports,b.imports); strings=_jaccard(a.strings,b.strings)
    keys=set(a.arm64)|set(b.arm64); arm=1.0
    if keys:
        diffs=[]
        for k in keys:
            x=float(a.arm64.get(k,0)); y=float(b.arm64.get(k,0)); diffs.append(abs(x-y)/max(1,x,y))
        arm=1.0-sum(diffs)/len(diffs)
    score=.12*size+.10*graph+.16*tags+.25*imports+.22*strings+.15*arm
    return round(score,4),{"size":round(size,3),"graph":round(graph,3),"tags":round(tags,3),"imports":round(imports,3),"strings":round(strings,3),"arm64":round(arm,3)}


def match_signature(sig:FunctionSignature,case:AnalysisCase,*,threshold:float=.55,limit:int=30)->list[dict[str,Any]]:
    rows=[]
    for ref in all_functions(case):
        other=make_signature(ref); score,parts=similarity(sig,other)
        if score>=threshold:
            rows.append({"score":score,"parts":parts,"module":ref.module.name,"offset":ref.function.offset,
                         "offset_hex":hex(ref.function.offset),"name":ref.function.name,"signature":other.to_dict()})
    rows.sort(key=lambda x:-x["score"])
    return rows[:limit]
