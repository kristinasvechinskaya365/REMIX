from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from .model import AnalysisCase, FunctionNode, ModuleAnalysis


TOKEN_RE=re.compile(r'''\s*(>=|<=|!=|!~|=|>|<|~|\(|\)|\bAND\b|\bOR\b|\bNOT\b|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s()]+)''',re.I)

@dataclass(slots=True)
class FunctionRef:
    module: ModuleAnalysis
    function: FunctionNode

    @property
    def id(self): return f"{self.module.name}+{self.function.offset:#x}"


def _field(ref: FunctionRef, key: str) -> Any:
    f,m=ref.function,ref.module
    k=key.lower()
    if k in {"score","size","offset","address"}: return getattr(f,k)
    if k in {"name","module"}: return f.name if k=="name" else m.name
    if k in {"tag","tags"}: return f.tags
    if k in {"import","imports"}: return f.imports
    if k in {"symbol","symbols"}: return f.symbols
    if k in {"jni","jnis"}: return f.jni_methods
    if k in {"caller","callers"}: return f.callers
    if k in {"callee","callees"}: return f.callees
    if k in {"dynamic","dynamic_hits","hits"}: return f.dynamic_hits
    if k in {"evidence","evidence_count"}: return len(f.evidence)
    if k.startswith("arm64."): return f.arm64_profile.get(k.split(".",1)[1],0)
    if k in {"strings","string"}:
        by={s.address:s.value for s in m.strings}
        return [by[x] for x in f.string_refs if x in by]
    raise ValueError(f"unknown selector field: {key}")


def _literal(v: str):
    if len(v)>=2 and v[0]==v[-1] and v[0] in "\"'":
        return bytes(v[1:-1],"utf-8").decode("unicode_escape")
    low=v.lower()
    if low in {"true","false"}: return low=="true"
    try: return int(v,0)
    except ValueError:
        try: return float(v)
        except ValueError: return v


def _cmp(value,op,rhs) -> bool:
    vals=value if isinstance(value,(list,tuple,set)) else [value]
    if op in {"~","!~"}:
        rx=re.compile(str(rhs),re.I)
        result=any(rx.search(str(v)) for v in vals)
        return (not result) if op=="!~" else result
    if op=="=": return any(v==rhs or str(v).lower()==str(rhs).lower() for v in vals)
    if op=="!=": return all(not (v==rhs or str(v).lower()==str(rhs).lower()) for v in vals)
    if op in {">",">=","<","<="}:
        try: a=float(value); b=float(rhs)
        except (TypeError,ValueError): return False
        return {">":a>b,">=":a>=b,"<":a<b,"<=":a<=b}[op]
    return False


class Parser:
    def __init__(self,text:str):
        self.toks=[m.group(1) for m in TOKEN_RE.finditer(text)]; self.i=0
    def peek(self): return self.toks[self.i] if self.i<len(self.toks) else None
    def pop(self):
        x=self.peek()
        if x is None: raise ValueError("unexpected end of selector")
        self.i+=1; return x
    def parse(self)->Callable[[FunctionRef],bool]:
        if not self.toks: return lambda _:True
        fn=self.or_expr()
        if self.peek() is not None: raise ValueError(f"unexpected token: {self.peek()}")
        return fn
    def or_expr(self):
        left=self.and_expr()
        while (self.peek() or "").upper()=="OR":
            self.pop(); right=self.and_expr(); old=left; left=lambda r,a=old,b=right:a(r) or b(r)
        return left
    def and_expr(self):
        left=self.not_expr()
        while (self.peek() or "").upper()=="AND":
            self.pop(); right=self.not_expr(); old=left; left=lambda r,a=old,b=right:a(r) and b(r)
        return left
    def not_expr(self):
        if (self.peek() or "").upper()=="NOT":
            self.pop(); inner=self.not_expr(); return lambda r,f=inner:not f(r)
        return self.atom()
    def atom(self):
        if self.peek()=="(":
            self.pop(); x=self.or_expr()
            if self.pop()!=")": raise ValueError("missing )")
            return x
        first=self.pop()
        # shorthand tag:crypto, module:libfoo, name:worker
        if ":" in first and not first.startswith(("http:","https:")):
            key,val=first.split(":",1); rhs=_literal(val)
            return lambda r,k=key,v=rhs:_cmp(_field(r,k),"=",v)
        # Compact comparisons are intentionally accepted because CLI selectors
        # should not require shell-hostile whitespace: score>=6, name~verify.
        cm=re.match(r"^([A-Za-z_][A-Za-z0-9_.-]*)(>=|<=|!=|!~|=|>|<|~)(.+)$", first)
        if cm:
            key,op,val=cm.groups(); rhs=_literal(val)
            return lambda r,k=key,o=op,v=rhs:_cmp(_field(r,k),o,v)
        op=self.pop()
        if op not in {"=","!=",">",">=","<","<=","~","!~"}: raise ValueError(f"expected comparison after {first}, got {op}")
        rhs=_literal(self.pop())
        return lambda r,k=first,o=op,v=rhs:_cmp(_field(r,k),o,v)


def compile_selector(expr:str)->Callable[[FunctionRef],bool]: return Parser(expr).parse()


def all_functions(case:AnalysisCase)->list[FunctionRef]:
    return [FunctionRef(m,f) for m in case.modules for f in m.functions]


def select(case:AnalysisCase,expr:str="",*,limit:int|None=None,sort:str="score") -> list[FunctionRef]:
    pred=compile_selector(expr)
    rows=[r for r in all_functions(case) if pred(r)]
    if sort=="score": rows.sort(key=lambda r:(-r.function.score,r.module.name,r.function.offset))
    elif sort=="offset": rows.sort(key=lambda r:(r.module.name,r.function.offset))
    elif sort=="size": rows.sort(key=lambda r:(-r.function.size,r.module.name,r.function.offset))
    return rows if limit is None else rows[:limit]


def expand(seed:Iterable[FunctionRef],case:AnalysisCase,*,direction:str="both",depth:int=1,include_xrefs:bool=True)->list[FunctionRef]:
    by={(m.name,f.address):FunctionRef(m,f) for m in case.modules for f in m.functions}
    seen={(r.module.name,r.function.address):r for r in seed}; frontier=list(seen.values())
    for _ in range(max(0,depth)):
        nxt=[]
        for r in frontier:
            f=r.function; add=[]
            if direction in {"up","both"}: add+=f.callers
            if direction in {"down","both"}: add+=f.callees
            if include_xrefs:
                if direction in {"up","both"}: add += [x.get("from_function") for x in f.xrefs_to if x.get("from_function")]
                if direction in {"down","both"}: add += [x.get("to_function") for x in f.xrefs_from if x.get("to_function")]
            for a in add:
                rr=by.get((r.module.name,a))
                if rr and (rr.module.name,rr.function.address) not in seen:
                    seen[(rr.module.name,rr.function.address)]=rr; nxt.append(rr)
        frontier=nxt
        if not frontier: break
    return sorted(seen.values(),key=lambda r:(-r.function.score,r.module.name,r.function.offset))
