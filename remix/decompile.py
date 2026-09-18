from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path


def _run(argv,timeout):
    t=time.monotonic()
    try:
        cp=subprocess.run([str(x) for x in argv],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout)
        return {"argv":[str(x) for x in argv],"rc":cp.returncode,"stdout":cp.stdout[-10000:],"stderr":cp.stderr[-10000:],"elapsed":time.monotonic()-t}
    except subprocess.TimeoutExpired:
        return {"argv":[str(x) for x in argv],"rc":124,"stdout":"","stderr":"timeout","elapsed":time.monotonic()-t}


def decompile(path:str|Path,out:str|Path,*,engine:str='jadx',timeout:int=180,threads:int=0,deobf:bool=True)->dict:
    src=Path(path);out=Path(out);out.mkdir(parents=True,exist_ok=True);runs=[]
    engines=[engine] if engine!='both' else ['jadx','vineflower']
    for e in engines:
        target=out/e if len(engines)>1 else out
        target.mkdir(parents=True,exist_ok=True)
        if e=='jadx':
            exe=shutil.which('jadx')
            if not exe:runs.append({"engine":e,"status":"unavailable"});continue
            argv=[exe,'--show-bad-code','-d',target]
            if deobf:argv.append('--deobf')
            if threads>0:argv += ['--threads-count',str(threads)]
            argv.append(src);r=_run(argv,timeout);r['engine']=e;runs.append(r)
        elif e=='vineflower':
            exe=shutil.which('vineflower')
            if not exe:runs.append({"engine":e,"status":"unavailable"});continue
            inp=src;tmp=None
            if src.suffix.lower() in {'.apk','.dex'}:
                d2j=shutil.which('d2j-dex2jar') or shutil.which('d2j-dex2jar.sh')
                if not d2j:runs.append({"engine":e,"status":"unavailable","reason":"dex2jar required for APK/DEX"});continue
                tmp=Path(tempfile.mktemp(suffix='.jar'))
                conv=_run([d2j,src,'-o',tmp,'--force'],min(timeout,90));conv['engine']='dex2jar';runs.append(conv)
                if conv['rc']!=0:continue
                inp=tmp
            r=_run([exe,inp,target],timeout);r['engine']=e;runs.append(r)
            if tmp:tmp.unlink(missing_ok=True)
    comparison={}
    for e in engines:
        target=out/e if len(engines)>1 else out
        comparison[e]={"java":len(list(target.rglob('*.java'))),"kt":len(list(target.rglob('*.kt'))),"files":sum(1 for x in target.rglob('*') if x.is_file())}
    result={"input":str(src),"out":str(out),"engines":engines,"runs":runs,"comparison":comparison}
    (out/'decompile.json').write_text(json.dumps(result,indent=2,sort_keys=True))
    return result
