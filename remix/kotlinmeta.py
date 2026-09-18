from __future__ import annotations

import json
import re
from pathlib import Path

DEBUG_RE=re.compile(r'@DebugMetadata\([^)]*?\bc\s*=\s*"([^"]+)"',re.S)
META_D2_RE=re.compile(r'@Metadata\([^)]*?\bd2\s*=\s*\{([^}]*)\}',re.S)
LCLASS_RE=re.compile(r'L([A-Za-z][\w/$]+);')
RENAMED_RE=re.compile(r'/\*\s*renamed from:\s*([\w.$]+)\s*\*/')

DEFAULT_SKIP=("kotlin.","kotlinx.","android.","androidx.","java.","javax.","org.jetbrains.","okhttp3.","okio.","retrofit2.")


def recover(root:str|Path,*,skip=DEFAULT_SKIP)->dict:
    root=Path(root); mapping={}; provenance={}
    for p in root.rglob('*.java'):
        rel=p.relative_to(root).as_posix(); obf=rel[:-5].replace('/','.')
        if obf.startswith(skip):continue
        try:text=p.read_text(errors='replace')
        except OSError:continue
        real=None; source=''
        m=DEBUG_RE.search(text)
        if m:
            real=m.group(1).split('$',1)[0]; source='DebugMetadata'
        if not real:
            m=META_D2_RE.search(text)
            if m:
                for cm in LCLASS_RE.finditer(m.group(1)):
                    cand=cm.group(1).replace('/','.').split('$',1)[0]
                    if '.' in cand and not cand.startswith(skip):real=cand;source='Metadata.d2';break
        if not real:
            m=RENAMED_RE.search(text)
            if m:real=m.group(1);source='jadx-renamed-comment'
        if real and real!=obf:
            mapping[obf]=real;provenance[obf]={"real":real,"source":source,"file":rel}
    return {"mapping":mapping,"provenance":provenance,"count":len(mapping)}


def write_mapping(result:dict,out:str|Path)->None:
    out=Path(out);out.mkdir(parents=True,exist_ok=True)
    (out/'mapping.json').write_text(json.dumps(result['mapping'],indent=2,sort_keys=True))
    (out/'provenance.json').write_text(json.dumps(result['provenance'],indent=2,sort_keys=True))
    lines=['obfuscated\trecovered\tsource\tfile']
    for k in sorted(result['mapping']):
        p=result['provenance'][k];lines.append(f"{k}\t{p['real']}\t{p['source']}\t{p['file']}")
    (out/'mapping.tsv').write_text('\n'.join(lines)+'\n')
