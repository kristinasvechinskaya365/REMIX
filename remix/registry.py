from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True, slots=True)
class EngineSpec:
    name: str
    capabilities: tuple[str, ...]
    executables: tuple[str, ...] = ()
    python_modules: tuple[str, ...] = ()
    formats: tuple[str, ...] = ()
    cost: int = 1                 # 1=cheap ... 5=expensive
    confidence: float = 0.7       # default evidence weight
    intrusive: bool = False
    independent_family: str = ""
    description: str = ""
    version_args: tuple[str, ...] = ("--version",)


@dataclass(slots=True)
class EngineStatus:
    spec: EngineSpec
    available: bool
    executable: str | None = None
    python_module: str | None = None
    version: str = ""
    reason: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["spec"] = asdict(self.spec)
        return d


# Registry intentionally contains engines REMIX can either use directly today or
# route to through its generic flow runner. The registry is discovery, not a claim
# that every optional tool is installed.
ENGINE_SPECS: tuple[EngineSpec, ...] = (
    EngineSpec("rizin", ("elf","functions","xrefs","strings","imports","symbols","relocs","cfg","pseudocode"),
               ("rizin",), formats=("elf","mach-o","pe"), cost=2, confidence=.84, independent_family="rizin", description="Primary bulk static extractor"),
    EngineSpec("radare2", ("elf","functions","xrefs","strings","imports","symbols","relocs","cfg","esil","debug"),
               ("r2", "radare2"), formats=("elf","mach-o","pe"), cost=2, confidence=.78, independent_family="radare", description="Independent static/debugger cross-check and ESIL backend"),
    EngineSpec("ghidra", ("functions","xrefs","decompile","types","callgraph","pcode","function-id"),
               ("analyzeHeadless",), formats=("elf","dex","pe","mach-o"), cost=4, confidence=.94, independent_family="ghidra", description="Headless second-opinion decompiler/type engine"),
    EngineSpec("lief", ("elf","headers","symbols","relocs","plt","got","android-packed-relocs"),
               python_modules=("lief",), formats=("elf","pe","mach-o"), cost=1, confidence=.92, independent_family="lief", description="Binary-format truth source"),
    EngineSpec("capstone", ("disasm","arm64","instruction-profile"), python_modules=("capstone",), formats=("raw","elf"), cost=1, confidence=.90, independent_family="capstone"),
    EngineSpec("unicorn", ("emulate","arm64","memory-hooks","code-hooks"), python_modules=("unicorn",), formats=("raw","elf"), cost=3, confidence=.86, independent_family="unicorn"),
    EngineSpec("angr", ("cfg","callgraph","symbolic","reaching-definitions","dataflow","vex"), python_modules=("angr",), formats=("elf","pe"), cost=5, confidence=.93, independent_family="angr", description="Targeted symbolic/data-flow validator"),
    EngineSpec("qiling", ("emulate","syscalls","arm64","android","hooks"), python_modules=("qiling",), formats=("elf","pe","mach-o"), cost=5, confidence=.88, independent_family="qiling"),
    EngineSpec("jadx", ("dex","java","resources","decompile","callflow"), ("jadx",), formats=("apk","dex"), cost=3, confidence=.86, independent_family="jadx"),
    EngineSpec("vineflower", ("jvm","decompile","cross-check"), ("vineflower",), formats=("jar","class"), cost=3, confidence=.88, independent_family="vineflower"),
    EngineSpec("apktool", ("apk","manifest","resources","smali"), ("apktool",), formats=("apk",), cost=2, confidence=.92, independent_family="apktool"),
    EngineSpec("apkid", ("apk","packer","protector","compiler","obfuscator","rasp"), ("apkid",), python_modules=("apkid",), formats=("apk","dex","elf"), cost=1, confidence=.90, independent_family="apkid"),
    EngineSpec("androguard", ("dex","classes","methods","xrefs","callgraph","manifest"), python_modules=("androguard",), formats=("apk","dex"), cost=3, confidence=.91, independent_family="androguard"),
    EngineSpec("capa", ("capabilities","rules","behavior-tags"), ("capa",), python_modules=("capa",), formats=("elf","pe","raw"), cost=3, confidence=.86, independent_family="capa"),
    EngineSpec("floss", ("strings","stack-strings","decoded-strings","tight-strings"), ("floss",), formats=("elf","pe"), cost=3, confidence=.88, independent_family="floss"),
    EngineSpec("frida", ("runtime","hooks","jni","modules","memory","backtrace"), ("frida",), python_modules=("frida",), formats=("process",), cost=3, confidence=.96, intrusive=True, independent_family="frida"),
    EngineSpec("r2frida", ("runtime","hooks","memory","static-runtime-namespace"), ("r2",), formats=("process",), cost=3, confidence=.94, intrusive=True, independent_family="frida", description="radare2 + Frida integration when plugin is present"),
    EngineSpec("llvm-readelf", ("elf","headers","sections","symbols","relocs"), ("llvm-readelf", "readelf"), formats=("elf",), cost=1, confidence=.90, independent_family="llvm"),
    EngineSpec("llvm-nm", ("symbols","demangle"), ("llvm-nm", "nm"), formats=("elf","mach-o"), cost=1, confidence=.88, independent_family="llvm"),
    EngineSpec("objdump", ("disasm","relocs","symbols"), ("llvm-objdump", "objdump"), formats=("elf","mach-o","pe"), cost=2, confidence=.84, independent_family="llvm"),
    EngineSpec("strings", ("strings",), ("strings",), formats=("any",), cost=1, confidence=.55, independent_family="binutils"),
    EngineSpec("triton", ("symbolic","taint","concolic","arm64"), python_modules=("triton",), formats=("raw","elf"), cost=5, confidence=.90, independent_family="triton"),
    EngineSpec("miasm", ("disasm","ir","symbolic","dataflow"), python_modules=("miasm",), formats=("elf","raw"), cost=4, confidence=.88, independent_family="miasm"),
    EngineSpec("z3", ("smt","constraints"), python_modules=("z3",), formats=("ir",), cost=4, confidence=.95, independent_family="z3"),
    EngineSpec("keystone", ("assemble","arm64"), python_modules=("keystone",), formats=("asm",), cost=1, confidence=.90, independent_family="keystone"),
    EngineSpec("dex2jar", ("dex","jar","translation"), ("d2j-dex2jar", "d2j-dex2jar.sh"), formats=("apk","dex"), cost=2, confidence=.80, independent_family="dex2jar"),
    EngineSpec("baksmali", ("dex","smali","disasm"), ("baksmali",), formats=("dex","apk"), cost=2, confidence=.90, independent_family="smali"),
    EngineSpec("aapt2", ("apk","manifest","resources"), ("aapt2",), formats=("apk",), cost=1, confidence=.92, independent_family="android-sdk"),
    EngineSpec("apksigner", ("apk","signer","certificates"), ("apksigner",), formats=("apk",), cost=1, confidence=.98, independent_family="android-sdk"),
    EngineSpec("retdec", ("decompile","cfg","ir"), ("retdec-decompiler",), formats=("elf","pe"), cost=5, confidence=.86, independent_family="retdec"),
    EngineSpec("blutter", ("flutter","dart-aot","symbols"), ("blutter",), formats=("elf","apk"), cost=4, confidence=.84, independent_family="blutter"),
)


def _find_ghidra() -> str | None:
    direct = shutil.which("analyzeHeadless")
    if direct:
        return direct
    roots = [Path("/Applications"), Path.home()/"Applications", Path.home()/"ghidra", Path("/opt")]
    hits: list[Path] = []
    for root in roots:
        if root.exists():
            try:
                hits.extend(root.glob("**/support/analyzeHeadless"))
            except OSError:
                pass
    return str(sorted(hits)[-1]) if hits else None


def _r2frida_present(r2: str | None) -> bool:
    if not r2:
        return False
    try:
        cp = subprocess.run([r2, "-N", "-q0", "-c", "L"], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=4)
        return "frida" in cp.stdout.lower()
    except Exception:
        return False


def _version(exe: str, args: Iterable[str]) -> str:
    try:
        cp = subprocess.run([exe, *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=4)
        text = re.sub(r"\s+", " ", cp.stdout).strip()
        return text[:240]
    except Exception:
        return ""


def discover_engines(*, with_versions: bool = True) -> list[EngineStatus]:
    out: list[EngineStatus] = []
    for spec in ENGINE_SPECS:
        exe = None
        pymod = None
        if spec.name == "ghidra":
            exe = _find_ghidra()
        else:
            for x in spec.executables:
                exe = shutil.which(x)
                if exe:
                    break
        for mod in spec.python_modules:
            try:
                if importlib.util.find_spec(mod) is not None:
                    pymod = mod
                    break
            except (ImportError, ValueError):
                pass
        available = bool(exe or pymod)
        reason = ""
        if spec.name == "r2frida":
            available = _r2frida_present(exe)
            reason = "r2frida plugin not detected" if not available else ""
        elif not available:
            reason = "no executable or Python module found"
        ver = _version(exe, spec.version_args) if (with_versions and exe and available) else ""
        out.append(EngineStatus(spec, available, exe, pymod, ver, reason))
    return out


def engine_map(*, with_versions: bool = False) -> dict[str, EngineStatus]:
    return {s.spec.name: s for s in discover_engines(with_versions=with_versions)}


def engine_json(*, with_versions: bool = True) -> str:
    return json.dumps([x.to_dict() for x in discover_engines(with_versions=with_versions)], indent=2, sort_keys=True)
