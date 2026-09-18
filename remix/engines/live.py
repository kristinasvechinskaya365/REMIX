from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

from ..runner import Budget, run


DEFAULT_IMPORT_PATTERNS = [
    "RegisterNatives", "dlopen", "android_dlopen_ext", "dlsym",
    "connect", "send", "sendto", "recv", "recvfrom", "sendmsg", "recvmsg",
    "SSL_read", "SSL_write", "SSL_do_handshake", "SSL_set_custom_verify",
    "open", "openat", "fopen", "read", "write", "rename", "unlink", "stat",
    "ptrace", "prctl", "mprotect", "mmap",
]


def build_frida_script(patterns: list[str] | None = None, *, backtrace: bool = True, offset_hooks: list[dict] | None = None) -> str:
    pats = patterns or DEFAULT_IMPORT_PATTERNS
    pats_json = json.dumps(pats)
    offsets_json = json.dumps(offset_hooks or [])
    bt = "true" if backtrace else "false"
    return r'''"use strict";
const WANT = new Set(''' + pats_json + r''');
const OFFSET_HOOKS = ''' + offsets_json + r''';
const WITH_BT = ''' + bt + r''';
const hooked = new Set();

function emit(o) { try { send(o); } catch (_) {} }
function addr(x) { try { return x ? x.toString() : "0x0"; } catch (_) { return "?"; } }
function bt(ctx) {
  if (!WITH_BT) return [];
  try { return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 12).map(DebugSymbol.fromAddress).map(String); }
  catch (_) { return []; }
}
function globalExport(name) {
  try {
    if (Module.findGlobalExportByName) return Module.findGlobalExportByName(name);
    if (Module.getGlobalExportByName) return Module.getGlobalExportByName(name);
  } catch (_) {}
  try { return Module.findExportByName(null, name); } catch (_) {}
  return null;
}
function hookAddress(p, name, moduleName) {
  if (!p || p.isNull()) return;
  const key = p.toString() + ":" + name;
  if (hooked.has(key)) return;
  hooked.add(key);
  try {
    Interceptor.attach(p, {
      onEnter(args) {
        const av = [];
        for (let i = 0; i < 8; i++) { try { av.push(addr(args[i])); } catch (_) { av.push("?"); } }
        this._remix = {symbol:name, module:moduleName || ""};
        emit({event:"call", symbol:name, hook_module:moduleName || "", address:addr(p), args:av,
              return_address:addr(this.returnAddress), thread_id:this.threadId, backtrace:bt(this.context)});
      },
      onLeave(retval) {
        emit({event:"return", symbol:name, hook_module:moduleName || "", address:addr(p), retval:addr(retval), thread_id:this.threadId});
      }
    });
  } catch (e) { emit({event:"hook-error", symbol:name, address:addr(p), error:String(e)}); }
}
function hookGlobal(name) {
  try {
    const p = globalExport(name);
    if (p) hookAddress(p, name, "global");
  } catch (_) {}
}

function hookOffsets() {
  for (const h of OFFSET_HOOKS) {
    try {
      const m = Process.findModuleByName(h.module);
      if (!m) continue;
      const off = ptr(h.offset);
      const p = m.base.add(off);
      hookAddress(p, h.label || (h.module + "+" + h.offset), h.module);
      emit({event:"offset-hook", module:h.module, base:addr(m.base), offset:String(h.offset), address:addr(p), label:h.label || ""});
    } catch (e) { emit({event:"offset-hook-error", hook:h, error:String(e)}); }
  }
}

// Runtime module inventory gives the correlation layer real ASLR bases.
for (const m of Process.enumerateModules()) {
  emit({event:"module", name:m.name, path:m.path, base:addr(m.base), size:m.size});
  try {
    for (const imp of m.enumerateImports()) {
      if (WANT.has(imp.name) && imp.address) hookAddress(imp.address, imp.name, m.name);
    }
  } catch (_) {}
}
for (const n of WANT) hookGlobal(n);
hookOffsets();

// Native registration is higher value than guessing JNI_OnLoad tables statically.
try {
  const art = Process.getModuleByName("libart.so");
  for (const s of art.enumerateSymbols()) {
    if (s.name.indexOf("RegisterNatives") === -1 || s.name.indexOf("CheckJNI") !== -1) continue;
    if (hooked.has("RN:" + s.address)) continue;
    hooked.add("RN:" + s.address);
    Interceptor.attach(s.address, {
      onEnter(args) {
        const methods = args[2];
        const count = args[3].toInt32();
        const ps = Process.pointerSize;
        const rows = [];
        for (let i = 0; i < count && i < 1024; i++) {
          try {
            const e = methods.add(i * ps * 3);
            const np = e.readPointer();
            const sp = e.add(ps).readPointer();
            const fp = e.add(ps * 2).readPointer();
            const mod = Process.findModuleByAddress(fp);
            rows.push({name:np.readCString(), signature:sp.readCString(), function:addr(fp),
                       module:mod ? mod.name : "", module_base:mod ? addr(mod.base) : "0x0"});
          } catch (_) {}
        }
        let cls = "";
        try { const env = Java.vm.tryGetEnv(); if (env) cls = env.getClassName(args[1]); } catch (_) {}
        emit({event:"register-natives", class:cls, count:count, methods:rows, register_address:addr(s.address)});
      }
    });
    break;
  }
} catch (e) { emit({event:"register-natives-error", error:String(e)}); }

// Refresh imports after dlopen. This catches late protected/native payloads.
function lateRefresh(path) {
  setTimeout(function () {
    for (const m of Process.enumerateModules()) {
      emit({event:"module", name:m.name, path:m.path, base:addr(m.base), size:m.size, refresh:true});
      try {
        for (const imp of m.enumerateImports()) {
          if (WANT.has(imp.name) && imp.address) hookAddress(imp.address, imp.name, m.name);
        }
      } catch (_) {}
    }
    hookOffsets();
    emit({event:"module-refresh", trigger:path || ""});
  }, 25);
}
for (const dl of ["dlopen", "android_dlopen_ext"]) {
  try {
    const p = globalExport(dl);
    if (!p) continue;
    Interceptor.attach(p, {
      onEnter(args) { try { this.path = args[0].isNull() ? "" : args[0].readCString(); } catch (_) { this.path=""; } },
      onLeave(retval) { emit({event:"dlopen", api:dl, path:this.path, result:addr(retval)}); lateRefresh(this.path); }
    });
  } catch (_) {}
}

emit({event:"ready", pid:Process.id, arch:Process.arch, pointer_size:Process.pointerSize});
'''


class FridaEngine:
    def __init__(self, *, budget: Budget, lab_root: str | None = None):
        self.budget = budget
        self.lab_root = Path(lab_root or (Path.home() / "AndroidCTFMax"))

    def python_candidates(self) -> list[Path]:
        candidates = [
            self.lab_root / "venvs/frida-stock-17.18.0/bin/python",
            self.lab_root / "venvs/frida-phantom-17.16.4/bin/python",
            self.lab_root / "venvs/frida-florida-17.17.0/bin/python",
        ]
        # Also accept future lineages without hardcoding a version.
        candidates += sorted(self.lab_root.glob("venvs/frida-*/bin/python"), reverse=True)
        seen = set(); out = []
        for c in candidates:
            if c.exists() and str(c) not in seen:
                seen.add(str(c)); out.append(c)
        return out

    def pick_python(self, prefer: str = "stock") -> Path | None:
        candidates = self.python_candidates()
        if prefer:
            for c in candidates:
                if prefer in str(c):
                    return c
        return candidates[0] if candidates else None

    def capture(self, package: str, case_dir: str | Path, *, duration: float = 20,
                endpoint: str | None = None, spawn: bool = False, prefer: str = "stock",
                patterns: list[str] | None = None, offset_hooks: list[dict] | None = None) -> Path | None:
        py = self.pick_python(prefer)
        if not py:
            return None
        case_dir = Path(case_dir)
        live_dir = case_dir / "live-frida"
        live_dir.mkdir(parents=True, exist_ok=True)
        script = live_dir / "correlator.js"
        script.write_text(build_frida_script(patterns, offset_hooks=offset_hooks), encoding="utf-8")
        out = live_dir / "events.jsonl"
        helper = Path(__file__).resolve().parent.parent / "frida_capture.py"
        argv = [str(py), str(helper), "--package", package, "--script", str(script), "--out", str(out),
                "--duration", str(duration)]
        if endpoint:
            argv += ["--endpoint", endpoint]
        if spawn:
            argv += ["--spawn"]
        rr = run(argv, timeout=self.budget.clamp(duration + 15))
        (live_dir / "capture.log").write_text(rr.stdout + "\n" + rr.stderr, errors="replace")
        return out if out.exists() else None

    @staticmethod
    def read_events(path: str | Path) -> list[dict]:
        rows = []
        for line in Path(path).read_text(errors="replace").splitlines():
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
        return rows
