from __future__ import annotations

import json
import os
import re
from pathlib import Path

from ..categories import classify
from ..runner import Budget, run, which_any


NATIVE_DECL_RE = re.compile(
    r"(?P<mods>(?:public|private|protected|static|final|synchronized|native|\s)+)\s+"
    r"(?P<ret>[\w.$<>\[\]?]+)\s+(?P<name>[\w$]+)\s*\((?P<args>[^)]*)\)\s*;"
)
METHOD_RE = re.compile(
    r"(?P<mods>(?:public|private|protected|static|final|synchronized|native|abstract|\s)+)\s+"
    r"(?P<ret>[\w.$<>\[\]?]+)\s+(?P<name>[\w$]+)\s*\((?P<args>[^)]*)\)\s*(?:\{|throws)"
)
CLASS_RE = re.compile(r"\b(?:class|interface|enum)\s+([\w$]+)")


class JavaEngine:
    def __init__(self, *, budget: Budget, timeout: float = 120):
        self.jadx = which_any(["jadx"])
        self.budget = budget
        self.timeout = timeout

    def fast_dex_strings(self, dex_files: list[str]) -> list[dict]:
        findings: list[dict] = []
        strings_cmd = which_any(["strings"])
        if not strings_cmd:
            return findings
        for dex in dex_files:
            rr = run([strings_cmd, "-a", "-n", "5", dex], timeout=self.budget.clamp(15))
            for line in rr.stdout.splitlines():
                tags = classify(line)
                if tags:
                    findings.append({"kind": "dex-string", "dex": dex, "value": line[:1000], "tags": sorted(tags)})
        return findings

    def decompile(self, apks: list[str], out_dir: str | Path, *, threads: int = 0) -> Path | None:
        if not self.jadx or not apks:
            return None
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        argv = [self.jadx, "--no-res", "--deobf", "--show-bad-code", "-d", str(out)]
        if threads > 0:
            argv += ["--threads-count", str(threads)]
        argv += apks
        rr = run(argv, timeout=self.budget.clamp(self.timeout))
        (out / "_jadx.log").write_text(rr.stdout + "\n" + rr.stderr, errors="replace")
        return out if any(out.rglob("*.java")) else None

    def index_sources(self, root: str | Path) -> list[dict]:
        root = Path(root)
        findings: list[dict] = []
        for path in root.rglob("*.java"):
            try:
                text = path.read_text(errors="replace")
            except Exception:
                continue
            package = ""
            pm = re.search(r"^\s*package\s+([\w.]+);", text, re.M)
            if pm:
                package = pm.group(1)
            cm = CLASS_RE.search(text)
            cls = cm.group(1) if cm else path.stem
            fqcn = f"{package}.{cls}" if package else cls
            lines = text.splitlines()

            # Approximate source-method topology: declaration + brace-balanced body.
            # It is intentionally labelled approximate because Java overload resolution
            # requires a full compiler frontend.
            i = 0
            while i < len(lines):
                line = lines[i]
                mm = METHOD_RE.search(line)
                if not mm:
                    i += 1; continue
                start_line = i + 1
                depth = line.count("{") - line.count("}")
                body = [line]
                j = i + 1
                while j < len(lines) and depth > 0:
                    body.append(lines[j])
                    depth += lines[j].count("{") - lines[j].count("}")
                    j += 1
                body_text = "\n".join(body)
                tags = classify(body_text)
                calls = sorted(set(re.findall(r"\b([A-Za-z_$][\w$]*)\s*\(", body_text)) -
                               {"if","for","while","switch","catch","return","new","throw","synchronized"})
                strings = re.findall(r'"([^"\n]{3,300})"', body_text)[:100]
                findings.append({
                    "kind": "java-method", "class": fqcn, "method": mm.group("name"),
                    "return": mm.group("ret"), "args": mm.group("args"),
                    "file": str(path.relative_to(root)), "start_line": start_line,
                    "end_line": max(start_line, j), "calls": calls[:300], "strings": strings,
                    "tags": sorted(tags), "confidence": 0.65,
                })
                i = max(i + 1, j)

            for m in NATIVE_DECL_RE.finditer(text):
                findings.append({
                    "kind": "java-native-declaration", "class": fqcn,
                    "method": m.group("name"), "return": m.group("ret"), "args": m.group("args"),
                    "file": str(path.relative_to(root)), "line": text.count("\n", 0, m.start()) + 1,
                    "tags": sorted(classify(m.group(0)) | {"jni"}),
                })

            for lineno, line in enumerate(lines, 1):
                tags = classify(line)
                if not tags:
                    continue
                st = line.strip()
                if not st or st.startswith("import "):
                    continue
                findings.append({
                    "kind": "java-line", "class": fqcn, "file": str(path.relative_to(root)),
                    "line": lineno, "value": st[:1600], "tags": sorted(tags),
                })

            for m in re.finditer(r"System\.loadLibrary\(\s*\"([^\"]+)\"\s*\)", text):
                findings.append({
                    "kind": "load-library", "class": fqcn, "library": m.group(1),
                    "file": str(path.relative_to(root)), "line": text.count("\n", 0, m.start()) + 1,
                    "tags": ["jni", "loader"],
                })
        return findings

    @staticmethod
    def exported_jni_from_symbols(module_name: str, symbols) -> list[dict]:
        out = []
        for s in symbols:
            name = getattr(s, "name", "")
            if not name.startswith("Java_"):
                continue
            # JNI mangling is richer than this, but preserving the raw symbol avoids false certainty.
            out.append({
                "kind": "jni-export", "module": module_name, "symbol": name,
                "address": getattr(s, "address", 0), "tags": ["jni"],
            })
        return out
