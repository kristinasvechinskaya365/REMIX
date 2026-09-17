# REMIX 2

REMIX is a CLI-only Android/ARM64 reverse-engineering correlation engine. It is not a command alias around JADX/Rizin/Frida: it normalizes their results into one function-level evidence model and produces queryable function dossiers, call/xref topology, JNI mappings, PLT/GOT/import relationships, string references, runtime ASLR mappings, and optional dynamic observations.

## Core idea

A fast run does bulk extraction once per ELF, correlates everything in Python, ranks functions semantically, and only then performs targeted pseudocode/disassembly. This avoids the slow pattern of running one external process per function or per xref.

Data sources:

- Rizin: functions, global xrefs, strings, imports, symbols, relocations, sections, targeted disassembly/pseudocode.
- LIEF: independent ELF parser and PLT/GOT relocation/symbol validation.
- JADX/DEX: Java classes, native declarations, loadLibrary points, method bodies, semantic strings, approximate method call topology.
- Root `/proc`: maps, threads, status, sockets, FDs, mount namespace, runtime module bases without instrumentation.
- Optional Frida: RegisterNatives, module loads, selected imported/exported calls, TLS/socket/file/anti-debug events, with return addresses mapped back to static functions.
- Optional Ghidra headless: second-opinion decompilation/caller/callee evidence for only the highest-ranked functions.

Outputs are evidence-class aware: root-only observations and Frida-instrumented observations remain distinct.

## Install

```bash
cd REMIX
chmod +x INSTALL.command
./INSTALL.command
~/AndroidCTFMax/bin/remix doctor --serial emulator-5554
```

## One-line autonomous run

Fast bounded pass:

```bash
remix analyze --package com.vcamor.vv --serial emulator-5554 --mode fast --budget 90 --live-root
```

Full correlated pass, still bounded:

```bash
remix analyze --package com.vcamor.vv --serial emulator-5554 --mode full --budget 240 --jobs 4 --live-root --focus auth,jni,tls,integrity --ghidra-top 8
```

Explicit instrumented pass (kept separate from the root baseline):

```bash
remix analyze --package com.vcamor.vv --serial emulator-5554 --mode full --budget 300 --live-root --instrument --instrument-duration 18 --frida-prefer stock --focus auth,jni,tls
```

## Manual function workflow

```bash
remix query --case ~/AndroidCTFMax/cases-remix/CASE --tag auth --tag jni --min-score 3 --limit 40
remix fn --case ~/AndroidCTFMax/cases-remix/CASE --module libsecrets.so --offset 0x42fdc
remix fn --case ~/AndroidCTFMax/cases-remix/CASE --module libsecrets.so --symbol n23 --json
remix graph --case ~/AndroidCTFMax/cases-remix/CASE --module libsecrets.so --offset 0x42fdc --depth 3 --direction both
remix trace --case ~/AndroidCTFMax/cases-remix/CASE --serial emulator-5554 --duration 18 --hook RegisterNatives --hook SSL_write --hook connect
remix diff --left ~/AndroidCTFMax/cases-remix/CASE_A --right ~/AndroidCTFMax/cases-remix/CASE_B --verbose
```

A `fn` dossier includes static address and module-relative offset, recovered symbols, callers/callees, strings, imports/PLT-GOT relationships, static/dynamic JNI mappings, ARM64 instruction profile, runtime hits/backtraces, targeted Rizin pseudocode/disassembly, and optional Ghidra consensus evidence.

## Performance model

- `fast`: bulk native index, DEX strings, root runtime map; no default pseudocode.
- `balanced`: fast index plus six high-value targeted function dossiers.
- `full`: deeper Rizin analysis + JADX semantic source index + sixteen targeted dossiers.
- `deep`: deeper analysis + thirty-two targeted dossiers.

`--budget N` is a hard overall wall-clock budget. Native analysis is cached by SHA-256 + REMIX version + analysis mode under `~/.cache/remix/`.

## Case artifacts

Each case contains `REPORT.md`, `case.json`, `case.sqlite`, `functions.jsonl`, `topology.dot`, `artifact/`, optional `java/`, `live-root/`, and `live-frida/`.

## Runtime tracing

`remix trace` uses `/proc/<pid>/maps` to translate runtime return addresses/function pointers into module-relative offsets and back into the static function index. The built-in Frida capture engine uses the matching Python environments under `~/AndroidCTFMax/venvs/frida-*` rather than whichever global `frida` happens to be first in `PATH`.

Instrumentation is explicit because some targets detect Frida/Gadget/ptrace/thread/listener artifacts. A root-only baseline should remain authoritative for clean-process claims.

## Ghidra headless

`--ghidra-top N` runs the shipped `RemixFunctionDossier.java` only for the top-ranked offsets after Rizin/JNI/string/import correlation.

## CI

GitHub Actions runs syntax, unit tests and CLI smoke tests on Linux and macOS with Python 3.11 and 3.13. Device/root/instrumentation qualification remains a lab test because hosted Actions runners do not reproduce a KernelSU Android 16 AVD.
