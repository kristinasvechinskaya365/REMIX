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
remix analyze --package targetpackage --serial emulator-5554 --mode fast --budget 90 --live-root
```

Full correlated pass, still bounded:

```bash
remix analyze --package targetpackage--serial emulator-5554 --mode full --budget 240 --jobs 4 --live-root --focus auth,jni,tls,integrity --ghidra-top 8
```

Explicit instrumented pass (kept separate from the root baseline):

```bash
remix analyze --package targetpackage --serial emulator-5554 --mode full --budget 300 --live-root --instrument --instrument-duration 18 --frida-prefer stock --focus auth,jni,tls
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

A `fn` dossier includes:

- static address and module-relative offset;
- recovered function/symbol names;
- callers and callees;
- referenced strings and semantic tags;
- imported functions reached through PLT/GOT/import xrefs;
- static/dynamic JNI mappings;
- targeted ARM64 instruction profile (direct/indirect calls, branches, PAC/AUT, BTI, SVC, ADRP, loads/stores, compares);
- correlated runtime hits and backtraces;
- targeted Rizin pseudocode/disassembly;
- optional Ghidra consensus evidence.

## Performance model

REMIX has four modes:

- `fast`: `aa` bulk native index, DEX strings, root runtime map; no default pseudocode.
- `balanced`: fast index plus six high-value targeted function dossiers.
- `full`: deeper Rizin analysis + JADX semantic source index + sixteen targeted dossiers.
- `deep`: deeper analysis + thirty-two targeted dossiers; intended for bounded hard cases.

`--budget N` is a hard overall wall-clock budget. Per-stage timeouts are clamped to the remaining total budget. Expensive engines stop rather than silently running forever.

Native analysis is cached by SHA-256 + REMIX version + analysis mode under `~/.cache/remix/`. Repeating an unchanged APK/ELF therefore avoids re-running bulk Rizin analysis.

## Evidence model

Each native function is normalized into one record with:

```text
module
address
module-relative offset
name / symbols
size
callers / callees
string xrefs
imports / PLT-GOT relationships
JNI mappings
semantic tags + score
ARM64 profile
dynamic observations
pseudocode / disassembly
source evidence + confidence
```

Semantic categories currently include `jni`, `loader`, `tls`, `network`, `crypto`, `integrity`, `antidebug`, `root`, `ipc`, `storage`, `auth`, and `camera`.

The score is a ranking aid, not a claim that a function implements a behavior. Dynamic observations carry higher weight; symbol/import/string-derived tags remain evidence with lower confidence.

## Case artifacts

Each case contains:

```text
REPORT.md          human-readable ranked report
case.json          complete normalized model
case.sqlite        queryable functions/strings/imports/JNI/edges
functions.jsonl    one function dossier per line
topology.dot       call/JNI graph
artifact/          APK/DEX/native inputs
java/              JADX output when enabled
live-root/         non-instrumented process snapshot
live-frida/        explicitly instrumented events
```

Example SQLite query:

```bash
sqlite3 case.sqlite '
select module, printf("0x%x",offset), name, score, tags
from functions
where tags like "%tls%" or tags like "%auth%"
order by score desc
limit 40;
'
```

## Runtime tracing

`remix trace` does not emit orphan ASLR pointers. It first uses the case's `/proc/<pid>/maps` module bases, then translates runtime return addresses/function pointers into module-relative offsets and back into the static function index.

The built-in Frida capture engine observes selected imports/exports, module loading and `RegisterNatives`. It uses the Frida Python environments already present under `~/AndroidCTFMax/venvs/frida-*`, rather than assuming whichever global `frida` happens to be first in `PATH`.

Instrumentation is explicit because some targets detect Frida/Gadget/ptrace/thread/listener artifacts. A root-only baseline should remain authoritative for clean-process claims.

## Ghidra headless

`--ghidra-top N` runs the shipped `RemixFunctionDossier.java` only for the top-ranked offsets after Rizin/JNI/string/import correlation. It does not headlessly decompile every function in every library. Ghidra's headless analyzer is therefore a targeted independent confirmation engine rather than the primary bottleneck.

## CI

GitHub Actions runs syntax, unit tests and CLI smoke tests on Linux and macOS with Python 3.11 and 3.13. Device/root/instrumentation qualification remains a lab test because hosted Actions runners do not reproduce a KernelSU Android 16 AVD.
