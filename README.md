# REMIX 2.1

REMIX is a CLI-only Android/ARM64 reverse-engineering correlation engine. It is intentionally **not** a collection of aliases around JADX, Rizin, Frida or Ghidra. Those engines contribute evidence to one normalized model so a native function can be queried once and show its offsets, symbols, callers/callees, all xrefs, strings, JNI bindings, imports, PLT/GOT slots, relocations, ARM64 control-flow profile, Java-side seams and runtime observations together.

The previous orchestration approach paid startup cost repeatedly and could finish with independent `jni`, `plt`, or hook logs that still had to be reconciled manually. REMIX instead performs bulk extraction once per ELF, correlates in-process, ranks functions, then spends expensive decompilation or live-hook time only on selected targets.

## Engines that feed the same evidence graph

- **Rizin**: bulk function discovery, global xrefs, strings, symbols, imports, relocations and sections in one analysis process per ELF; targeted `pdf`/`pdc`/ARM64/basic-block work only for ranked functions.
- **LIEF**: independent loader truth: `DT_NEEDED`, PIE/RELRO/NX/RWX segments, constructors/destructors, dynamic entries, dynamic symbols, demangled C++ names, RTTI/vtables, relocations and PLT/GOT slots.
- **JADX + raw DEX strings**: Java methods, native declarations, `System.loadLibrary`, semantic strings and conservative Java call edges.
- **Root `/proc`**: clean-process status, maps, threads, file descriptors, sockets, mount namespace, runtime module bases and suspicious executable-memory mappings without injecting anything.
- **Frida** (explicit only): `RegisterNatives`, module loads, exact `module+offset` hooks, imports/exports, arguments, return values and backtraces. Runtime pointers are normalized back to the static function records.
- **Ghidra headless** (optional): independent targeted second-opinion decompilation for only the highest-ranked offsets.

Evidence classes remain distinct. Root-only observations are not relabeled as instrumented results, and Frida observations are not treated as stock/clean-process facts.

## Install

```bash
cd REMIX
chmod +x INSTALL.command VERIFY.command
./VERIFY.command
./INSTALL.command
source ~/AndroidCTFMax/env.sh 2>/dev/null || true
rehash 2>/dev/null || true
remix doctor --serial emulator-5554
```

## One-line autonomous runs

Fast static + clean root runtime baseline:

```bash
remix analyze --package com.vcamor.vv --serial emulator-5554 --mode fast --budget 90 --jobs 4 --live-root
```

Full correlated static pass:

```bash
remix analyze --package com.vcamor.vv --serial emulator-5554 --mode full --budget 240 --jobs 4 --live-root --focus auth,jni,tls,integrity --ghidra-top 8
```

Full pass plus explicit dynamic correlation of the top ranked functions:

```bash
remix analyze --package com.vcamor.vv --serial emulator-5554 --mode full --budget 300 --jobs 4 --live-root --focus auth,jni,tls,integrity --instrument --trace-top 10 --instrument-duration 18 --frida-prefer stock
```

Exact offset instrumentation can be combined with semantic hooks:

```bash
remix analyze --package com.vcamor.vv --serial emulator-5554 --mode full --budget 300 --live-root --instrument --offset-hook 'libsecrets.so@0x42fdc:n8' --offset-hook 'libsecrets.so@0x435c8:n23' --hook RegisterNatives --hook SSL_write --hook connect
```

## Manual RE surface

All commands below query the **same case model** rather than launching separate analysis stacks:

```bash
remix query   --case ~/AndroidCTFMax/cases-remix/CASE --tag auth --tag jni --min-score 3 --limit 60
remix fn      --case ~/AndroidCTFMax/cases-remix/CASE --module libsecrets.so --offset 0x42fdc
remix refs    --case ~/AndroidCTFMax/cases-remix/CASE --module libsecrets.so --offset 0x42fdc --direction both --limit 200
remix symbols --case ~/AndroidCTFMax/cases-remix/CASE --module libsecrets.so --contains signer --limit 100
remix strings --case ~/AndroidCTFMax/cases-remix/CASE --module libsecrets.so --tag integrity --with-refs --limit 100
remix jni     --case ~/AndroidCTFMax/cases-remix/CASE --contains 'n8'
remix module  --case ~/AndroidCTFMax/cases-remix/CASE --module libsecrets.so --limit 40
remix graph   --case ~/AndroidCTFMax/cases-remix/CASE --module libsecrets.so --offset 0x42fdc --depth 4 --direction both
remix path    --case ~/AndroidCTFMax/cases-remix/CASE --module libsecrets.so --from 0x42fdc --to 0x435c8
remix trace   --case ~/AndroidCTFMax/cases-remix/CASE --serial emulator-5554 --duration 18 --offset-hook 'libsecrets.so@0x42fdc:n8' --hook RegisterNatives --hook SSL_write
remix diff    --left ~/AndroidCTFMax/cases-remix/CASE_A --right ~/AndroidCTFMax/cases-remix/CASE_B --verbose
```

A `fn` dossier includes:

```text
module / SHA-256
static VA / module-relative offset / runtime normalized address hits
function name + symbol aliases + demangled names
size / callers / callees
incoming + outgoing code/data/call/string/import xrefs
referenced strings + semantic keyword classes
imports reached from the function
PLT/GOT and relocation evidence
static exported JNI and dynamic RegisterNatives mappings
ARM64 instruction count + direct/indirect calls + branches + CFG complexity
PAC/AUT + BTI + SVC + ADRP + load/store/compare profile
dynamic calls/arguments/returns/backtraces when explicitly instrumented
Rizin pseudocode/disassembly when selected
Ghidra second-opinion evidence when requested
source + confidence annotations
```

## Topology and mechanism inference

REMIX emits more than a flat function list. It builds:

- native call edges;
- non-call code/data/string/import xrefs;
- approximate Java call edges, explicitly confidence-labeled;
- Java→native JNI edges from exported JNI names and observed `RegisterNatives`;
- import-call edges;
- constructor/destructor lifecycle anchors;
- PLT/GOT relocation topology;
- C++ RTTI/vtable candidates;
- semantic category subgraphs with probable roots, hubs and sinks;
- implementation fingerprints such as native TLS, POSIX networking, dynamic loading, filesystem state and JNI registration.

Semantic classes currently include `jni`, `loader`, `tls`, `network`, `crypto`, `integrity`, `antidebug`, `root`, `ipc`, `storage`, `auth`, and `camera`. A semantic tag is a ranking signal, not proof that the function implements the behavior.

## ARM64 specifics

For ranked functions REMIX records direct `bl`, indirect `blr`, `br`, conditional branches, returns, `svc`, PAC/AUT, BTI, ADRP, load/store and compare instructions. Basic-block edges provide an approximate cyclomatic-complexity signal. Bulk global xrefs remain the authoritative static relation source; the instruction profile is supporting evidence.

## Root runtime memory

A clean root snapshot records `/proc/<pid>/maps`, status, thread names, FDs, sockets and mountinfo. It also creates `live-root/memory_anomalies.json` for executable anonymous/memfd mappings, deleted mappings, W+X regions and executable code under unusual writable paths. This is useful for protected/custom loaders before choosing an instrumentation route.

## Runtime exact-offset loop

`--offset-hook MODULE@0xOFFSET[:label]` hooks `module.base + OFFSET` after ASLR is known. Late `dlopen` events refresh the module inventory and retry requested offset hooks. Call events capture pointer-valued arguments, return address and backtrace; return events capture the return value. These hits are then mapped back into the same static function dossier.

`--trace-top N` closes the automatic loop:

```text
bulk static index
  → correlate xrefs/JNI/strings/imports
  → semantic rank
  → select N functions
  → exact module+offset runtime hooks
  → ASLR-normalize hits/backtraces
  → enrich original function dossiers
```

## Performance model

- `fast`: Rizin `aa`, raw DEX semantic strings and optional clean root runtime map; no default decompilation.
- `balanced`: fast index + six targeted high-value function dossiers.
- `full`: deeper Rizin analysis + JADX semantic source index + sixteen targeted dossiers.
- `deep`: deeper analysis + thirty-two targeted dossiers.

Native bulk results are cached by SHA-256 + REMIX version + mode under `~/.cache/remix/`. Unchanged libraries are not re-analyzed on subsequent cases.

`--budget N` bounds subprocess stage timeouts and prevents new expensive stages from starting once the budget is exhausted. Parallel workers already in flight can finish or hit their individually clamped timeout, so the budget is a practical wall-time bound rather than a claim of single-millisecond hard scheduling.

## Case artifacts

```text
REPORT.md          ranked human report + mechanism/flow/module topology
case.json          complete normalized evidence model
case.sqlite        functions, strings, symbols, imports, JNI, xrefs, relocations, Java and edges
functions.jsonl    one function dossier per line
topology.dot       native call/JNI topology
artifact/          acquired APK/DEX/native inputs
java/              JADX output when enabled
live-root/         clean root observation
live-frida/        explicit instrumented observations
```

Useful SQL examples:

```bash
sqlite3 case.sqlite 'select module,printf("0x%x",offset),name,score,tags from functions order by score desc limit 50;'
sqlite3 case.sqlite 'select module,printf("0x%x",src_function),type,to_symbol,to_import,to_string from xrefs where to_string like "%token%";'
sqlite3 case.sqlite 'select module,name,demangled,printf("0x%x",address),type from symbols where name like "%JNI%" or demangled like "%verify%";'
sqlite3 case.sqlite 'select module,java_class,java_method,signature,printf("0x%x",native_offset),source from jni;'
```

## CI and scope

GitHub Actions validates syntax, unit tests and CLI smoke on Ubuntu and macOS with Python 3.11 and 3.13. Hosted CI cannot reproduce the KernelSU Android 16 AVD, so root/ADB/Frida route qualification remains an on-lab check.

No RE framework can truthfully guarantee that every obfuscated/virtualized/self-modifying target will be recovered without ambiguity. REMIX therefore records source and confidence, keeps conflicting engine evidence instead of hiding it, uses bounded fallbacks, and exposes raw addresses/xrefs so uncertain results can be checked manually.
