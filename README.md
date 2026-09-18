# REMIX 3

REMIX is a CLI-only reverse-engineering control plane for Android and ARM64/native targets. It keeps a single evidence model across static analysis, Android/Dex analysis, runtime observation, cross-engine validation, graph slicing, and binary matching.

The core design rule is **route first, analyze second, validate third**. REMIX does not blindly run every installed tool. Cheap fingerprinting determines the target shape, selectors reduce the search space, expensive engines only receive high-value functions, and independent engine families are tracked separately when calculating consensus.

## What V3 adds

V3 keeps all V2.1 commands (`doctor`, `analyze`, `fn`, `query`, `graph`, `module`, `refs`, `symbols`, `strings`, `jni`, `path`, `trace`, `diff`) and adds:

- `fingerprint` — fast pre-decompile routing for APK/XAPK/DEX structure, frameworks, HTTP stacks, DI/serialization, native ABIs, split APKs, obfuscation signals and protection signals.
- `engines` — capability registry and availability/version discovery for static, dynamic, symbolic, emulation, Android and decompiler backends.
- `select` — safe expression language over the function evidence model.
- `slice` — caller/callee/xref neighborhood extraction with semantic filtering.
- `validate` — independent-family function validation and weighted consensus.
- `flow` — composable named datasets: select → filter → expand → enrich → validate → consensus → scan → external → assert → emit.
- `auto` — bounded autonomous high-signal plan generated from the available local engines.
- `decompile` — controlled jadx/Vineflower dual-decompiler lane.
- `kotlin-names` — Kotlin metadata-assisted recovery of useful names in R8-heavy source output.
- `sig` / `match` — fuzzy function signatures for cross-version matching when names/addresses move.
- `recipe` — reusable deep-analysis plans.

No GUI is required.

## Install

```bash
cd REMIX
chmod +x VERIFY.command INSTALL.command
./VERIFY.command
./INSTALL.command

remix --version
remix engines --available
```

## Fast autonomous run

```bash
remix auto \
  --package com.example.target \
  --serial emulator-5554 \
  --mode balanced \
  --analysis-budget 90 \
  --budget 240 \
  --jobs 4
```

For an APK without a live device:

```bash
remix auto \
  --apk ./target.apk \
  --mode full \
  --analysis-budget 120 \
  --budget 300 \
  --deep-validators
```

`--deep-validators` enables expensive validators such as angr only when they are actually installed.

## Phase-0 fingerprinting

```bash
remix fingerprint --apk ./target.apk
remix fingerprint --apk ./target.apk --json > fingerprint.json
```

The router looks for framework markers (native Java/Kotlin, Compose, Flutter, React Native/Hermes, Cordova/Capacitor, Xamarin/.NET, Unity), network stacks (OkHttp, Retrofit, Ktor, Apollo, Volley, Cronet/HttpEngine, gRPC, WebView), DI/serialization signals, native libraries and ABIs, split APKs, protection markers and a bounded obfuscation heuristic. If APKiD is present it is used as an additional independent packer/compiler/protector source.

## Function selector language

Selectors work against the normalized function model, not raw grep output:

```bash
remix select --case CASE --where 'tag:crypto AND score>=6'
remix select --case CASE --where 'name~verify AND arm64.indirect_call>0'
remix select --case CASE --where '(tag:integrity OR tag:antidebug) AND size>32'
remix select --case CASE --where 'imports~SSL_ AND NOT tag:storage' --json
```

Fields include `score`, `size`, `offset`, `address`, `name`, `module`, `tags`, `imports`, `symbols`, `jni`, `callers`, `callees`, `strings`, `dynamic_hits`, `evidence_count`, and `arm64.<metric>`.

## Slice a topology

```bash
remix slice \
  --case CASE \
  --where 'tag:jni OR tag:loader' \
  --direction both \
  --depth 2 \
  --filter 'score>=2' \
  --limit 300
```

This keeps native calls and non-call xref neighborhoods useful for stripped ARM64 code, where tables, GOT entries, strings and function pointers often matter more than exported names.

## Cross-engine validation

```bash
remix validate \
  --case CASE \
  --where 'tag:integrity AND score>=5' \
  --engine rizin \
  --engine lief \
  --engine radare2 \
  --engine ghidra \
  --engine angr \
  --limit 12 \
  --policy weighted \
  --json
```

REMIX records engine families as well as engine names. Agreement from unrelated analysis families is weighted more strongly than several outputs derived from the same parser lineage. Missing optional engines are explicit; they are never counted as evidence.

## Composable flows

A flow operates on named datasets. Each stage can consume the result of an earlier stage.

```bash
remix flow \
  --case CASE \
  --step 'id=hot;op=select;where=tag:crypto AND score>=6;limit=40' \
  --step 'id=near;op=expand;from=hot;direction=both;depth=1;limit=120' \
  --step 'id=rz;op=enrich;engine=rizin;from=near;limit=32' \
  --step 'id=check;op=validate;from=hot;engines=rizin,lief,radare2,ghidra;limit=20' \
  --step 'id=vote;op=consensus;from=check;policy=weighted' \
  --step 'id=strong;op=filter;from=vote;criteria={"score":{"gte":0.75}}' \
  --step 'id=out;op=emit;from=strong;format=json'
```

For complex flows, use a JSON plan:

```bash
remix flow --case CASE --plan examples/flows/consensus.json
```

### Feeding one tool's result into another

`external` stages accept an argv array, never an interpolated shell command. They can run once per selected function and support `${module_path}`, `${offset}`, `${address}`, `${end}`, `${size}`, `${name}`, `${case}`, `${out}` placeholders.

Example plan fragment:

```json
{
  "id": "objdump",
  "op": "external",
  "from": "hot",
  "foreach": true,
  "argv": ["llvm-objdump", "-d", "--start-address=${address}", "--stop-address=${end}", "${module_path}"],
  "parser": "text",
  "timeout": 15
}
```

The returned records can then be filtered, projected, asserted, emitted, or passed into another external stage. Every stage records elapsed time, input/output cardinality, engine version/family where known, and errors in `flow/flow.json`.

## Recipes

```bash
remix recipe list
remix recipe show native-hard

remix flow --case CASE --recipe native-hard
remix flow --case CASE --recipe jni-bridge
remix flow --case CASE --recipe network-tls
remix flow --case CASE --recipe integrity-antidebug
remix flow --case CASE --recipe deep-consensus
```

## Dual decompiler and Kotlin recovery

```bash
remix decompile ./target.apk --out ./dec --engine both --threads 4
remix kotlin-names --sources ./dec/jadx/sources --out ./dec/kotlin-names
```

The dual lane is explicit: jadx remains the Android-first decompiler; Vineflower is a second opinion for JVM output when available. APK/DEX → Vineflower requires dex2jar.

## Function signatures and cross-build matching

```bash
remix sig \
  --case OLD_CASE \
  --where 'tag:crypto AND score>=6' \
  --limit 1 \
  --out crypto-worker.json

remix match \
  --signature crypto-worker.json \
  --case NEW_CASE \
  --threshold 0.70
```

Signatures intentionally avoid raw address/name dependence. They combine size, graph degree, semantic tags, imported APIs, normalized referenced strings and ARM64 instruction profile.

## Engine model

```bash
remix engines --available --verbose
remix engines --capability symbolic
remix engines --capability decompile
remix engines --capability runtime
```

The registry knows about Rizin, radare2, Ghidra headless, LIEF, Capstone, Unicorn, angr, Qiling, Triton, Miasm, Z3, Keystone, jadx, Vineflower, dex2jar, apktool, baksmali, APKiD, Androguard, capa, FLOSS, Frida, r2frida, LLVM tools, RetDec and framework-specific helpers. Registry presence is not equivalent to installation: `engines` reports the actual local state.

REMIX does not vendor these projects. Optional third-party engines retain their own licenses and are invoked only when present.

## Evidence discipline

REMIX distinguishes:

- static evidence,
- clean/root-observed runtime evidence,
- instrumented runtime evidence,
- decompiler-derived approximations,
- cross-engine validation.

An instrumented observation is not silently promoted to clean behavior. An unavailable engine is not a failed target. A heuristic fingerprint is not represented as proof. Cross-engine conflicts are retained in the result instead of being averaged away.

## Outputs

A case can contain:

```text
case.json              normalized full evidence model
case.sqlite            queryable index
functions.jsonl        one dossier per function
topology.dot           graph export
REPORT.md              human summary
artifact/              acquired inputs
live-root/             clean root observation
live-frida/            explicit instrumented evidence
flow/flow.json         pipeline provenance
flow/*.json            named flow outputs
ghidra/                targeted headless enrichment
```

See `docs/ARCHITECTURE.md` for the V3 control-plane design.
