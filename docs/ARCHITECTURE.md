# REMIX V3 architecture

## 1. Analysis routing

V3 uses a cheap fingerprint stage before expensive work. Framework, transport, obfuscation, native-code and protection markers determine which analysis lanes are relevant. This prevents Java decompilation from dominating targets whose useful code lives in native AOT, managed assemblies, JavaScript bundles, or protected runtime mappings.

## 2. Normalized evidence graph

The stable center remains `AnalysisCase` + `ModuleAnalysis` + `FunctionNode`. Backends contribute observations to that model rather than becoming the user interface themselves. Function identities are normalized as `module + static offset`; runtime PCs are converted through the observed mapping base.

## 3. Dataset control plane

A V3 flow is a DAG-like sequence of named datasets. Built-in operations are:

- `select`: selector expression over normalized functions.
- `filter`: criteria over generic result records.
- `expand`: callers/callees/xrefs neighborhood.
- `enrich`: targeted Rizin or Ghidra analysis.
- `validate`: independent engine observations.
- `consensus`: confidence/family-aware agreement and conflict ledger.
- `scan`: module-level capability/string/protector scanners.
- `signature`: address-independent function fingerprints.
- `external`: safe argv-based custom adapter with structured placeholders.
- `project`: field extraction.
- `assert`: fail a flow when evidence requirements are not met.
- `emit`: JSON/JSONL/text artifact.

No `shell=True` path exists in the external operator.

## 4. Cost model

Bulk cheap extractors run first. Expensive work is targeted:

1. fingerprint / archive inventory,
2. bulk native/Dex topology,
3. rank/select,
4. graph slice,
5. targeted decompile/disassembly,
6. independent validation,
7. optional symbolic/emulation/runtime work.

This design avoids one process per xref/function and avoids symbolic execution across an entire application when only a small gate or transform matters.

## 5. Validation

Engine outputs are tagged with an `independent_family`. Consensus includes:

- per-claim agreement,
- per-claim conflicts,
- engine confidence,
- family diversity,
- evidence coverage.

Rizin and radare2 are still separate implementations for practical cross-checking, but family metadata prevents raw engine count from being treated as mathematical independence. Format parsers such as LIEF validate loader/relocation facts rather than pretending to be function-boundary engines.

## 6. Extension contract

New engines should expose one or more capabilities in `registry.py` and add a narrow adapter only for evidence they can actually support. A backend should not be used to produce claims outside its domain simply to increase an apparent consensus score.
