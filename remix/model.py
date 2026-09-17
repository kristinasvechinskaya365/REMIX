from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class Evidence:
    source: str
    kind: str
    value: Any
    confidence: float = 1.0
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class StringRef:
    address: int
    value: str
    section: str = ""
    length: int = 0
    refs_from: list[int] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ImportRef:
    name: str
    address: int | None = None
    plt: int | None = None
    got: int | None = None
    library: str = ""
    refs_from: list[int] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SymbolRef:
    name: str
    address: int
    size: int = 0
    bind: str = ""
    type: str = ""
    imported: bool = False
    exported: bool = False


@dataclass(slots=True)
class FunctionNode:
    module: str
    address: int
    offset: int
    name: str
    size: int = 0
    end: int = 0
    callers: list[int] = field(default_factory=list)
    callees: list[int] = field(default_factory=list)
    string_refs: list[int] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)
    jni_methods: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    score: float = 0.0
    pseudocode: str = ""
    disasm: str = ""
    dynamic_hits: list[dict[str, Any]] = field(default_factory=list)
    arm64_profile: dict[str, Any] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["address_hex"] = hex(self.address)
        d["offset_hex"] = hex(self.offset)
        if self.end:
            d["end_hex"] = hex(self.end)
        return d


@dataclass(slots=True)
class JNIMapping:
    java_class: str
    java_method: str
    signature: str
    module: str
    native_address: int | None = None
    native_offset: int | None = None
    native_symbol: str = ""
    source: str = ""
    confidence: float = 1.0

    @property
    def java_fqmn(self) -> str:
        return f"{self.java_class}->{self.java_method}{self.signature}"


@dataclass(slots=True)
class DynamicModule:
    name: str
    path: str
    base: int
    end: int
    perms: str = ""


@dataclass(slots=True)
class ModuleAnalysis:
    path: str
    name: str
    sha256: str
    arch: str = ""
    bits: int = 0
    image_base: int = 0
    entry: int = 0
    functions: list[FunctionNode] = field(default_factory=list)
    strings: list[StringRef] = field(default_factory=list)
    imports: list[ImportRef] = field(default_factory=list)
    symbols: list[SymbolRef] = field(default_factory=list)
    relocations: list[dict[str, Any]] = field(default_factory=list)
    sections: list[dict[str, Any]] = field(default_factory=list)
    jni: list[JNIMapping] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def function_by_addr(self, addr: int) -> FunctionNode | None:
        for fn in self.functions:
            if fn.address <= addr < (fn.end or (fn.address + max(fn.size, 1))):
                return fn
        return None

    def function_by_offset(self, off: int) -> FunctionNode | None:
        target = self.image_base + off
        return self.function_by_addr(target)


@dataclass(slots=True)
class AndroidArtifact:
    package: str = ""
    serial: str = ""
    apk_paths: list[str] = field(default_factory=list)
    local_apks: list[str] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)
    dex_files: list[str] = field(default_factory=list)
    version_name: str = ""
    version_code: str = ""
    signer_sha256: str = ""
    apk_sha256: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AnalysisCase:
    case_dir: str
    target: str
    mode: str
    created_at: str
    artifact: AndroidArtifact | None = None
    modules: list[ModuleAnalysis] = field(default_factory=list)
    dynamic_modules: list[DynamicModule] = field(default_factory=list)
    java_findings: list[dict[str, Any]] = field(default_factory=list)
    dynamic_events: list[dict[str, Any]] = field(default_factory=list)
    topology: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def path(self) -> Path:
        return Path(self.case_dir)
