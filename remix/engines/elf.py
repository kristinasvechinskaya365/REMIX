from __future__ import annotations

from pathlib import Path
from typing import Any

from ..categories import classify
from ..model import ImportRef, ModuleAnalysis, SymbolRef


def _str_enum(v: Any) -> str:
    s = str(v)
    return s.split(".")[-1] if "." in s else s


def _function_row(f: Any) -> dict[str, Any]:
    return {
        "name": str(getattr(f, "name", "") or ""),
        "address": int(getattr(f, "address", 0) or 0),
        "address_hex": hex(int(getattr(f, "address", 0) or 0)),
        "size": int(getattr(f, "size", 0) or 0),
    }


class LiefEngine:
    """Independent loader-level ELF topology.

    Rizin answers control-flow questions. LIEF is used independently for loader
    truth: DT_NEEDED, segments, RELRO/NX/PIE, constructors/destructors, dynamic
    entries, PLT/GOT relocations, symbol binding/visibility and C++ RTTI/vtables.
    Keeping these sources independent makes disagreement visible instead of
    silently trusting one disassembler's naming.
    """

    def __init__(self):
        try:
            import lief  # type: ignore
        except Exception:
            lief = None
        self.lief = lief

    @property
    def available(self) -> bool:
        return self.lief is not None

    def enrich(self, module: ModuleAnalysis) -> None:
        if not self.lief:
            module.metadata["lief"] = "unavailable"
            return
        try:
            binary = self.lief.ELF.parse(module.path)
        except Exception as e:
            module.errors.append(f"LIEF parse error: {e}")
            return
        if binary is None:
            module.errors.append("LIEF returned no ELF binary")
            return

        module.metadata["lief"] = "ok"
        module.metadata["libraries"] = list(binary.libraries)
        module.metadata["interpreter"] = str(getattr(binary, "interpreter", "") or "")
        module.metadata["is_pie"] = bool(getattr(binary, "is_pie", False))
        module.metadata["is_android"] = bool(getattr(binary, "is_targeting_android", False))
        module.metadata["entrypoint_lief"] = int(getattr(binary, "entrypoint", 0) or 0)

        # Security / loader segment topology.
        segments = []
        has_relro = False
        nx_stack = None
        rwx_segments = []
        for seg in binary.segments:
            stype = _str_enum(getattr(seg, "type", ""))
            flags_obj = getattr(seg, "flags", 0)
            flags = str(flags_obj)
            try:
                flags_value = int(flags_obj)
            except Exception:
                flags_value = 0
            row = {
                "type": stype,
                "flags": flags,
                "flags_value": flags_value,
                "virtual_address": int(getattr(seg, "virtual_address", 0) or 0),
                "virtual_address_hex": hex(int(getattr(seg, "virtual_address", 0) or 0)),
                "virtual_size": int(getattr(seg, "virtual_size", 0) or 0),
                "file_offset": int(getattr(seg, "file_offset", 0) or 0),
                "physical_size": int(getattr(seg, "physical_size", 0) or 0),
            }
            segments.append(row)
            if "GNU_RELRO" in stype:
                has_relro = True
            if "GNU_STACK" in stype:
                # LIEF Segment flags use X=1, W=2, R=4.
                nx_stack = not bool(flags_value & 1)
            if (flags_value & 0x3) == 0x3:  # W + X
                rwx_segments.append(row)
        module.metadata["segments_lief"] = segments
        module.metadata["security"] = {
            "pie": bool(getattr(binary, "is_pie", False)),
            "relro_segment": has_relro,
            "nx_stack": nx_stack,
            "rwx_segment_count": len(rwx_segments),
            "rwx_segments": rwx_segments,
            "has_symtab": any(getattr(s, "name", "") == ".symtab" for s in binary.sections),
        }

        # Constructors/destructors are direct lifecycle edges and often more useful
        # than starting at JNI_OnLoad after initialization has already happened.
        try:
            ctors = [_function_row(f) for f in binary.ctor_functions]
        except Exception:
            ctors = []
        try:
            dtors = [_function_row(f) for f in binary.dtor_functions]
        except Exception:
            dtors = []
        module.metadata["constructors"] = ctors
        module.metadata["destructors"] = dtors

        dyn = []
        for entry in binary.dynamic_entries:
            row = {"tag": _str_enum(getattr(entry, "tag", "")), "repr": str(entry)}
            for attr in ("value", "name", "array", "flags"):
                try:
                    val = getattr(entry, attr)
                    if attr == "array": val = [int(x) for x in val]
                    elif isinstance(val, (int, str, bool)): pass
                    else: val = str(val)
                    row[attr] = val
                except Exception:
                    pass
            dyn.append(row)
        module.metadata["dynamic_entries"] = dyn

        known_imports = {i.name: i for i in module.imports}
        for f in binary.imported_functions:
            name = str(f.name)
            if name not in known_imports:
                tags = classify(name)
                imp = ImportRef(name=name, address=int(f.address or 0) or None, tags=sorted(tags))
                module.imports.append(imp)
                known_imports[name] = imp

        known_syms = {(s.name, s.address) for s in module.symbols}
        cxx = []
        for sym in binary.dynamic_symbols:
            name = str(sym.name)
            address = int(sym.value)
            try: demangled = str(sym.demangled_name or "")
            except Exception: demangled = ""
            tags = sorted(classify(" ".join((name, demangled))))
            key = (name, address)
            if key not in known_syms:
                section = ""
                try: section = str(sym.section.name) if sym.section else ""
                except Exception: pass
                module.symbols.append(SymbolRef(
                    name=name, address=address, size=int(sym.size),
                    bind=_str_enum(sym.binding), type=_str_enum(sym.type),
                    visibility=_str_enum(getattr(sym, "visibility", "")),
                    demangled=demangled, section=section,
                    imported=bool(getattr(sym, "imported", address == 0)),
                    exported=bool(getattr(sym, "exported", address != 0)),
                    tags=tags,
                ))
            if name.startswith(("_ZTV", "_ZTI", "_ZTS")):
                kind = "vtable" if name.startswith("_ZTV") else "rtti" if name.startswith("_ZTI") else "type-name"
                cxx.append({"kind": kind, "name": name, "demangled": demangled, "address": address, "address_hex": hex(address)})
        module.metadata["cxx_type_topology"] = cxx

        # PLT/GOT is loader truth independent of disassembler naming.
        import_by_name = {i.name: i for i in module.imports}
        pltgot_rows = []
        try:
            for r in binary.pltgot_relocations:
                sym_name = str(r.symbol.name) if r.has_symbol else ""
                address = int(r.address)
                if sym_name and sym_name in import_by_name:
                    import_by_name[sym_name].got = address
                pltgot_rows.append({
                    "got": address, "got_hex": hex(address), "symbol": sym_name,
                    "type": _str_enum(r.type), "size": int(r.size),
                })
        except Exception as e:
            module.metadata["lief_pltgot_error"] = str(e)
        module.metadata["pltgot_relocations"] = pltgot_rows

        relocs: list[dict[str, Any]] = []
        for r in binary.relocations:
            sym = ""
            try:
                if r.has_symbol: sym = str(r.symbol.name)
            except Exception:
                pass
            relocs.append({
                "address": int(r.address), "address_hex": hex(int(r.address)),
                "size": int(r.size), "purpose": str(getattr(r, "purpose", "")),
                "type": _str_enum(r.type), "symbol": sym,
            })
        if relocs:
            module.metadata["lief_relocations"] = relocs

        # Lifecycle/native seam anchors get promoted into module metadata for fast
        # manual lookup even when function names are otherwise stripped.
        anchors = []
        for s in module.symbols:
            text = f"{s.name} {s.demangled}"
            if s.name in {"JNI_OnLoad", "JNI_OnUnload"} or s.name.startswith("Java_") or classify(text) & {"jni", "loader", "integrity", "antidebug"}:
                anchors.append({"name": s.name, "demangled": s.demangled, "address": s.address,
                                "address_hex": hex(s.address), "tags": s.tags})
        module.metadata["native_anchors"] = anchors[:1000]
