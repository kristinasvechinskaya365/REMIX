from __future__ import annotations

from pathlib import Path
from typing import Any

from ..categories import classify, score_tags
from ..model import ImportRef, ModuleAnalysis, SymbolRef


class LiefEngine:
    """Adds loader-level ELF facts without depending on disassembler heuristics."""

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

        known_imports = {i.name: i for i in module.imports}
        for f in binary.imported_functions:
            name = str(f.name)
            if name not in known_imports:
                tags = classify(name)
                module.imports.append(ImportRef(name=name, address=int(f.address or 0) or None,
                                                tags=sorted(tags)))

        known_syms = {(s.name, s.address) for s in module.symbols}
        for sym in binary.dynamic_symbols:
            key = (str(sym.name), int(sym.value))
            if key in known_syms:
                continue
            module.symbols.append(SymbolRef(
                name=str(sym.name), address=int(sym.value), size=int(sym.size),
                bind=str(sym.binding), type=str(sym.type),
                imported=int(sym.value) == 0,
                exported=int(sym.value) != 0,
            ))

        # PLT/GOT is loader truth, independent of disassembler naming. Associate
        # relocations back to imports whenever LIEF exposes a symbol.
        import_by_name = {i.name: i for i in module.imports}
        try:
            for r in binary.pltgot_relocations:
                sym_name = str(r.symbol.name) if r.has_symbol else ""
                if sym_name and sym_name in import_by_name:
                    import_by_name[sym_name].got = int(r.address)
        except Exception as e:
            module.metadata["lief_pltgot_error"] = str(e)

        relocs: list[dict[str, Any]] = []
        for r in binary.relocations:
            sym = ""
            try:
                if r.has_symbol:
                    sym = str(r.symbol.name)
            except Exception:
                pass
            relocs.append({
                "address": int(r.address),
                "address_hex": hex(int(r.address)),
                "size": int(r.size),
                "purpose": str(getattr(r, "purpose", "")),
                "type": str(r.type),
                "symbol": sym,
            })
        if relocs:
            module.metadata["lief_relocations"] = relocs
