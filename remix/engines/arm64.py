from __future__ import annotations

from pathlib import Path


class Arm64Engine:
    """Targeted AArch64 feature extraction using Capstone when available."""

    def __init__(self):
        try:
            from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # type: ignore
            self.Cs, self.ARCH, self.MODE = Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
        except Exception:
            self.Cs = self.ARCH = self.MODE = None

    @property
    def available(self) -> bool:
        return self.Cs is not None

    def summarize_bytes(self, code: bytes, address: int) -> dict:
        if not self.Cs:
            return {"available": False}
        md = self.Cs(self.ARCH, self.MODE)
        md.detail = False
        counts = {"bl": 0, "blr": 0, "b": 0, "br": 0, "ret": 0, "svc": 0, "pac": 0, "bti": 0,
                  "adrp": 0, "ldr": 0, "str": 0, "cmp": 0}
        insns = []
        for ins in md.disasm(code, address):
            mn = ins.mnemonic.lower()
            if mn in counts:
                counts[mn] += 1
            if mn.startswith("pac") or mn.startswith("aut"):
                counts["pac"] += 1
            if mn.startswith("bti"):
                counts["bti"] += 1
            insns.append({"address": ins.address, "address_hex": hex(ins.address), "mnemonic": mn, "op_str": ins.op_str})
        return {"available": True, "counts": counts, "instruction_count": len(insns), "instructions": insns[:600]}
