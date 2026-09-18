import json
import tempfile
import unittest
from pathlib import Path

from remix.categories import classify
from remix.correlate import Correlator
from remix.engines.android import AndroidEngine
from remix.engines.rizin import RizinEngine
from remix.model import AnalysisCase, DynamicModule, FunctionNode, ModuleAnalysis, StringRef, ImportRef
from remix.runner import Budget


class CoreTests(unittest.TestCase):
    def test_categories(self):
        self.assertIn("antidebug", classify("TracerPid: 0 /proc/self/maps frida"))
        self.assertIn("tls", classify("okhttp3.CertificatePinner sha256/"))
        self.assertIn("jni", classify("JNI_OnLoad RegisterNatives"))
        self.assertIn("crypto", classify("X25519 HKDF SHA256"))

    def test_maps(self):
        text = """70000000-70001000 r--p 0 00:00 0 /data/app/libfoo.so
70001000-70005000 r-xp 1000 00:00 0 /data/app/libfoo.so
71000000-71001000 r-xp 0 00:00 0 /system/lib64/libc.so
"""
        mods = AndroidEngine.parse_maps(text)
        foo = [m for m in mods if m.name == "libfoo.so"][0]
        self.assertEqual(foo.base, 0x70000000)
        self.assertEqual(foo.end, 0x70005000)

    def test_rizin_population_xrefs(self):
        eng = RizinEngine(budget=Budget(20))
        mod = ModuleAnalysis(path="/tmp/libx.so", name="libx.so", sha256="x")
        d = {
            "meta": {"bin": {"arch": "arm", "bits": 64, "baddr": 0x1000}},
            "functions": [
                {"offset": 0x1100, "size": 0x40, "name": "auth_worker"},
                {"offset": 0x1200, "size": 0x40, "name": "helper"},
            ],
            "strings": [{"vaddr": 0x3000, "string": "device_secret"}],
            "imports": [{"vaddr": 0x4000, "name": "SSL_write"}],
            "symbols": [], "relocs": [], "sections": [],
            "xrefs": [
                {"from": 0x1110, "to": 0x1200, "type": "CALL"},
                {"from": 0x1118, "to": 0x3000, "type": "DATA"},
                {"from": 0x1120, "to": 0x4000, "type": "CALL"},
            ]
        }
        eng._populate(mod, d)
        f = mod.function_by_addr(0x1100)
        self.assertIn(0x1200, f.callees)
        self.assertIn(0x3000, f.string_refs)
        self.assertIn("SSL_write", f.imports)
        self.assertIn("auth", f.tags)
        self.assertIn("tls", f.tags)
        self.assertEqual(len(f.xrefs_from), 3)
        self.assertTrue(any(x.get("to_string") == "device_secret" for x in f.xrefs_from))
        case = AnalysisCase("/tmp/case", "x", "fast", "now", modules=[mod])
        Correlator(case).run()
        self.assertGreaterEqual(case.summary.get("xref_edges", 0), 3)
        self.assertIn("auth", case.summary.get("semantic_flows", {}))
        self.assertIn("native_tls", case.summary.get("mechanisms", {}))

    def test_runtime_correlation(self):
        case = AnalysisCase("/tmp/c", "pkg", "fast", "now")
        m = ModuleAnalysis(path="x", name="libx.so", sha256="x", image_base=0)
        m.functions = [FunctionNode("libx.so", 0x100, 0x100, "worker", size=0x80, end=0x180)]
        case.modules = [m]
        case.dynamic_modules = [DynamicModule("libx.so", "/data/libx.so", 0x70000000, 0x70010000, "r-xp")]
        case.dynamic_events = [{"event": "call", "symbol": "SSL_write", "return_address": "0x70000110"}]
        Correlator(case).run()
        self.assertIn("tls", m.functions[0].tags)
        self.assertTrue(m.functions[0].dynamic_hits)


if __name__ == "__main__":
    unittest.main()
