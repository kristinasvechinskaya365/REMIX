import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from remix.deep import EngineObservation, consensus
from remix.fingerprint import fingerprint
from remix.flow import FlowEngine
from remix.kotlinmeta import recover
from remix.model import AnalysisCase, FunctionNode, ModuleAnalysis, StringRef
from remix.selector import expand, select
from remix.signatures import make_signature, match_signature


class V3Tests(unittest.TestCase):
    def case(self, root):
        c=AnalysisCase(str(root),"generic-target","fast","now")
        m=ModuleAnalysis(path=str(root/"libtarget.so"),name="libtarget.so",sha256="x")
        a=FunctionNode("libtarget.so",0x100,0x100,"verify_gate",size=64,end=0x140,callees=[0x200],tags=["integrity","crypto"],score=8.0,arm64_profile={"indirect_call":1,"conditional_branch":3})
        b=FunctionNode("libtarget.so",0x200,0x200,"helper",size=48,end=0x230,callers=[0x100],tags=["crypto"],score=3.0,imports=["SHA256"])
        m.functions=[a,b];m.strings=[StringRef(0x500,"verification failed",refs_from=[0x100],tags=["integrity"])]
        a.string_refs=[0x500]
        c.modules=[m]
        return c

    def test_selector_compact_and_slice(self):
        with tempfile.TemporaryDirectory() as td:
            c=self.case(Path(td))
            rows=select(c,"tag:integrity AND score>=6 AND arm64.indirect_call>0")
            self.assertEqual([r.function.name for r in rows],["verify_gate"])
            sl=expand(rows,c,direction="down",depth=1)
            self.assertEqual({r.function.name for r in sl},{"verify_gate","helper"})

    def test_fingerprint_phase0(self):
        with tempfile.TemporaryDirectory() as td:
            apk=Path(td)/"sample.apk"
            with zipfile.ZipFile(apk,"w") as z:
                z.writestr("classes.dex",b"xxxx kotlin/Metadata okhttp3 OkHttpClient retrofit2 RegisterNatives TracerPid "+b"Lx/y/a;"*40)
                z.writestr("lib/arm64-v8a/libtarget.so",b"ELF")
            fp=fingerprint(apk,use_apkid=False)
            self.assertIn("native-kotlin",fp.framework)
            self.assertIn("okhttp",fp.http_stacks)
            self.assertIn("arm64-v8a",fp.abis)
            self.assertTrue(fp.native_libraries)
            self.assertIn("clean-root-baseline",fp.recommended_route)

    def test_kotlin_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            src=Path(td)/"a/b";src.mkdir(parents=True)
            (src/"c.java").write_text('@DebugMetadata(c = "com.example.RealRepository$load$1", f = "RealRepository.kt")\nclass c {}')
            r=recover(td)
            self.assertEqual(r["mapping"]["a.b.c"],"com.example.RealRepository")

    def test_signature_match(self):
        with tempfile.TemporaryDirectory() as td:
            c=self.case(Path(td)); sig=make_signature(select(c,"name~verify",limit=1)[0])
            matches=match_signature(sig,c,threshold=.8)
            self.assertEqual(matches[0]["name"],"verify_gate")
            self.assertGreaterEqual(matches[0]["score"],.99)

    def test_consensus_independence(self):
        obs=[
            EngineObservation("rizin","rizin","lib+0x10","ok",.8,{"size":64,"exists":True}),
            EngineObservation("radare2","radare","lib+0x10","ok",.8,{"size":64,"exists":True}),
            EngineObservation("angr","angr","lib+0x10","ok",.9,{"size":65,"exists":True}),
        ]
        c=consensus(obs,tolerance=.05)[0]
        self.assertGreater(c.score,.8)
        self.assertIn("exists",c.agreements)

    def test_flow_select_expand_emit(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);c=self.case(root)
            plan={"steps":[
                {"id":"hot","op":"select","where":"score>=6"},
                {"id":"slice","op":"expand","from":"hot","direction":"down","depth":1},
                {"id":"sig","op":"signature","from":"slice"},
                {"id":"out","op":"emit","from":"sig","format":"json"},
            ]}
            r=FlowEngine(c,out_dir=root/"flow",budget=20,jobs=2).run(plan)
            self.assertEqual(len(r.datasets["slice"]),2)
            self.assertTrue((root/"flow"/"out.json").exists())


if __name__ == "__main__":
    unittest.main()
