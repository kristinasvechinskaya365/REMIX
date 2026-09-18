from __future__ import annotations

RECIPES={
"native-hard":{
  "description":"High-signal native triage, neighborhood expansion, decompile and independent validation.",
  "steps":[
    {"id":"hot","op":"select","where":"score>=4 OR arm64.indirect_call>0 OR tag:jni OR tag:integrity","limit":80},
    {"id":"slice","op":"expand","from":"hot","direction":"both","depth":1,"limit":160},
    {"id":"rz-enrich","op":"enrich","engine":"rizin","from":"slice","limit":32},
    {"id":"validate","op":"validate","engines":["rizin","lief","radare2","ghidra"],"from":"slice","limit":24},
    {"id":"consensus","op":"consensus","from":"validate","policy":"weighted"},
    {"id":"emit","op":"emit","from":"consensus","format":"json"}
  ]},
"jni-bridge":{
  "description":"Map Java native declarations/exports/RegisterNatives to nearby native control flow.",
  "steps":[
    {"id":"jni","op":"select","where":"tag:jni OR jni ~ '.+'","limit":100},
    {"id":"slice","op":"expand","from":"jni","direction":"both","depth":2,"limit":250},
    {"id":"enrich","op":"enrich","engine":"rizin","from":"slice","limit":40},
    {"id":"validate","op":"validate","engines":["rizin","radare2","ghidra"],"from":"jni","limit":24},
    {"id":"emit","op":"emit","from":"validate","format":"jsonl"}
  ]},
"network-tls":{
  "description":"Trace Java/native network/TLS choke points and validate native boundaries.",
  "steps":[
    {"id":"net","op":"select","where":"tag:network OR tag:tls","limit":120},
    {"id":"slice","op":"expand","from":"net","direction":"up","depth":2,"limit":250},
    {"id":"validate","op":"validate","engines":["rizin","lief","radare2"],"from":"slice","limit":30},
    {"id":"emit","op":"emit","from":"validate","format":"json"}
  ]},
"integrity-antidebug":{
  "description":"Prioritize integrity/anti-debug gates, callers, strings and independent static checks.",
  "steps":[
    {"id":"gates","op":"select","where":"tag:integrity OR tag:antidebug","limit":100},
    {"id":"parents","op":"expand","from":"gates","direction":"up","depth":2,"limit":250},
    {"id":"validate","op":"validate","engines":["rizin","radare2","ghidra","angr"],"from":"gates","limit":12},
    {"id":"consensus","op":"consensus","from":"validate","policy":"weighted"},
    {"id":"emit","op":"emit","from":"consensus","format":"json"}
  ]},
"deep-consensus":{
  "description":"Expensive cross-engine validation for a small top-ranked set.",
  "steps":[
    {"id":"top","op":"select","where":"score>=5","limit":16},
    {"id":"validate","op":"validate","engines":["rizin","lief","radare2","ghidra","angr"],"from":"top","limit":16},
    {"id":"consensus","op":"consensus","from":"validate","policy":"weighted"},
    {"id":"emit","op":"emit","from":"consensus","format":"json"}
  ]}
}
