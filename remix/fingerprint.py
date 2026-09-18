from __future__ import annotations

import io
import json
import re
import subprocess
import zipfile
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from .registry import engine_map
from .runner import sha256_file


ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")

FRAMEWORK_MARKERS = {
    "flutter": ("libflutter.so", "libapp.so", "flutter_assets", "io.flutter"),
    "react-native": ("libreactnativejni.so", "libhermes.so", "index.android.bundle", "com.facebook.react"),
    "cordova-capacitor": ("cordova.js", "capacitor.config", "com.getcapacitor", "org.apache.cordova"),
    "xamarin-dotnet": ("assemblies/", "libmonosgen", "xamarin", "mono.android"),
    "unity": ("libunity.so", "libil2cpp.so", "assets/bin/data", "unityplayer"),
    "native-kotlin": ("kotlin/", "kotlinx/", "kotlin_module", "kotlin.Metadata"),
    "jetpack-compose": ("androidx.compose", "compose-runtime", "Composable"),
}

HTTP_MARKERS = {
    "okhttp": ("okhttp3", "OkHttpClient", "Request$Builder"),
    "retrofit": ("retrofit2", "@GET", "@POST"),
    "ktor": ("io.ktor", "HttpClient", "BearerTokens"),
    "apollo-graphql": ("ApolloClient", "com.apollographql"),
    "volley": ("com.android.volley", "RequestQueue"),
    "cronet-httpengine": ("org.chromium.net", "CronetEngine", "android.net.http.HttpEngine", "UrlRequest"),
    "grpc": ("io.grpc", "ManagedChannel", "grpc-java"),
    "webview": ("WebView", "loadUrl", "addJavascriptInterface"),
}

DI_MARKERS = {
    "hilt-dagger": ("dagger.hilt", "@HiltAndroidApp", "@Provides", "javax.inject"),
    "koin": ("org.koin", "startKoin", "KoinComponent"),
}

SER_MARKERS = {
    "kotlinx-serialization": ("kotlinx.serialization",),
    "moshi": ("com.squareup.moshi", "Moshi"),
    "gson": ("com.google.gson", "Gson"),
    "jackson": ("com.fasterxml.jackson", "ObjectMapper"),
    "protobuf": ("com.google.protobuf", "GeneratedMessageLite"),
}

PROTECTION_MARKERS = {
    "frida-detection": ("TracerPid", "gum-js-loop", "frida-server", "/proc/self/maps"),
    "root-detection": ("/data/adb", "magisk", "KernelSU", "zygisk"),
    "signature-integrity": ("getApkContentsSigners", "SigningInfo", "APK Signing Block"),
    "native-loader": ("android_dlopen_ext", "RegisterNatives", "JNI_OnLoad"),
}

@dataclass(slots=True)
class Fingerprint:
    path: str
    sha256: str
    kind: str
    framework: list[str] = field(default_factory=list)
    http_stacks: list[str] = field(default_factory=list)
    di: list[str] = field(default_factory=list)
    serialization: list[str] = field(default_factory=list)
    protections: list[str] = field(default_factory=list)
    abis: list[str] = field(default_factory=list)
    native_libraries: list[str] = field(default_factory=list)
    dex_files: list[str] = field(default_factory=list)
    split_apks: list[str] = field(default_factory=list)
    obfuscation: dict = field(default_factory=dict)
    apkid: dict | list | None = None
    markers: dict[str, list[str]] = field(default_factory=dict)
    recommended_route: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def _ascii_strings(data: bytes, *, cap: int = 120000) -> list[str]:
    # cap prevents a malicious/huge DEX from exploding memory during triage.
    out=[]
    for i,m in enumerate(ASCII_RE.finditer(data)):
        if i >= cap: break
        out.append(m.group().decode("utf-8", "replace"))
    return out


def _detect(hay: str, table: dict[str, tuple[str,...]]) -> tuple[list[str],dict[str,list[str]]]:
    found=[]; markers={}
    low=hay.lower()
    for name, pats in table.items():
        hits=[p for p in pats if p.lower() in low]
        if hits:
            found.append(name); markers[name]=hits
    return sorted(found),markers


def _obfuscation(strings: Iterable[str]) -> dict:
    # Extract descriptor-ish package/class paths. This is heuristic and labelled as such.
    pkgs=[]
    for s in strings:
        for m in re.finditer(r"L([A-Za-z_$][\w$]*(?:/[A-Za-z_$][\w$]*){1,8})[;$]", s):
            parts=m.group(1).split("/")
            if len(parts)>=2: pkgs.append(parts)
    if not pkgs:
        return {"level":"unknown","score":0.0,"sample":[],"basis":"no descriptor-like strings"}
    roots=[p[0] for p in pkgs]
    short=sum(1 for p in pkgs if len(p[0])<=2 and len(p[1])<=2)
    single=sum(1 for p in pkgs if all(len(x)<=2 for x in p[:min(3,len(p))]))
    ratio=(short+single)/(2*len(pkgs))
    level="high" if ratio>.45 else "moderate" if ratio>.18 else "low"
    return {"level":level,"score":round(ratio,3),"sample":["/".join(x[:4]) for x in pkgs[:25]],"basis":"short descriptor package/class heuristic"}


def _run_apkid(path: Path):
    st=engine_map().get("apkid")
    if not st or not st.available or not st.executable:
        return None
    try:
        cp=subprocess.run([st.executable,"-j",str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=20)
        return json.loads(cp.stdout) if cp.returncode==0 and cp.stdout.strip() else {"error":cp.stderr[-1000:],"rc":cp.returncode}
    except Exception as e:
        return {"error":str(e)}


def _zip_scan(z: zipfile.ZipFile, fp: Fingerprint, global_strings: list[str], names: list[str]) -> None:
    for name in names:
        low=name.lower()
        if low.endswith(".dex"):
            fp.dex_files.append(name)
            try: global_strings.extend(_ascii_strings(z.read(name)))
            except Exception as e: fp.warnings.append(f"dex read {name}: {e}")
        if "/lib/" in ("/"+low) and low.endswith(".so") or low.startswith("lib/") and low.endswith(".so"):
            parts=name.split("/")
            if len(parts)>=3 and parts[0]=="lib": fp.abis.append(parts[1])
            fp.native_libraries.append(name)
        if low.endswith(".apk"):
            fp.split_apks.append(name)
            try:
                blob=z.read(name)
                with zipfile.ZipFile(io.BytesIO(blob)) as inner:
                    _zip_scan(inner, fp, global_strings, [f"{name}!{x}" for x in []])
                    # direct scan inner without recursive path rewriting
                    for n2 in inner.namelist():
                        l2=n2.lower()
                        if l2.endswith(".dex"):
                            global_strings.extend(_ascii_strings(inner.read(n2)))
                        if l2.startswith("lib/") and l2.endswith(".so"):
                            p=n2.split("/")
                            if len(p)>=3: fp.abis.append(p[1])
                            fp.native_libraries.append(f"{name}!{n2}")
            except Exception:
                pass


def fingerprint(path: str | Path, *, use_apkid: bool = True) -> Fingerprint:
    p=Path(path)
    kind=p.suffix.lower().lstrip(".") or "file"
    fp=Fingerprint(str(p),sha256_file(p),kind)
    strings: list[str]=[]
    names: list[str]=[]
    if zipfile.is_zipfile(p):
        with zipfile.ZipFile(p) as z:
            names=z.namelist()
            _zip_scan(z,fp,strings,names)
    else:
        strings=_ascii_strings(p.read_bytes())
    hay="\n".join(names+strings)
    allmarkers={}
    fp.framework,m=_detect(hay,FRAMEWORK_MARKERS); allmarkers.update({"framework:"+k:v for k,v in m.items()})
    fp.http_stacks,m=_detect(hay,HTTP_MARKERS); allmarkers.update({"http:"+k:v for k,v in m.items()})
    fp.di,m=_detect(hay,DI_MARKERS); allmarkers.update({"di:"+k:v for k,v in m.items()})
    fp.serialization,m=_detect(hay,SER_MARKERS); allmarkers.update({"ser:"+k:v for k,v in m.items()})
    fp.protections,m=_detect(hay,PROTECTION_MARKERS); allmarkers.update({"protection:"+k:v for k,v in m.items()})
    fp.markers=allmarkers
    fp.abis=sorted(set(fp.abis)); fp.native_libraries=sorted(set(fp.native_libraries)); fp.dex_files=sorted(set(fp.dex_files)); fp.split_apks=sorted(set(fp.split_apks))
    fp.obfuscation=_obfuscation(strings)
    if use_apkid and kind in {"apk","dex","xapk","zip"}: fp.apkid=_run_apkid(p)

    route=["fingerprint"]
    fw=set(fp.framework)
    if "flutter" in fw:
        route += ["native-library-inventory","strings+floss","runtime-module-map","targeted-native-analysis"]
    elif "react-native" in fw:
        route += ["bundle/hermes-triage","native-library-inventory","runtime-module-map"]
    elif "unity" in fw:
        route += ["il2cpp-metadata-triage","native-library-inventory","binary-signatures"]
    elif "xamarin-dotnet" in fw:
        route += ["assembly-inventory","managed-decompile","native-library-inventory"]
    else:
        route += ["jadx-fast"]
        if fp.obfuscation.get("level") in {"moderate","high"} and ("native-kotlin" in fw or "jetpack-compose" in fw):
            route += ["kotlin-metadata-recovery"]
        route += ["native-library-inventory"]
    if fp.protections:
        route += ["clean-root-baseline","protector-aware-runtime-first"]
    if fp.native_libraries:
        route += ["bulk-native-topology","rank","targeted-decompile","cross-engine-validate"]
    fp.recommended_route=route
    return fp
