from __future__ import annotations

import re

# Categories are deliberately semantic. A hit does not prove behavior; it is used
# to rank functions for deeper analysis.
CATEGORY_PATTERNS: dict[str, tuple[str, ...]] = {
    "jni": (
        r"RegisterNatives", r"JNI_OnLoad", r"FindClass", r"GetMethodID",
        r"GetStaticMethodID", r"Call.*Method", r"NewStringUTF", r"GetByteArrayElements",
        r"Java_[A-Za-z0-9_]",
    ),
    "loader": (
        r"dlopen", r"android_dlopen_ext", r"dlsym", r"dladdr", r"System\.loadLibrary",
        r"DexClassLoader", r"InMemoryDexClassLoader", r"mmap", r"mprotect",
    ),
    "tls": (
        r"SSL_(read|write|connect|do_handshake|set_custom_verify|set_verify)", r"X509_",
        r"CertificatePinner", r"checkServerTrusted", r"HostnameVerifier", r"TrustManager",
        r"Conscrypt", r"Cronet", r"QUIC", r"boringssl", r"sha256/",
    ),
    "network": (
        r"connect", r"send(to)?", r"recv(from)?", r"socket", r"getaddrinfo", r"OkHttp",
        r"Retrofit", r"HttpUrl", r"UrlRequest", r"CronetEngine", r"https?://",
    ),
    "crypto": (
        r"AES", r"GCM", r"ChaCha", r"Poly1305", r"HKDF", r"HMAC", r"SHA(1|224|256|384|512)",
        r"EVP_", r"ECDH", r"ECDSA", r"X25519", r"Ed25519", r"RSA", r"Cipher", r"MessageDigest",
    ),
    "integrity": (
        r"signer", r"signature", r"SigningInfo", r"getApkContentsSigners", r"PackageInfo",
        r"classes\.dex", r"APK Signing Block", r"integrity", r"digest", r"hash_blob",
    ),
    "antidebug": (
        r"TracerPid", r"ptrace", r"frida", r"gum-js-loop", r"gmain", r"gdbus",
        r"/proc/self/maps", r"/proc/self/status", r"/proc/net/tcp", r"debugger",
    ),
    "root": (
        r"/data/adb", r"KernelSU", r"Magisk", r"su\b", r"zygisk", r"mount", r"overlayfs",
    ),
    "ipc": (
        r"AF_UNIX", r"unix", r"Binder", r"transact", r"Parcel", r"LocalSocket", r"sendmsg",
        r"recvmsg", r"pipe", r"eventfd",
    ),
    "storage": (
        r"SharedPreferences", r"sqlite", r"open(at)?", r"fopen", r"read", r"write", r"rename",
        r"unlink", r"stat", r"auth_token", r"session_token", r"frame_key", r"device_secret",
    ),
    "auth": (
        r"auth", r"activate", r"license", r"entitlement", r"token", r"session", r"device_secret",
        r"runtime_token", r"challenge", r"bootstrap", r"verify",
    ),
    "camera": (
        r"camera", r"cameraserver", r"Camera2", r"CameraService", r"ACamera", r"ImageReader",
        r"Surface", r"gralloc", r"GraphicBuffer",
    ),
}

COMPILED = {
    cat: tuple(re.compile(p, re.I) for p in pats)
    for cat, pats in CATEGORY_PATTERNS.items()
}


def classify(text: str) -> set[str]:
    if not text:
        return set()
    return {cat for cat, pats in COMPILED.items() if any(p.search(text) for p in pats)}


def score_tags(tags: set[str], *, source: str) -> float:
    base = {
        "symbol": 3.0,
        "import": 2.5,
        "string": 1.5,
        "java": 2.0,
        "dynamic": 4.0,
        "jni": 3.0,
        "xref": 1.0,
    }.get(source, 1.0)
    return base * max(1, len(tags))
