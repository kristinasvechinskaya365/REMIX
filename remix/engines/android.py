from __future__ import annotations

import hashlib
import os
import re
import shutil
import zipfile
from pathlib import Path

from ..model import AndroidArtifact, DynamicModule
from ..runner import Budget, run, sha256_file, which_any


class AndroidEngine:
    def __init__(self, *, serial: str, budget: Budget, timeout: float = 30):
        self.serial = serial
        self.budget = budget
        self.timeout = timeout
        self.adb = which_any(["adb"])
        if not self.adb:
            sdk = Path.home() / "Library/Android/sdk/platform-tools/adb"
            if sdk.exists():
                self.adb = str(sdk)

    @property
    def available(self) -> bool:
        return bool(self.adb)

    def adb_run(self, args: list[str], *, timeout: float | None = None):
        if not self.adb:
            raise RuntimeError("adb not found")
        return run([self.adb, "-s", self.serial, *args], timeout=self.budget.clamp(timeout or self.timeout))

    def shell(self, command: str, *, root: bool = False, timeout: float | None = None):
        if root:
            return self.adb_run(["shell", f"su -c '{command}'"], timeout=timeout)
        return self.adb_run(["shell", command], timeout=timeout)

    def doctor(self) -> dict:
        out = {"adb": bool(self.adb), "serial": self.serial}
        if not self.adb:
            return out
        st = self.adb_run(["get-state"], timeout=5)
        out["state"] = st.stdout.strip()
        if st.returncode == 0:
            root = self.adb_run(["shell", "su -c 'id; getenforce'"], timeout=6)
            out["root"] = root.stdout.strip()
        return out

    def acquire_package(self, package: str, case_dir: str | Path) -> AndroidArtifact:
        case_dir = Path(case_dir)
        art_dir = case_dir / "artifact"
        apk_dir = art_dir / "apks"
        native_dir = art_dir / "native"
        dex_dir = art_dir / "dex"
        for p in (apk_dir, native_dir, dex_dir):
            p.mkdir(parents=True, exist_ok=True)

        rr = self.adb_run(["shell", "pm", "path", package], timeout=10)
        if rr.returncode != 0 or "package:" not in rr.stdout:
            raise RuntimeError(f"package not installed: {package}")
        remotes = [line.split("package:", 1)[1].strip() for line in rr.stdout.splitlines() if line.startswith("package:")]
        artifact = AndroidArtifact(package=package, serial=self.serial, apk_paths=remotes)

        dump = self.adb_run(["shell", "dumpsys", "package", package], timeout=12).stdout
        m = re.search(r"versionName=([^\s]+)", dump)
        if m:
            artifact.version_name = m.group(1)
        m = re.search(r"versionCode=(\d+)", dump)
        if m:
            artifact.version_code = m.group(1)

        for idx, remote in enumerate(remotes):
            name = Path(remote).name
            if (apk_dir / name).exists():
                name = f"{idx:02d}_{name}"
            local = apk_dir / name
            pr = self.adb_run(["pull", remote, str(local)], timeout=30)
            if pr.returncode != 0:
                raise RuntimeError(f"adb pull failed for {remote}: {pr.stderr}")
            artifact.local_apks.append(str(local))
            artifact.apk_sha256.append(sha256_file(local))
            self._extract_apk(local, native_dir, dex_dir)

        artifact.native_libs = sorted(str(p) for p in native_dir.rglob("*.so"))
        artifact.dex_files = sorted(str(p) for p in dex_dir.glob("*.dex"))
        artifact.signer_sha256 = self._signer_sha256(Path(artifact.local_apks[0])) if artifact.local_apks else ""
        artifact.metadata["dumpsys_excerpt"] = "\n".join(
            line for line in dump.splitlines()
            if any(k in line for k in ("versionName=", "versionCode=", "primaryCpuAbi=", "secondaryCpuAbi="))
        )
        return artifact

    def acquire_file(self, path: str | Path, case_dir: str | Path) -> AndroidArtifact:
        path = Path(path).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(path)
        case_dir = Path(case_dir)
        art_dir = case_dir / "artifact"
        art_dir.mkdir(parents=True, exist_ok=True)
        artifact = AndroidArtifact()
        if path.suffix.lower() == ".apk":
            apk_dir = art_dir / "apks"; apk_dir.mkdir(exist_ok=True)
            native_dir = art_dir / "native"; native_dir.mkdir(exist_ok=True)
            dex_dir = art_dir / "dex"; dex_dir.mkdir(exist_ok=True)
            dst = apk_dir / path.name
            if dst != path:
                shutil.copy2(path, dst)
            artifact.local_apks = [str(dst)]
            artifact.apk_sha256 = [sha256_file(dst)]
            self._extract_apk(dst, native_dir, dex_dir)
            artifact.native_libs = sorted(str(p) for p in native_dir.rglob("*.so"))
            artifact.dex_files = sorted(str(p) for p in dex_dir.glob("*.dex"))
            artifact.signer_sha256 = self._signer_sha256(dst)
        elif path.suffix.lower() == ".so" or path.read_bytes()[:4] == b"\x7fELF":
            native_dir = art_dir / "native"; native_dir.mkdir(exist_ok=True)
            dst = native_dir / path.name
            if dst != path:
                shutil.copy2(path, dst)
            artifact.native_libs = [str(dst)]
        else:
            raise ValueError("target file must be APK or ELF/shared object")
        return artifact

    def _extract_apk(self, apk: Path, native_dir: Path, dex_dir: Path) -> None:
        with zipfile.ZipFile(apk) as zf:
            for zi in zf.infolist():
                n = zi.filename
                if re.match(r"^lib/[^/]+/[^/]+\.so$", n):
                    abi = n.split("/")[1]
                    out = native_dir / abi / Path(n).name
                    out.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(zi) as src, open(out, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                elif re.match(r"^classes(?:\d+)?\.dex$", n):
                    out = dex_dir / (apk.stem + "_" + Path(n).name)
                    with zf.open(zi) as src, open(out, "wb") as dst:
                        shutil.copyfileobj(src, dst)

    def _signer_sha256(self, apk: Path) -> str:
        apksigner = which_any(["apksigner"])
        if not apksigner:
            sdk = Path.home() / "Library/Android/sdk/build-tools"
            if sdk.exists():
                candidates = sorted(sdk.glob("*/apksigner"), reverse=True)
                if candidates:
                    apksigner = str(candidates[0])
        if not apksigner:
            return ""
        rr = run([apksigner, "verify", "--print-certs", str(apk)], timeout=self.budget.clamp(15))
        m = re.search(r"Signer #1 certificate SHA-256 digest:\s*([0-9a-fA-F]{64})", rr.stdout + rr.stderr)
        return m.group(1).lower() if m else ""

    def launch(self, package: str) -> None:
        self.adb_run(["shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"], timeout=8)

    def pid(self, package: str) -> int | None:
        rr = self.adb_run(["shell", "pidof", package], timeout=5)
        if rr.returncode != 0:
            return None
        s = rr.stdout.strip().split()
        return int(s[0]) if s and s[0].isdigit() else None

    def root_snapshot(self, package: str, case_dir: str | Path, *, launch: bool = True) -> list[DynamicModule]:
        if launch and not self.pid(package):
            self.launch(package)
        pid = self.pid(package)
        if not pid:
            raise RuntimeError(f"target did not start: {package}")
        snap = Path(case_dir) / "live-root"
        snap.mkdir(parents=True, exist_ok=True)

        commands = {
            "status.txt": f"cat /proc/{pid}/status",
            "maps.txt": f"cat /proc/{pid}/maps",
            "threads.txt": f"for x in /proc/{pid}/task/*/comm; do cat $x; done",
            "fd.txt": f"ls -l /proc/{pid}/fd 2>/dev/null",
            "tcp.txt": "cat /proc/net/tcp; echo ---TCP6---; cat /proc/net/tcp6; echo ---UDP---; cat /proc/net/udp; echo ---UDP6---; cat /proc/net/udp6",
            "mountinfo.txt": f"cat /proc/{pid}/mountinfo",
        }
        for name, cmd in commands.items():
            rr = self.shell(cmd, root=True, timeout=10)
            (snap / name).write_text(rr.stdout + ("\nSTDERR:\n" + rr.stderr if rr.stderr else ""), encoding="utf-8", errors="replace")

        maps_text = (snap / "maps.txt").read_text(errors="replace")
        return self.parse_maps(maps_text)

    @staticmethod
    def parse_maps(text: str) -> list[DynamicModule]:
        grouped: dict[str, tuple[int, int, str]] = {}
        for line in text.splitlines():
            parts = line.split(None, 5)
            if len(parts) < 6:
                continue
            rng, perms, _, _, _, path = parts
            if not path.startswith("/"):
                continue
            try:
                a, b = (int(x, 16) for x in rng.split("-", 1))
            except Exception:
                continue
            old = grouped.get(path)
            if old:
                grouped[path] = (min(old[0], a), max(old[1], b), old[2])
            else:
                grouped[path] = (a, b, perms)
        return [DynamicModule(Path(p).name, p, a, b, perms) for p, (a, b, perms) in sorted(grouped.items(), key=lambda kv: kv[1][0])]
