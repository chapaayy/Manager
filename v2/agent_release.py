"""Versioned, SHA-256 pinned agent artifacts baked into the Manager Docker image."""
from pathlib import Path
import hashlib
import re

ROOT=Path(__file__).resolve().parent/"agent"
VERSION_FILE=ROOT/"main.go"
VERSION_RE=re.compile(r'const Version = "([0-9]+\\.[0-9]+\\.[0-9]+)"')


def release() -> dict:
    match=VERSION_RE.search(VERSION_FILE.read_text("utf-8"))
    if not match:
        raise RuntimeError("Agent release version missing")
    version=match.group(1)
    binaries={}
    for arch in ("amd64","arm64"):
        path=ROOT/("agent-"+arch)
        if path.is_file() and not path.is_symlink():
            binaries[arch]={"version":version,
                            "sha256":hashlib.sha256(path.read_bytes()).hexdigest(),
                            "size":path.stat().st_size}
    return {"version":version,"binaries":binaries}


def artifact(arch:str)->Path:
    if arch not in ("amd64","arm64"):
        raise ValueError("Unsupported agent architecture")
    path=ROOT/("agent-"+arch)
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError("Agent executable is not built")
    if not 10000 <= path.stat().st_size <= 14000000:
        raise ValueError("Invalid agent executable size")
    return path


def compare(a:str,b:str)->int:
    """Only semver triplets; unknown older agents never auto-update."""
    pat=r"[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
    if not re.fullmatch(pat,a) or not re.fullmatch(pat,b):
        return 0
    aa=tuple(map(int,a.split(".")))
    bb=tuple(map(int,b.split(".")))
    return (aa>bb)-(aa<bb)
