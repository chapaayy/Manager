"""Build the root-helper library zip from source modules baked into Manager."""
from __future__ import annotations

import io
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent / "agent"
LIB = ROOT / "helperlib"
MAX_HELPER_FILE = 120000
MAX_HELPER_ZIP = 600000


def launcher_bytes() -> bytes:
    path = ROOT / "helper.py"
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError("Agent helper launcher missing")
    raw = path.read_bytes()
    if not 100 <= len(raw) <= 50000:
        raise ValueError("Agent helper launcher size invalid")
    return raw


def library_zip_bytes() -> bytes:
    files = sorted(LIB.glob("*.py"))
    if not files or not any(path.name == "__init__.py" for path in files):
        raise FileNotFoundError("Agent helper library missing")
    output = io.BytesIO()
    with zipfile.ZipFile(
        output,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for path in files:
            if path.is_symlink() or not path.is_file():
                raise ValueError("Invalid helper library source")
            raw = path.read_bytes()
            if not raw or len(raw) > MAX_HELPER_FILE:
                raise ValueError("Invalid helper module size")
            info = zipfile.ZipInfo(
                "helperlib/" + path.name,
                date_time=(2026, 1, 1, 0, 0, 0),
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, raw)
    raw = output.getvalue()
    if not raw or len(raw) > MAX_HELPER_ZIP:
        raise ValueError("Agent helper library archive invalid")
    return raw


def artifacts() -> dict[str, bytes]:
    return {
        "agent-helper.py": launcher_bytes(),
        "agent-helperlib.zip": library_zip_bytes(),
    }
