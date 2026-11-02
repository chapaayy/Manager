"""Validated process configuration.

Keep environment parsing in one place so API and domain modules do not reach
into os.environ independently for Manager authentication settings.
"""
from __future__ import annotations

import os


def database_path() -> str:
    return os.environ.get("XPPN_V2_DB", "/data/xppn-v2.db")


def data_key() -> str:
    key = os.environ.get("XPPN_DATA_KEY", "")
    if not key:
        raise RuntimeError("XPPN_DATA_KEY is required; do not generate a new key on each reboot")
    return key


def session_secret() -> str:
    key = os.environ.get("XPPN_V2_SESSION_SECRET", "")
    if len(key) < 32:
        raise RuntimeError("Set XPPN_V2_SESSION_SECRET (at least 32 random characters)")
    return key


def admin_username() -> str:
    name = os.environ.get("XPPN_V2_ADMIN_USER", "admin")
    if not 3 <= len(name) <= 40 or not all(c.isalnum() or c in "_.-" for c in name):
        raise RuntimeError("XPPN_V2_ADMIN_USER must be 3–40 safe characters")
    return name


def admin_password_hash() -> str:
    stored = os.environ.get("XPPN_V2_ADMIN_PASSWORD_HASH", "")
    if stored:
        parts = stored.replace("$", ":").split(":")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            raise RuntimeError("Invalid XPPN_V2_ADMIN_PASSWORD_HASH")
        try:
            rounds = int(parts[1])
            if not 300_000 <= rounds <= 2_000_000:
                raise ValueError()
            salt = bytes.fromhex(parts[2])
            digest = bytes.fromhex(parts[3])
            if len(salt) != 16 or len(digest) != 32:
                raise ValueError()
        except ValueError:
            raise RuntimeError("Invalid XPPN_V2_ADMIN_PASSWORD_HASH") from None
        return stored

    # Compatibility for installations created before password hashes became
    # mandatory. setup_env.py replaces this value on the next normal install.
    value = os.environ.get("XPPN_V2_ADMIN_PASSWORD", "")
    if len(value) < 12:
        raise RuntimeError("Configure XPPN_V2_ADMIN_PASSWORD_HASH before starting")
    return ""


def legacy_admin_password() -> str:
    return os.environ.get("XPPN_V2_ADMIN_PASSWORD", "")


def cookie_secure() -> bool:
    return os.environ.get("XPPN_V2_COOKIE_SECURE", "1") != "0"
