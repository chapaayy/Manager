"""SQLite connection and encryption primitives.

This module owns persistence infrastructure only. Table schemas and domain
queries remain in their repositories/storage modules.
"""
from __future__ import annotations

import contextlib
import os
import sqlite3

from cryptography.fernet import Fernet


def db_path() -> str:
    return os.environ.get("XPPN_V2_DB", "/data/xppn-v2.db")


def cipher() -> Fernet:
    key = os.environ.get("XPPN_DATA_KEY")
    if not key:
        raise RuntimeError("XPPN_DATA_KEY is required; do not generate a new key on each reboot")
    return Fernet(key.encode())


def encrypt(value: str) -> str:
    return cipher().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt(value: str) -> str:
    return cipher().decrypt(value.encode("ascii")).decode("utf-8")


@contextlib.contextmanager
def connect():
    connection = sqlite3.connect(db_path(), timeout=15, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=15000")
    try:
        yield connection
    finally:
        connection.close()


@contextlib.contextmanager
def transaction():
    with connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
        except Exception:
            connection.execute("ROLLBACK")
            raise
        else:
            connection.execute("COMMIT")
