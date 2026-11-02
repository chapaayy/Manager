"""SQLite connection and encryption primitives.

This module owns persistence infrastructure only. Table schemas and domain
queries remain in their repositories/storage modules.
"""
from __future__ import annotations

import contextlib
import sqlite3

from cryptography.fernet import Fernet

from . import config


def db_path() -> str:
    return config.database_path()


def cipher() -> Fernet:
    return Fernet(config.data_key().encode())


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
