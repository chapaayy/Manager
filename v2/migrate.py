"""One-way, explicit migration of *only* the main Remnawave connection from v1.

The legacy database is opened with SQLite mode=ro; other projects and unknown
VPS deployment state are NOT imported. No legacy tables are created in v2.
Run a dry inspection before adding --execute.
"""
import argparse
import json
import os
import sqlite3
from pathlib import Path
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken
from . import storage, remnawave


class MigrationError(ValueError):
    pass


def inspect_legacy(source: str) -> dict:
    path = Path(source).expanduser().resolve(strict=True)
    if not path.is_file():
        raise MigrationError("Ожидается путь к файлу SQLite базы v1")
    uri = "file:" + quote(str(path), safe="/") + "?mode=ro"
    try:
        db = sqlite3.connect(uri, uri=True)
        db.row_factory = sqlite3.Row
        try:
            project = db.execute("SELECT * FROM projects WHERE id='default'").fetchone()
            count = db.execute("SELECT count(*) FROM projects").fetchone()[0]
            nodes = db.execute("SELECT count(*) FROM nodes").fetchone()[0]
        finally:
            db.close()
    except sqlite3.Error as e:
        raise MigrationError("Не удалось прочитать базу v1: "+str(e)) from None
    if not project:
        raise MigrationError("Не найдена основная панель id=default в v1")
    return {"source": str(path), "panel": dict(project),
            "other_panels_ignored": max(0, count-1),
            "legacy_nodes_not_imported": nodes}


def migrate_panel(source: str, *, execute: bool = False) -> dict:
    original = inspect_legacy(source)
    p = original["panel"]
    view = {
        "primary_panel_found": True,
        "panel_url": p.get("panel_url", ""),
        "other_panels_ignored": original["other_panels_ignored"],
        "legacy_nodes_not_imported": original["legacy_nodes_not_imported"],
        "executed": False,
        "note": "Это только перенос настроек одной основной Remnawave; ноды не переносятся.",
    }
    if not execute:
        return view
    v1_key = os.environ.get("XPPN_V1_DATA_KEY")
    if not v1_key:
        raise MigrationError("Для переноса нужен XPPN_V1_DATA_KEY в окружении")
    token = ""
    if p.get("api_token_enc"):
        try:
            token = Fernet(v1_key.encode()).decrypt(p["api_token_enc"].encode()).decode()
        except (InvalidToken,ValueError,UnicodeDecodeError):
            raise MigrationError("Не удалось расшифровать токен v1; проверь XPPN_V1_DATA_KEY") from None
    storage.init_db()
    if storage.get_panel()["url"] or storage.list_nodes():
        raise MigrationError("v2 уже настроена. Перенос не будет перезаписывать текущие данные.")
    url = p.get("panel_url", "")
    if url:
        url = remnawave.validate_url(url)
    storage.set_panel(
        url=url, outbound_ip=p.get("panel_ip", ""),
        token=token,
    )
    profile = p.get("panel_config_profile_uuid", "")
    try:
        inbounds = json.loads(p.get("panel_active_inbounds", "[]"))
    except (TypeError, ValueError):
        inbounds = []
    if profile and isinstance(inbounds, list) and inbounds:
        storage.set_panel_profile(profile, inbounds)
    view["executed"] = True
    view["note"] = "Панель перенесена, но до установки нод проверь живой API и inbound-ы."
    return view


def cli():
    parser = argparse.ArgumentParser(description="Migrate single Remnawave panel from v1 read-only")
    parser.add_argument("--source", required=True, help="Path to existing v1 SQLite DB")
    parser.add_argument("--execute", action="store_true", help="Actually populate empty v2 DB")
    args = parser.parse_args()
    result = migrate_panel(args.source, execute=args.execute)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    cli()
