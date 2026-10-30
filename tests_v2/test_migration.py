"""Legacy migration reads *only* default Remnawave; no projects survive into v2."""
import json
import sqlite3
from pathlib import Path
import pytest
from cryptography.fernet import Fernet
from v2 import migrate, storage


def test_only_primary_panel_is_migrated_without_writing_old_db(tmp_path,monkeypatch):
    old=tmp_path/"v1.db"
    legacy_key=Fernet.generate_key()
    token="this_is_a_valid_long_secret_token"
    enc=Fernet(legacy_key).encrypt(token.encode()).decode()
    with sqlite3.connect(old) as c:
        c.execute("""CREATE TABLE projects (
            id TEXT PRIMARY KEY,panel_url TEXT,panel_ip TEXT,api_token_enc TEXT,
            panel_config_profile_uuid TEXT,panel_active_inbounds TEXT
        )""")
        c.execute("CREATE TABLE nodes (id TEXT PRIMARY KEY)")
        c.execute("INSERT INTO projects VALUES(?,?,?,?,?,?)",(
            "default","https://panel.example.com","1.1.1.1",enc,
            "11111111-2222-4333-8444-555555555555",
            '["aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"]'))
        c.execute("INSERT INTO projects VALUES(?,?,?,?,?,?)",(
            "other","https://other.example.com","8.8.8.8",enc,"","[]"))
        c.execute("INSERT INTO nodes VALUES('old-vps')")
    monkeypatch.setenv("XPPN_V1_DATA_KEY",legacy_key.decode())
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"v2.sqlite"))
    before=old.read_bytes()
    dry=migrate.migrate_panel(str(old))
    assert dry["primary_panel_found"]
    assert dry["other_panels_ignored"]==1
    assert dry["legacy_nodes_not_imported"]==1
    assert dry["executed"] is False
    assert not (tmp_path/"v2.sqlite").exists()
    done=migrate.migrate_panel(str(old),execute=True)
    assert done["executed"]
    assert storage.get_panel()["url"]=="https://panel.example.com"
    assert storage.get_panel_token()==token
    assert len(storage.get_panel()["inbound_uuids"])==1
    assert storage.list_nodes()==[]
    with storage.connect() as c:
        tables=[r["name"] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        ciphertext=c.execute("SELECT token_enc FROM panel WHERE id=1").fetchone()["token_enc"]
    assert "projects" not in tables
    assert token not in ciphertext
    assert old.read_bytes()==before
    with pytest.raises(ValueError):
        migrate.migrate_panel(str(old),execute=True)
