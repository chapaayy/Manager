"""Single Remnawave panel connection state."""
from __future__ import annotations

import json
import time

from ..core.database import connect, decrypt, encrypt, transaction
from ..core.events import record as event

def get_panel() -> dict:
    with connect() as c:
        r = c.execute("SELECT * FROM panel WHERE id=1").fetchone()
        if not r:
            raise RuntimeError("Storage not initialized")
    return {
        "url": r["url"], "outbound_ip": r["outbound_ip"],
        "has_token": bool(r["token_enc"]),
        "has_caddy_api_key": bool(r["caddy_api_key_enc"]),
        "monitor_interval": float(r["monitor_interval"]),
        "config_profile_uuid": r["config_profile_uuid"],
        "inbound_uuids": json.loads(r["inbound_uuids_json"]),
        "updated_at": r["updated_at"],
    }


def set_panel(*, url: str, outbound_ip: str = "", token: str | None = None,
              caddy_api_key: str | None = None):
    with transaction() as c:
        row = c.execute("SELECT url,token_enc,caddy_api_key_enc FROM panel WHERE id=1").fetchone()
        previous = row["token_enc"]
        current_url = row["url"]
        current_caddy_key = row["caddy_api_key_enc"] if current_url == url else ""
        if caddy_api_key is not None:
            current_caddy_key = encrypt(caddy_api_key) if caddy_api_key else ""
        if current_url and current_url != url and token is None:
            raise ValueError("При смене домена панели повторно введи API-токен")
        if token is not None:
            previous = encrypt(token) if token else ""
        c.execute("""UPDATE panel SET url=?, outbound_ip=?, token_enc=?,caddy_api_key_enc=?,
                  config_profile_uuid=CASE WHEN url<>? THEN '' ELSE config_profile_uuid END,
                  inbound_uuids_json=CASE WHEN url<>? THEN '[]' ELSE inbound_uuids_json END,
                  updated_at=? WHERE id=1""",
                  (url, outbound_ip, previous, current_caddy_key, url, url, int(time.time())))
        event(c, "panel.update", "panel", "Updated single panel connection")
    return get_panel()


def get_panel_token() -> str:
    with connect() as c:
        row = c.execute("SELECT token_enc FROM panel WHERE id=1").fetchone()
    return decrypt(row["token_enc"]) if row and row["token_enc"] else ""


def get_caddy_api_key() -> str:
    with connect() as c:
        row = c.execute("SELECT caddy_api_key_enc FROM panel WHERE id=1").fetchone()
    return decrypt(row["caddy_api_key_enc"]) if row and row["caddy_api_key_enc"] else ""


def set_panel_profile(profile_uuid: str, inbound_uuids: list[str]):
    with transaction() as c:
        c.execute("""UPDATE panel SET config_profile_uuid=?,inbound_uuids_json=?,updated_at=? WHERE id=1""",
                  (profile_uuid, json.dumps(inbound_uuids), int(time.time())))
        event(c, "panel.profile", profile_uuid, "Selected inbound IDs")
    return get_panel()
