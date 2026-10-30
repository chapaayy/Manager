"""Versioned starter files from user's Xray example and XPPN legacy installer.

Seed only empty libraries. Never overwrite existing configs or presets.
These are editable templates, not proof of a production-ready TLS node.
"""
from __future__ import annotations
from pathlib import Path
import time
import uuid

from . import storage

ROOT = Path(__file__).resolve().parent / "data"
STARTERS = (
    ("XPPN · Xray Bridge VLESS TLS", "xray", "xray_bridge_template.json"),
    ("XPPN · Nginx fallback (80/8080)", "nginx", "nginx.conf"),
    ("XPPN · Nginx Compose", "nginx_compose", "nginx-compose.yml"),
    ("XPPN · Remnawave Node Compose", "node_compose", "remnanode-compose.yml"),
)
DEFAULT_PRESET = "XPPN · Bridge VLESS TLS RAW"


def seed_defaults() -> None:
    """In an empty library, add one usable template bundle and one preset.

    This is a database-only operation. Never touches nodes or Remnawave.
    """
    with storage.transaction() as c:
        if c.execute("SELECT 1 FROM library_configs LIMIT 1").fetchone():
            return
        now = int(time.time())
        ids = []
        for name, kind, filename in STARTERS:
            content = (ROOT / filename).read_text(encoding="utf-8")
            file_id = str(uuid.uuid4())
            c.execute(
                """INSERT INTO library_configs
                   (id,name,kind,content_enc,revision,created_at,updated_at)
                   VALUES(?,?,?,?,1,?,?)""",
                (file_id,name,kind,storage.encrypt(content),now,now),
            )
            ids.append((file_id,kind))
        preset_id = str(uuid.uuid4())
        c.execute(
            "INSERT INTO presets(id,name,description,created_at,updated_at) VALUES(?,?,?,?,?)",
            (preset_id,DEFAULT_PRESET,
             "Базовый комплект из рабочего Xray-примера и Nginx/Compose прежнего установщика; перед запуском проверяются домены, UUID и TLS.",
             now,now)
        )
        for file_id, kind in ids:
            c.execute("INSERT INTO preset_items(preset_id,config_id,kind) VALUES(?,?,?)",
                      (preset_id,file_id,kind))
        storage.event(c,"library.seed",preset_id,"Added baseline Xray, Nginx and Compose templates")
