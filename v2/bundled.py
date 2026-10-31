"""Idempotent starter library from user's Xray example and legacy installer.

New starter files are inserted once per DB. Existing files are never
overwritten, and intentional deletions are not resurrected on restart.
"""
from __future__ import annotations
from pathlib import Path
import time
import uuid

from . import storage

ROOT=Path(__file__).resolve().parent/"data"
STARTERS=(
    ("XPPN · Xray Bridge VLESS TLS","xray","xray_bridge_template.json"),
    ("XPPN · Nginx fallback (80/8080)","nginx","nginx.conf"),
    ("XPPN · Nginx Compose","nginx_compose","nginx-compose.yml"),
    ("XPPN · Remnawave Node Compose","node_compose","remnanode-compose.yml"),
)
DEFAULT_PRESET="XPPN · Bridge VLESS TLS RAW"


def seed_defaults() -> None:
    with storage.transaction() as c:
        now=int(time.time())
        ids={}
        for name,kind,filename in STARTERS:
            key="starter:"+kind+":"+filename
            old=c.execute("SELECT id FROM library_configs WHERE kind=? AND name=?",
                          (kind,name)).fetchone()
            if old:
                ids[kind]=old["id"]
            elif not c.execute("SELECT 1 FROM starter_seeds WHERE name=?",(key,)).fetchone():
                content=(ROOT/filename).read_text(encoding="utf-8")
                ident=str(uuid.uuid4())
                c.execute("""INSERT INTO library_configs
                    (id,name,kind,content_enc,revision,created_at,updated_at)
                    VALUES(?,?,?,?,1,?,?)""",
                    (ident,name,kind,storage.encrypt(content),now,now))
                ids[kind]=ident
            if not c.execute("SELECT 1 FROM starter_seeds WHERE name=?",(key,)).fetchone():
                c.execute("INSERT INTO starter_seeds(name,applied_at) VALUES(?,?)",(key,now))
        key="preset:"+DEFAULT_PRESET
        existing=c.execute("SELECT id FROM presets WHERE name=?",(DEFAULT_PRESET,)).fetchone()
        if not existing and not c.execute("SELECT 1 FROM starter_seeds WHERE name=?",(key,)).fetchone():
            # If the user has intentionally deleted one starter file, never invent
            # references or re-create the deleted file.
            if len(ids)==len(STARTERS):
                preset_id=str(uuid.uuid4())
                c.execute("INSERT INTO presets(id,name,description,created_at,updated_at) VALUES(?,?,?,?,?)",
                          (preset_id,DEFAULT_PRESET,
                           "Xray по примеру пользователя + Nginx и Compose из прежнего установщика; нужны реальные домены, сертификаты и проверка TLS.",
                           now,now))
                for kind,file_id in ids.items():
                    c.execute("INSERT INTO preset_items(preset_id,config_id,kind) VALUES(?,?,?)",
                              (preset_id,file_id,kind))
        if not c.execute("SELECT 1 FROM starter_seeds WHERE name=?",(key,)).fetchone():
            c.execute("INSERT INTO starter_seeds(name,applied_at) VALUES(?,?)",(key,now))
