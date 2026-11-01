"""Idempotent XPPN starter library: two Xray roles and shared VPS files.

Existing user-edited content and existing preset associations are never
overwritten. Deleted starter files are not resurrected.
"""
from __future__ import annotations
from pathlib import Path
import time
import uuid

from . import storage

ROOT=Path(__file__).resolve().parent/"data"
STARTERS=(
    ("XPPN · Xray Bridge VLESS TLS","xray","xray_bridge_template.json"),
    ("XPPN · Xray Direct VLESS TLS","xray","xray_direct_template.json"),
    ("XPPN · Nginx fallback (80/8080)","nginx","nginx.conf"),
    ("XPPN · Nginx Compose","nginx_compose","nginx-compose.yml"),
    ("XPPN · Remnawave Node Compose","node_compose","remnanode-compose.yml"),
)
BRIDGE_PRESET="XPPN · Bridge VLESS TLS RAW"
DIRECT_PRESET="XPPN · Direct VLESS TLS RAW"
DEFAULT_PRESET=DIRECT_PRESET


def seed_defaults() -> None:
    with storage.transaction() as c:
        now=int(time.time())
        ids={}
        for name,kind,filename in STARTERS:
            key="starter:"+kind+":"+filename
            old=c.execute("SELECT id FROM library_configs WHERE kind=? AND name=?",
                          (kind,name)).fetchone()
            if old:
                ids[filename]=old["id"]
            elif not c.execute("SELECT 1 FROM starter_seeds WHERE name=?",(key,)).fetchone():
                ident=str(uuid.uuid4())
                c.execute("""INSERT INTO library_configs
                    (id,name,kind,content_enc,revision,created_at,updated_at)
                    VALUES(?,?,?,?,1,?,?)""",
                    (ident,name,kind,storage.encrypt((ROOT/filename).read_text("utf-8")),now,now))
                ids[filename]=ident
            if not c.execute("SELECT 1 FROM starter_seeds WHERE name=?",(key,)).fetchone():
                c.execute("INSERT INTO starter_seeds(name,applied_at) VALUES(?,?)",(key,now))
        common=("nginx.conf","nginx-compose.yml","remnanode-compose.yml")
        # Bridge topology is disabled. Keep the bridge Xray file as a plain
        # library config, but only seed the normal-node installation bundle.
        existing_bridge=c.execute("SELECT id,mode FROM presets WHERE name=?",(BRIDGE_PRESET,)).fetchone()
        if existing_bridge and existing_bridge["mode"]=="bridge":
            c.execute("UPDATE presets SET mode='custom' WHERE id=?",(existing_bridge["id"],))
        for name,mode,xray in (
            (DIRECT_PRESET,"direct","xray_direct_template.json"),
        ):
            key="preset:"+name
            existing=c.execute("SELECT id,mode FROM presets WHERE name=?",(name,)).fetchone()
            if existing:
                pass
            elif not c.execute("SELECT 1 FROM starter_seeds WHERE name=?",(key,)).fetchone():
                if all(f in ids for f in (xray,*common)):
                    preset_id=str(uuid.uuid4())
                    description=("Прямой VLESS TLS сервер: Xray 443 + Nginx + Docker."
                                 if mode=="direct" else
                                 "Входной мост 443/8443: безопасный старт без выходных маршрутов. "
                                 "Связи с выходными VPS настраиваются отдельно.")
                    c.execute("""INSERT INTO presets
                        (id,name,description,mode,created_at,updated_at)
                        VALUES(?,?,?,?,?,?)""",
                        (preset_id,name,description,mode,now,now))
                    for filename in (xray,*common):
                        kind=next(k for n,k,f in STARTERS if f==filename)
                        c.execute("INSERT INTO preset_items(preset_id,config_id,kind) VALUES(?,?,?)",
                                  (preset_id,ids[filename],kind))
            if not c.execute("SELECT 1 FROM starter_seeds WHERE name=?",(key,)).fetchone():
                c.execute("INSERT INTO starter_seeds(name,applied_at) VALUES(?,?)",(key,now))
