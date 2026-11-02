"""Base Manager v2 SQLite schema and additive migrations."""
from __future__ import annotations

import os

from ..core.database import cipher, connect, db_path

def init_db():
    cipher()  # Check encryption settings before touching a database.
    path = db_path()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with connect() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript("""
        CREATE TABLE IF NOT EXISTS panel (
            id INTEGER PRIMARY KEY CHECK(id=1),
            url TEXT NOT NULL DEFAULT '',
            outbound_ip TEXT NOT NULL DEFAULT '',
            token_enc TEXT NOT NULL DEFAULT '',
            caddy_api_key_enc TEXT NOT NULL DEFAULT '',
            config_profile_uuid TEXT NOT NULL DEFAULT '',
            inbound_uuids_json TEXT NOT NULL DEFAULT '[]',
            monitor_interval REAL NOT NULL DEFAULT 5,
            updated_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS nodes (
            id TEXT PRIMARY KEY,
            code TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            domain TEXT NOT NULL UNIQUE,
            country TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('regular','entry','exit')),
            status TEXT NOT NULL DEFAULT 'planned',
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS bridges (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            entry_id TEXT NOT NULL UNIQUE REFERENCES nodes(id) ON DELETE RESTRICT,
            revision INTEGER NOT NULL DEFAULT 0,
            snapshot_enc TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS bridge_exits (
            bridge_id TEXT NOT NULL REFERENCES bridges(id) ON DELETE CASCADE,
            exit_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
            inbound_port INTEGER NOT NULL CHECK(inbound_port BETWEEN 443 AND 8999),
            uuid_enc TEXT NOT NULL,
            PRIMARY KEY(bridge_id,exit_id),
            UNIQUE(bridge_id,inbound_port)
        );
        CREATE TABLE IF NOT EXISTS plans (
            id TEXT PRIMARY KEY,
            bridge_id TEXT NOT NULL REFERENCES bridges(id) ON DELETE CASCADE,
            exit_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
            source_revision INTEGER NOT NULL,
            proposal_enc TEXT NOT NULL,
            outgoing_uuid_enc TEXT NOT NULL,
            inbound_port INTEGER NOT NULL,
            diff_redacted TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('draft','approved','deployed','rejected')),
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_plans_bridge ON plans(bridge_id,created_at DESC);
        CREATE TABLE IF NOT EXISTS node_installations (
            node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            ssh_fingerprint TEXT NOT NULL,
            stage TEXT NOT NULL CHECK(stage IN
               ('queued','installing','registered','ready','failed','interrupted')),
            note TEXT NOT NULL DEFAULT '',
            remote_uuid TEXT NOT NULL DEFAULT '',
            profile_uuid TEXT NOT NULL DEFAULT '',
            preset_id TEXT NOT NULL DEFAULT '',
            preset_snapshot_enc TEXT NOT NULL DEFAULT '',
            ssh_password_enc TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_installed_vps_ip ON node_installations(ip);
        CREATE TABLE IF NOT EXISTS node_tls_sync (
            node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
            sync_key_enc TEXT NOT NULL DEFAULT '',
            fingerprint TEXT NOT NULL DEFAULT '',
            expires_at INTEGER NOT NULL DEFAULT 0,
            last_checked INTEGER NOT NULL DEFAULT 0,
            last_applied INTEGER NOT NULL DEFAULT 0,
            last_error TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS node_lifecycle(
            node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
            archived INTEGER NOT NULL DEFAULT 0,
            phase TEXT NOT NULL DEFAULT '',
            job_id TEXT NOT NULL DEFAULT '',
            delete_profile INTEGER NOT NULL DEFAULT 1,
            updated_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS starter_seeds (
            name TEXT PRIMARY KEY,
            applied_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS library_configs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('xray','nginx','nginx_compose','node_compose')),
            content_enc TEXT NOT NULL,
            revision INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS presets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            mode TEXT NOT NULL DEFAULT 'custom',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS preset_items (
            preset_id TEXT NOT NULL REFERENCES presets(id) ON DELETE CASCADE,
            config_id TEXT NOT NULL REFERENCES library_configs(id) ON DELETE RESTRICT,
            kind TEXT NOT NULL,
            PRIMARY KEY(preset_id,kind)
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time INTEGER NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            message TEXT NOT NULL
        );
        INSERT OR IGNORE INTO panel(id) VALUES(1);
        """)
        # Add new credentials without resetting an existing v2 database.
        columns = {r["name"] for r in c.execute("PRAGMA table_info(panel)").fetchall()}
        if "caddy_api_key_enc" not in columns:
            c.execute("ALTER TABLE panel ADD COLUMN caddy_api_key_enc TEXT NOT NULL DEFAULT ''")
        if "monitor_interval" not in columns:
            c.execute("ALTER TABLE panel ADD COLUMN monitor_interval REAL NOT NULL DEFAULT 5")
        installation_columns={r["name"] for r in c.execute("PRAGMA table_info(node_installations)")}
        if "preset_id" not in installation_columns:
            c.execute("ALTER TABLE node_installations ADD COLUMN preset_id TEXT NOT NULL DEFAULT ''")
        if "preset_snapshot_enc" not in installation_columns:
            c.execute("ALTER TABLE node_installations ADD COLUMN preset_snapshot_enc TEXT NOT NULL DEFAULT ''")
        if "ssh_password_enc" not in installation_columns:
            c.execute("ALTER TABLE node_installations ADD COLUMN ssh_password_enc TEXT NOT NULL DEFAULT ''")
        preset_columns={r["name"] for r in c.execute("PRAGMA table_info(presets)")}
        if "mode" not in preset_columns:
            c.execute("ALTER TABLE presets ADD COLUMN mode TEXT NOT NULL DEFAULT 'custom'")
