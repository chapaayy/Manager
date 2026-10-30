"""Reusable encrypted configuration files and named bundles.

The library stores file contents in the manager database, never in GitHub. Bundles
reference the latest saved library revisions; no endpoint applies anything to a VPS.
"""
import sqlite3
import time
import uuid
from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field
from . import store

KINDS = ('nginx', 'nginx_compose', 'node_compose')


class LibraryBody(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    kind: str
    content: str = Field(max_length=100000)
    revision: int | None = Field(default=None, ge=1)


class PresetBody(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default='', max_length=700)
    config_ids: list[str] = Field(min_length=1, max_length=3)


def check_library(body):
    if body.kind not in KINDS or not body.name.strip() or '\x00' in body.content:
        raise HTTPException(422, 'Invalid name, file type or content')
    if len(body.content.encode('utf-8')) > 100000:
        raise HTTPException(413, 'File exceeds 100 KB')


def view_library(row, detail=False):
    data = {k: row[k] for k in ('id', 'name', 'kind', 'revision', 'created_at', 'updated_at')}
    if detail:
        data['content'] = store.FERNET.decrypt(row['content_enc'].encode()).decode('utf-8')
    return data


def preset_view(c, row):
    items = [dict(r) for r in c.execute(
        """SELECT i.kind, f.id AS config_id, f.name AS config_name, f.revision
           FROM config_preset_items i JOIN library_configs f ON f.id=i.config_id
           WHERE i.preset_id=? ORDER BY i.kind""", (row['id'],))]
    return {**dict(row), 'items': items}


def validate_preset_files(c, config_ids):
    if len(set(config_ids)) != len(config_ids):
        raise HTTPException(422, 'A file was selected more than once')
    kinds = set()
    selected = []
    for ident in config_ids:
        row = c.execute('SELECT id,kind FROM library_configs WHERE id=?', (ident,)).fetchone()
        if row is None:
            raise HTTPException(422, 'The preset contains an unknown file')
        if row['kind'] in kinds:
            raise HTTPException(422, 'A preset can include only one config per file type')
        kinds.add(row['kind'])
        selected.append(row)
    return selected


def register(app, admin, write_access):
    @app.get('/api/config-library')
    def list_files(_=Depends(admin)):
        with store.connect() as c:
            return [view_library(row) for row in c.execute(
                'SELECT * FROM library_configs ORDER BY kind,name COLLATE NOCASE')]

    @app.post('/api/config-library')
    def create_file(body: LibraryBody, _=Depends(write_access)):
        check_library(body)
        ident = str(uuid.uuid4())
        now = int(time.time())
        encrypted = store.FERNET.encrypt(body.content.encode()).decode()
        with store.connect() as c:
            c.execute('INSERT INTO library_configs(id,name,kind,content_enc,created_at,updated_at) VALUES(?,?,?,?,?,?)',
                      (ident,body.name.strip(),body.kind,encrypted,now,now))
            row = c.execute('SELECT * FROM library_configs WHERE id=?', (ident,)).fetchone()
            return view_library(row)

    @app.get('/api/config-library/{config_id}')
    def get_file(config_id: str, _=Depends(admin)):
        with store.connect() as c:
            row=c.execute('SELECT * FROM library_configs WHERE id=?',(config_id,)).fetchone()
            if not row: raise HTTPException(404, 'Config not found')
            return view_library(row, True)

    @app.put('/api/config-library/{config_id}')
    def update_file(config_id: str, body: LibraryBody, _=Depends(write_access)):
        check_library(body)
        if body.revision is None:
            raise HTTPException(422, 'Revision is required to avoid overwriting newer changes')
        now=int(time.time())
        encrypted=store.FERNET.encrypt(body.content.encode()).decode()
        with store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            row=c.execute('SELECT kind,revision FROM library_configs WHERE id=?',(config_id,)).fetchone()
            if not row:
                c.execute('ROLLBACK')
                raise HTTPException(404, 'Config not found')
            if row['kind']!=body.kind or row['revision']!=body.revision:
                c.execute('ROLLBACK')
                raise HTTPException(409, 'File type or revision changed. Reload the file')
            c.execute('UPDATE library_configs SET name=?,content_enc=?,revision=revision+1,updated_at=? WHERE id=?',
                      (body.name.strip(),encrypted,now,config_id))
            updated=c.execute('SELECT * FROM library_configs WHERE id=?',(config_id,)).fetchone()
            c.execute('COMMIT')
            return view_library(updated)

    @app.delete('/api/config-library/{config_id}')
    def delete_file(config_id: str, _=Depends(write_access)):
        with store.connect() as c:
            n=c.execute('SELECT count(*) FROM config_preset_items WHERE config_id=?',(config_id,)).fetchone()[0]
            if n: raise HTTPException(409, 'This file is used in a preset. Remove it from the preset first')
            affected=c.execute('DELETE FROM library_configs WHERE id=?',(config_id,)).rowcount
            if not affected: raise HTTPException(404, 'Config not found')
        return {'ok':True}

    @app.get('/api/config-presets')
    def list_presets(_=Depends(admin)):
        with store.connect() as c:
            return [preset_view(c,row) for row in c.execute(
                'SELECT * FROM config_presets ORDER BY updated_at DESC,name COLLATE NOCASE').fetchall()]

    def save_preset(body, preset_id=None):
        with store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            selected=validate_preset_files(c,body.config_ids)
            now=int(time.time())
            if preset_id is not None:
                if not c.execute('SELECT 1 FROM config_presets WHERE id=?',(preset_id,)).fetchone():
                    c.execute('ROLLBACK')
                    raise HTTPException(404,'Preset not found')
                c.execute('UPDATE config_presets SET name=?,description=?,updated_at=? WHERE id=?',
                          (body.name.strip(),body.description.strip(),now,preset_id))
                c.execute('DELETE FROM config_preset_items WHERE preset_id=?',(preset_id,))
                ident=preset_id
            else:
                ident=str(uuid.uuid4())
                c.execute('INSERT INTO config_presets VALUES(?,?,?,?,?)',
                          (ident,body.name.strip(),body.description.strip(),now,now))
            for item in selected:
                c.execute('INSERT INTO config_preset_items VALUES(?,?,?)',(ident,item['id'],item['kind']))
            result=preset_view(c,c.execute('SELECT * FROM config_presets WHERE id=?',(ident,)).fetchone())
            c.execute('COMMIT')
            return result

    @app.post('/api/config-presets')
    def create_preset(body: PresetBody, _=Depends(write_access)):
        return save_preset(body)

    @app.put('/api/config-presets/{preset_id}')
    def update_preset(preset_id: str, body: PresetBody, _=Depends(write_access)):
        return save_preset(body,preset_id)

    @app.delete('/api/config-presets/{preset_id}')
    def delete_preset(preset_id: str, _=Depends(write_access)):
        with store.connect() as c:
            affected=c.execute('DELETE FROM config_presets WHERE id=?',(preset_id,)).rowcount
            if not affected:raise HTTPException(404,'Preset not found')
        return {'ok':True}
