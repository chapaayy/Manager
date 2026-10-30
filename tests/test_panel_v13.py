"""No network or live VPS required: integration checks for new project registration flow."""
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi import HTTPException
from manager import store, projects, remna_api, app

P='11111111-2222-4333-8444-555555555555'
I='aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
N='bbbbbbbb-2222-4333-8444-555555555555'

def test_project_sync_key_and_profiles(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        old_db,old_fernet=store.DB,store.FERNET
        store.DB=str(Path(tmp)/'manager.db');store.FERNET=Fernet(Fernet.generate_key());store.init_db()
        try:
            pid=projects.create_project({'name':'test','panel_url':'https://panel.example.com','api_token':'safe_test_token_aaaaaaaaaaaaaa'})
            def fake_request(pid1,method,path,body=None):
                if path=='/api/config-profiles':
                    return {'response':{'configProfiles':[{'uuid':P,'name':'MAIN'}]}}
                if path.endswith('/inbounds'):
                    return {'response':{'inbounds':[{'uuid':I,'tag':'VLESS-TLS'}]}}
                if path=='/api/keygen':return {'response':{'pubKey':'A'*44}}
                raise AssertionError(path)
            monkeypatch.setattr(remna_api,'request',fake_request)
            resp=app.panel_sync(pid,True)
            assert resp['has_node_key'] is True
            assert resp['profiles'][0]['inbounds'][0]['uuid']==I
            assert 'A'*44 not in json.dumps(resp)
            assert projects.project_secret(pid)['secret_key']=='A'*44
            app.panel_defaults(pid,app.PanelDefaultsBody(config_profile_uuid=P,active_inbounds=[I],country_code='NL'),True)
            with store.connect() as db:
                r=db.execute('SELECT * FROM projects WHERE id=?',(pid,)).fetchone()
                assert r['panel_config_profile_uuid']==P
                assert json.loads(r['panel_active_inbounds'])==[I]
                assert r['panel_country_code']=='NL'
            assert projects.project_view(r)['has_secret_key']
            assert 'A'*44 not in json.dumps(projects.project_view(r))
        finally:
            store.DB,store.FERNET=old_db,old_fernet

def test_registration_only_once_after_telemetry(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        old_db,old_fernet=store.DB,store.FERNET
        store.DB=str(Path(tmp)/'manager.db');store.FERNET=Fernet(Fernet.generate_key());store.init_db()
        try:
            with store.connect() as db:
                db.execute("INSERT INTO nodes(id,name,ip,token_hash,ssh_fingerprint,stage,preset,created_at,project_id,panel_auto_profile_uuid,panel_auto_inbounds,panel_auto_country) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                            ('n1','NL1','1.1.1.1','hash','SHA256:a','verifying','node',1,'default',P,json.dumps([I]),'NL'))
            store.verify_telemetry('n1',{'containers':[{'Names':'remnanode','State':'running'}]})
            with store.connect() as db:assert db.execute("SELECT stage FROM nodes WHERE id='n1'").fetchone()['stage']=='registering'
            called=[]
            def fake_register(*args):called.append(args);return N
            monkeypatch.setattr(remna_api,'register_node',fake_register)
            app.auto_register_after_install('n1')
            app.auto_register_after_install('n1')
            assert len(called)==1
            with store.connect() as db:
                r=db.execute("SELECT stage,panel_node_uuid FROM nodes WHERE id='n1'").fetchone()
                assert r['stage']=='ready' and r['panel_node_uuid']==N
        finally:store.DB,store.FERNET=old_db,old_fernet

def test_registration_error_does_not_reinstall(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        old_db,old_fernet=store.DB,store.FERNET
        store.DB=str(Path(tmp)/'manager.db');store.FERNET=Fernet(Fernet.generate_key());store.init_db()
        try:
            with store.connect() as db:
                db.execute("INSERT INTO nodes(id,name,ip,token_hash,ssh_fingerprint,stage,preset,created_at,project_id,panel_auto_profile_uuid,panel_auto_inbounds,panel_auto_country) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                            ('n1','NL1','1.1.1.1','hash','SHA256:a','registering','node',1,'default',P,json.dumps([I]),'NL'))
            def fail(*args):raise remna_api.PanelError('Remote panel 502')
            monkeypatch.setattr(remna_api,'register_node',fail)
            app.auto_register_after_install('n1')
            with store.connect() as db:
                r=db.execute("SELECT stage,panel_registering FROM nodes WHERE id='n1'").fetchone()
                assert r['stage']=='registration_failed' and r['panel_registering']==0
                assert not db.execute("SELECT 1 FROM jobs WHERE node_id='n1'").fetchone()
        finally:store.DB,store.FERNET=old_db,old_fernet

def test_changed_panel_clears_stale_defaults():
    with tempfile.TemporaryDirectory() as tmp:
        old_db,old_fernet=store.DB,store.FERNET
        store.DB=str(Path(tmp)/'manager.db');store.FERNET=Fernet(Fernet.generate_key());store.init_db()
        try:
            pid=projects.create_project({'name':'test','panel_url':'https://old.example.com','api_token':'token_'+'a'*24})
            with store.connect() as db:
                db.execute('UPDATE projects SET panel_config_profile_uuid=?,panel_active_inbounds=?,secret_key_enc=? WHERE id=?',(P,json.dumps([I]),projects._encrypt_secret('a'*44),pid))
            projects.update_project(pid,{'panel_url':'https://new.example.com'})
            with store.connect() as db:
                r=db.execute('SELECT * FROM projects WHERE id=?',(pid,)).fetchone()
                assert not r['secret_key_enc'] and not r['panel_config_profile_uuid'] and r['panel_active_inbounds']=='[]'
        finally:store.DB,store.FERNET=old_db,old_fernet
