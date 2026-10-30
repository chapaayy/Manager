"""Regression: Remnawave node key is base64-encoded JSON containing mTLS certificates.
No live API calls and no real credentials are used.
"""
import base64
import json
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet
from manager import remna_api, projects, store, app
from agent import helper


def fake_bundle():
    data={
        'caCertPem':'-----BEGIN CERTIFICATE-----\n'+'A'*1300+'\n-----END CERTIFICATE-----',
        'nodeCertPem':'-----BEGIN CERTIFICATE-----\n'+'B'*1300+'\n-----END CERTIFICATE-----',
        'nodeKeyPem':'-----BEGIN PRIVATE KEY-----\n'+'C'*1700+'\n-----END PRIVATE KEY-----',
        'jwtPublicKey':'-----BEGIN PUBLIC KEY-----\n'+'D'*500+'\n-----END PUBLIC KEY-----',
    }
    return base64.b64encode(json.dumps(data).encode()).decode()


def test_long_key_end_to_end(monkeypatch):
    bundle=fake_bundle()
    assert 2048 < len(bundle) < 32768
    with tempfile.TemporaryDirectory() as d:
        old_db,old_f=store.DB,store.FERNET
        store.DB=str(Path(d)/'test.db')
        store.FERNET=Fernet(Fernet.generate_key())
        store.init_db()
        try:
            pid=projects.create_project({'name':'Node Key test', 'panel_url':'https://panel.example.com','api_token':'token_'+'T'*30})
            monkeypatch.setattr(remna_api,'request',lambda *args: {'response':{'secretKey':bundle}})
            fetched=remna_api.get_node_public_key(pid)
            assert fetched==bundle
            encrypted=projects._encrypt_secret(fetched,max_length=32768)
            assert store.FERNET.decrypt(encrypted).decode()==bundle
            projects.update_project(pid,{'secret_key':bundle})
            assert projects.project_secret(pid)['secret_key']==bundle
            with store.connect() as db:
                assert projects.project_view(db.execute('SELECT * FROM projects WHERE id=?',(pid,)).fetchone())['has_secret_key']
            app.validate_job('node.install',{'panel_ip':'8.8.8.8','secret_key':bundle,'version':'3.4.2'})
            app.validate_job('legacy.install',{'panel_ip':'8.8.8.8','secret_key':bundle,'version':'3.4.2','domain':'nl.example.com','confirm_clean':True})
            class ReachedFirewall(Exception):pass
            def firewall(_):raise ReachedFirewall()
            monkeypatch.setattr(helper,'ensure_panel_firewall',firewall)
            try:helper.install_node({'panel_ip':'8.8.8.8','secret_key':bundle,'version':'3.4.2'})
            except ReachedFirewall:pass
            else:raise AssertionError('Did not reach firewall validation')
            try:helper.legacy_install({'panel_ip':'8.8.8.8','secret_key':bundle,'version':'3.4.2','domain':'nl.example.com','confirm_clean':True})
            except ReachedFirewall:pass
            else:raise AssertionError('Did not reach firewall validation')
        finally:store.DB,store.FERNET=old_db,old_f


def test_key_controls(monkeypatch):
    good=fake_bundle()
    for bad in (good+'!',good+'\n','A'*32769):
        monkeypatch.setattr(remna_api,'request',lambda *args, key=bad:{'response':{'secretKey':key}})
        try:remna_api.get_node_public_key('dummy')
        except remna_api.PanelError:pass
        else:raise AssertionError('Unsafe key accepted')
    # API bearer tokens remain capped at 2048, unlike node certificate bundles.
    try:projects._encrypt_secret('A'*2049)
    except ValueError:pass
    else:raise AssertionError('Long generic secret accepted')
