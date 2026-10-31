"""Node-only certificate paths: no Panel secrets, no other profiles changed."""
from copy import deepcopy
from datetime import datetime,timedelta,timezone
from email.utils import format_datetime
import hashlib
import time
import uuid

import pytest
from cryptography.fernet import Fernet
from v2 import agent_transport,node_cert_sync,node_local_tls,remnawave,storage


@pytest.fixture
def ready_node(tmp_path,monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"db.sqlite"))
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    storage.init_db()
    agent_transport.initialize()
    n=storage.create_node(code="RUS10",name="RUS10",domain="rus10.gowayot.com",
                          country="RU",role="regular")
    storage.create_install_job(n["id"],"1.1.1.1",22,"SHA256:"+"a"*43)
    storage.set_install_status(n["id"],"ready","online",
                               remote_uuid=str(uuid.uuid4()),profile_uuid=str(uuid.uuid4()))
    agent_transport.issue_token(n["id"])
    agent_transport.heartbeat(n["id"],{"version":"1.1.0","metrics":{}})
    return n


def cert_status(node,digest="a"*64):
    expiry=format_datetime(datetime.now(timezone.utc)+timedelta(days=50),
                           usegmt=True)
    return {"domain":node["domain"],"certificate_sha256":digest,
            "details":"notAfter="+expiry+"\nsha256 Fingerprint=AA:BB"}


def mock_profile(monkeypatch,node,inline=False,shared=False):
    job=storage.get_install_job(node["id"])
    cert=({"key":["PRIVATE_KEY_OLD"],"certificate":["CERTIFICATE_OLD"]} if inline
          else node_local_tls.paths(node["domain"]))
    original={"inbounds":[{"tag":"RUS10_VLESS_TLS_IN",
                           "streamSettings":{"tlsSettings":{"certificates":[cert]}}}],
              "routing":{"rules":[]},"outbounds":[{"tag":"DIRECT","protocol":"freedom"}]}
    current={"config":deepcopy(original)}
    writes=[]
    restarts=[]
    rows=[{"uuid":job["remote_uuid"],"configProfile":{
        "activeConfigProfileUuid":job["profile_uuid"]}}]
    if shared:
        rows.append({"uuid":str(uuid.uuid4()),"configProfile":{
            "activeConfigProfileUuid":job["profile_uuid"]}})
    monkeypatch.setattr(remnawave,"request",lambda *_:{"response":rows})
    monkeypatch.setattr(remnawave,"detailed_profile",lambda *_:{
        "name":"XPPN RUS10 RU VLESS TLS","config":deepcopy(current["config"])})
    def patch(pid,cfg):
        assert pid==job["profile_uuid"]
        writes.append(deepcopy(cfg))
        current["config"]=deepcopy(cfg)
    monkeypatch.setattr(remnawave,"replace_profile_config",patch)
    monkeypatch.setattr(remnawave,"restart_node",lambda uid:restarts.append(uid))
    monkeypatch.setattr(remnawave,"node_health",lambda uid:{
        "connected":True,"xray_running":True})
    return current,writes,restarts,original


def test_agent_status_never_transports_private_key(ready_node,monkeypatch):
    _,writes,restarts,_=mock_profile(monkeypatch,ready_node)
    result=node_cert_sync.apply_agent_status(ready_node["id"],cert_status(ready_node))
    assert result["mode"]=="node_local_paths"
    assert not result["updated"] and not writes and not restarts
    assert node_cert_sync.sync(ready_node["id"])["action"]=="cert.status"
    with storage.connect() as db:
        records=str([tuple(r) for r in db.execute("SELECT * FROM node_tls_sync")])
    assert "PRIVATE KEY" not in records
    assert "PRIVATE KEY" not in str(node_cert_sync.status())
    with pytest.raises(node_cert_sync.CertificateSyncError,match="отключена"):
        node_cert_sync.apply_agent_export(ready_node["id"],{
            "domain":ready_node["domain"],"key":"PRIVATE KEY"})


def test_certbot_renewal_restarts_only_owned_node_without_profile_patch(ready_node,monkeypatch):
    _,writes,restarts,_=mock_profile(monkeypatch,ready_node)
    node_cert_sync.apply_agent_status(ready_node["id"],cert_status(ready_node))
    changed=node_cert_sync.apply_agent_status(ready_node["id"],cert_status(ready_node,"b"*64))
    assert changed["updated"]
    assert len(restarts)==1 and restarts[0]==storage.get_install_job(ready_node["id"])["remote_uuid"]
    assert not writes
    assert not node_cert_sync.apply_agent_status(
        ready_node["id"],cert_status(ready_node,"b"*64))["updated"]
    assert len(restarts)==1


def test_failed_tls_reload_does_not_mark_renewal_as_applied(ready_node,monkeypatch):
    _,writes,restarts,_=mock_profile(monkeypatch,ready_node)
    node_cert_sync.apply_agent_status(ready_node["id"],cert_status(ready_node))
    monkeypatch.setattr(remnawave,"node_health",lambda *_:{
        "connected":False,"xray_running":False})
    monkeypatch.setattr(node_local_tls.time,"sleep",lambda *_:None)
    with pytest.raises(node_cert_sync.CertificateSyncError,match="не подтвердил запуск"):
        node_cert_sync.apply_agent_status(ready_node["id"],cert_status(ready_node,"b"*64))
    with storage.connect() as db:
        fp=db.execute("SELECT fingerprint FROM node_tls_sync WHERE node_id=?",
                      (ready_node["id"],)).fetchone()["fingerprint"]
    assert fp=="a"*64
    assert not writes and len(restarts)==1


def test_inline_profile_requires_explicit_migration_and_no_implicit_write(ready_node,monkeypatch):
    _,writes,restarts,_=mock_profile(monkeypatch,ready_node,inline=True)
    result=node_cert_sync.apply_agent_status(ready_node["id"],cert_status(ready_node))
    assert result["mode"]=="migration_required"
    assert not writes and not restarts


def test_shared_profile_never_restarted_or_changed(ready_node,monkeypatch):
    _,writes,restarts,_=mock_profile(monkeypatch,ready_node,shared=True)
    with pytest.raises(node_cert_sync.CertificateSyncError,match="другой нодой"):
        node_cert_sync.apply_agent_status(ready_node["id"],cert_status(ready_node))
    assert not writes and not restarts


def test_unknown_profile_assignment_rejected(ready_node,monkeypatch):
    _,writes,restarts,_=mock_profile(monkeypatch,ready_node)
    job=storage.get_install_job(ready_node["id"])
    monkeypatch.setattr(remnawave,"request",lambda *_:{"response":[
        {"uuid":job["remote_uuid"],"configProfile":{"activeConfigProfileUuid":job["profile_uuid"]}},
        {"uuid":str(uuid.uuid4()),"name":"unknown"}]})
    with pytest.raises(node_cert_sync.CertificateSyncError,match="привязки"):
        node_cert_sync.apply_agent_status(ready_node["id"],cert_status(ready_node))
    assert not writes and not restarts


def complete_probe(node):
    cert=agent_transport.enqueue(node["id"],"cert.status")
    agent_transport.poll(node["id"])
    agent_transport.report(node["id"],{"id":cert["id"],"ok":True,
        "result":cert_status(node)})
    compose=agent_transport.enqueue(node["id"],"config.read",{
        "name":"node-compose"})
    agent_transport.poll(node["id"])
    agent_transport.report(node["id"],{"id":compose["id"],"ok":True,"result":{
        "name":"node-compose",
        "content":"services:\n  remnanode:\n    volumes:\n      - /opt/nginx/certs:/opt/nginx/certs:ro\n"}})
    return cert["id"],compose["id"]


def test_migration_changes_only_dedicated_tls_field(ready_node,monkeypatch):
    current,writes,restarts,original=mock_profile(monkeypatch,ready_node,inline=True)
    cert,compose=complete_probe(ready_node)
    result=node_cert_sync.migrate_to_local_paths(
        ready_node["id"],"RUS10",cert,compose)
    assert result["migrated"]
    assert len(writes)==1 and len(restarts)==1
    assert writes[0]["inbounds"][0]["streamSettings"]["tlsSettings"]["certificates"]==[
        node_local_tls.paths(ready_node["domain"])]
    assert writes[0]["routing"]==original["routing"]
    assert writes[0]["outbounds"]==original["outbounds"]
    assert "PRIVATE" not in str(writes[0])


def test_migration_rolls_back_original_profile_if_xray_not_ready(ready_node,monkeypatch):
    current,writes,restarts,original=mock_profile(monkeypatch,ready_node,inline=True)
    cert,compose=complete_probe(ready_node)
    monkeypatch.setattr(remnawave,"node_health",lambda *_:{
        "connected":False,"xray_running":False})
    monkeypatch.setattr(node_local_tls.time,"sleep",lambda *_:None)
    with pytest.raises(node_cert_sync.CertificateSyncError,match="восстановлен"):
        node_cert_sync.migrate_to_local_paths(ready_node["id"],"RUS10",cert,compose)
    assert len(writes)==2 and writes[-1]==original
    assert len(restarts)==2


def test_migration_rejects_wrong_code_and_unverified_mount(ready_node,monkeypatch):
    current,writes,restarts,_=mock_profile(monkeypatch,ready_node,inline=True)
    cert,compose=complete_probe(ready_node)
    with pytest.raises(node_cert_sync.CertificateSyncError,match="точный код"):
        node_cert_sync.migrate_to_local_paths(ready_node["id"],"OTHER",cert,compose)
    with storage.transaction() as db:
        db.execute("UPDATE manager_agent_jobs SET result_json=? WHERE id=?",
                   ('{"name":"node-compose","content":"volumes: []"}',compose))
    with pytest.raises(node_cert_sync.CertificateSyncError,match="read-only mount"):
        node_cert_sync.migrate_to_local_paths(ready_node["id"],"RUS10",cert,compose)
    assert not writes and not restarts


def test_certificate_status_refuses_pem_or_wrong_domain(ready_node):
    with pytest.raises(node_local_tls.LocalTLSError,match="Передача PEM"):
        node_local_tls.agent_status(ready_node["id"],{
            **cert_status(ready_node),"key":"PRIVATE KEY"})
    with pytest.raises(node_local_tls.LocalTLSError,match="домен"):
        node_local_tls.agent_status(ready_node["id"],{
            **cert_status(ready_node),"domain":"other.example.org"})
