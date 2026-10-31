"""Certificate manager regression tests. No live SSH or Remnawave writes."""
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.fernet import Fernet
from v2 import certificates as certs, storage


@pytest.fixture
def cert_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"certs.db"))
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    root=tmp_path/"panel-certs"
    root.mkdir(mode=0o750)
    monkeypatch.setenv("XPPN_V2_PANEL_CERT_DIR",str(root))
    storage.init_db()
    node=storage.create_node(code="RUS10",name="RUS10",country="RU",
                             domain="rus10.gowayot.com",role="regular")
    storage.create_install_job(node["id"],"1.1.1.1",22,"SHA256:"+"a"*43)
    storage.set_install_status(node["id"],"ready","OK",
                               remote_uuid=str(uuid.uuid4()),profile_uuid=str(uuid.uuid4()))
    return node,root


def bundle(domain="rus10.gowayot.com"):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,domain)])
    now=datetime.now(timezone.utc)
    certificate=(x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(days=1))
        .not_valid_after(now+timedelta(days=60))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]),critical=False)
        .sign(key,hashes.SHA256()))
    return (certificate.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


def test_not_enabled_by_default(cert_environment):
    assert not certs.enabled()
    with pytest.raises(certs.CertError):
        certs.configure(True)
    certs.configure(True,confirmed_panel_mount=True)
    assert certs.enabled()


def test_cert_validation_detects_key_and_domain_errors(cert_environment):
    cert,key=bundle()
    assert certs._validate(cert,key,"rus10.gowayot.com")["expires_at"]>0
    with pytest.raises(certs.CertError,match="другого домена"):
        certs._validate(cert,key,"other.example.org")
    cert2,key2=bundle()
    with pytest.raises(certs.CertError,match="не соответствует"):
        certs._validate(cert,key2,"rus10.gowayot.com")


def test_publication_is_atomic_and_does_not_put_private_key_in_db(cert_environment):
    node,root=cert_environment
    certs.configure(True,confirmed_panel_mount=True)
    cert,key=bundle()
    result=certs.publish(node["code"],cert,key,node["domain"])
    certs.save_status(node["id"],result,True)
    current=root/"RUS10"/"current"
    assert current.is_symlink()
    assert (current/"privkey.key").read_bytes()==key
    assert (current/"fullchain.pem").read_bytes()==cert
    with storage.connect() as db:
        values=str(list(db.execute("SELECT * FROM node_certificates").fetchone()))
    assert key.decode() not in values
    assert certs.paths(node["code"])["keyFile"].endswith("/RUS10/current/privkey.key")


def test_migration_is_explicit_keeps_full_config_and_rollback(cert_environment,monkeypatch):
    from v2 import remnawave
    node,_=cert_environment
    certs.configure(True,confirmed_panel_mount=True)
    cert,key=bundle()
    result=certs.publish(node["code"],cert,key,node["domain"])
    certs.save_status(node["id"],result,True)
    original={"log":{"loglevel":"warning"},"inbounds":[{
        "tag":"RUS10_VLESS_TLS_IN","protocol":"vless","streamSettings":{
            "tlsSettings":{"certificates":[{"key":["SECRET-PRIVATE-KEY"],
                                             "certificate":["SECRET-CERTIFICATE"]}]}}}],
        "outbounds":[{"tag":"DIRECT","protocol":"freedom"}]}
    monkeypatch.setattr(remnawave,"detailed_profile",lambda *_:{
        "name":"XPPN RUS10 RU VLESS TLS","config":original})
    calls=[]
    monkeypatch.setattr(remnawave,"replace_profile_config",
                        lambda profile,config:calls.append(("patch",config)))
    monkeypatch.setattr(remnawave,"restart_node",lambda uid:calls.append(("restart",uid)))
    preview=certs.migration_preview(node["id"])
    assert "SECRET" not in str(preview)
    with pytest.raises(certs.CertError,match="Подтверди"):
        certs.migrate_profile(node["id"],preview["sha256"],False)
    assert calls==[]
    migrated=certs.migrate_profile(node["id"],preview["sha256"],True)
    assert migrated["mode"]=="files"
    updated=calls[0][1]
    assert updated["outbounds"]==original["outbounds"]
    assert "keyFile" in updated["inbounds"][0]["streamSettings"]["tlsSettings"]["certificates"][0]
    assert "SECRET" not in str(updated)
    with storage.connect() as db:
        backup=db.execute("SELECT * FROM cert_profile_backups").fetchone()
        assert "SECRET-PRIVATE-KEY" not in backup["config_enc"]
    restored=certs.restore_profile(node["id"],True)
    assert restored["mode"]=="inline"
    assert calls[-2][1]==original


def test_file_mode_new_cert_requests_only_one_restart(cert_environment,monkeypatch):
    from v2 import remnawave
    node,_=cert_environment
    certs.configure(True,confirmed_panel_mount=True)
    cert,key=bundle()
    monkeypatch.setattr(certs,"_remote_password_bundle",lambda *a:(cert,key))
    restarted=[]
    monkeypatch.setattr(remnawave,"restart_node",lambda uid:restarted.append(uid))
    certs.sync(node["id"],"test-password")
    with storage.transaction() as db:
        db.execute("UPDATE node_certificates SET profile_mode='files',applied_fingerprint='old' WHERE node_id=?",(node["id"],))
    certs.sync(node["id"],"test-password")
    assert len(restarted)==1
    certs.sync(node["id"],"test-password")
    assert len(restarted)==1


def test_ssh_secret_is_never_returned_in_certificate_status(cert_environment):
    node,_=cert_environment
    certs.configure(True,confirmed_panel_mount=True)
    with storage.transaction() as db:
        db.execute("INSERT INTO node_certificates(node_id,sync_key_enc) VALUES(?,?)",
                   (node["id"],storage.encrypt("SECRET_SSH_PRIVATE_KEY")))
    shown=certs.status()
    assert "SECRET_SSH_PRIVATE_KEY" not in str(shown)
    assert shown["nodes"][0]["auto_sync"] is True
