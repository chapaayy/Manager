"""Regression tests: node-local Certbot sources, Remnawave API-only TLS refresh."""
from copy import deepcopy
from datetime import datetime,timedelta,timezone
import uuid

import pytest
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from v2 import node_cert_sync, remnawave, storage


@pytest.fixture
def ready_node(tmp_path,monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"db.sqlite"))
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    storage.init_db()
    node=storage.create_node(code="RUS10",name="RUS10",domain="rus10.gowayot.com",
                             country="RU",role="regular")
    storage.create_install_job(node["id"],"1.1.1.1",22,"SHA256:"+"a"*43)
    storage.set_install_status(node["id"],"ready","online",
       remote_uuid=str(uuid.uuid4()),profile_uuid=str(uuid.uuid4()))
    return node


def bundle(domain="rus10.gowayot.com"):
    private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,domain)])
    now=datetime.now(timezone.utc)
    certificate=(x509.CertificateBuilder().issuer_name(name).subject_name(name)
       .public_key(private.public_key()).serial_number(x509.random_serial_number())
       .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=60))
       .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]),critical=False)
       .sign(private,hashes.SHA256()))
    return (certificate.public_bytes(serialization.Encoding.PEM),
            private.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))


def test_node_tls_validation(ready_node):
    chain,key=bundle()
    assert node_cert_sync.validate_bundle(chain,key,"rus10.gowayot.com")["expires_at"]>0
    with pytest.raises(node_cert_sync.CertificateSyncError,match="другого домена"):
        node_cert_sync.validate_bundle(chain,key,"other.example.org")
    _,other=bundle()
    with pytest.raises(node_cert_sync.CertificateSyncError,match="не соответствует"):
        node_cert_sync.validate_bundle(chain,other,"rus10.gowayot.com")


def mock_profile(monkeypatch,node):
    job=storage.get_install_job(node["id"])
    config={"log":{"loglevel":"warning"},"inbounds":[{
       "tag":"RUS10_VLESS_TLS_IN","streamSettings":{"tlsSettings":{
          "certificates":[{"key":["OLD_KEY"],"certificate":["OLD_CERT"]}]}}}],
       "routing":{"rules":[{"outboundTag":"DIRECT"}]},
       "outbounds":[{"tag":"DIRECT","protocol":"freedom"}]}
    current={"config":deepcopy(config)}
    monkeypatch.setattr(remnawave,"detailed_profile",lambda *args:{
       "name":"XPPN RUS10 RU VLESS TLS","config":deepcopy(current["config"])})
    monkeypatch.setattr(remnawave,"request",lambda *args:{
       "response":[{"uuid":job["remote_uuid"],
         "configProfile":{"activeConfigProfileUuid":job["profile_uuid"]}}]})
    patches=[]
    def patch(pid,config):
        patches.append(deepcopy(config))
        current["config"]=deepcopy(config)
    monkeypatch.setattr(remnawave,"replace_profile_config",patch)
    restarted=[]
    monkeypatch.setattr(remnawave,"restart_node",lambda value:restarted.append(value))
    return current,patches,restarted,config


def test_certificate_refresh_only_updates_tls_of_own_profile(ready_node,monkeypatch):
    state,patches,restarts,original=mock_profile(monkeypatch,ready_node)
    chain,key=bundle()
    monkeypatch.setattr(node_cert_sync,"_bundle_from_password",lambda *args:(chain,key))
    result=node_cert_sync.sync(ready_node["id"],"ssh-password")
    assert result["updated"] is True
    assert result["panel_mount_required"] is False
    assert len(patches)==1 and len(restarts)==1
    assert patches[0]["routing"]==original["routing"]
    assert patches[0]["outbounds"]==original["outbounds"]
    assert patches[0]["inbounds"][0]["streamSettings"]["tlsSettings"]["certificates"][0]["key"] == key.decode().strip().splitlines()
    assert node_cert_sync.sync(ready_node["id"],"ssh-password")["updated"] is False
    assert len(restarts)==1
    assert "BEGIN PRIVATE KEY" not in str(node_cert_sync.status())


def test_reject_shared_profile_and_do_not_modify_other_nodes(ready_node,monkeypatch):
    chain,key=bundle()
    job=storage.get_install_job(ready_node["id"])
    monkeypatch.setattr(node_cert_sync,"_bundle_from_password",lambda *_:(chain,key))
    monkeypatch.setattr(remnawave,"request",lambda *_:{
       "response":[{"uuid":job["remote_uuid"],
                    "configProfile":{"activeConfigProfileUuid":job["profile_uuid"]}},
                   {"uuid":str(uuid.uuid4()),
                    "configProfile":{"activeConfigProfileUuid":job["profile_uuid"]}}]})
    monkeypatch.setattr(remnawave,"detailed_profile",
        lambda *_:{"name":"XPPN RUS10 RU VLESS TLS","config":{"inbounds":[]}})
    monkeypatch.setattr(remnawave,"replace_profile_config",
        lambda *_:pytest.fail("shared profile should not be patched"))
    with pytest.raises(node_cert_sync.CertificateSyncError,match="другой нодой"):
        node_cert_sync.sync(ready_node["id"],"password")


def test_existing_file_paths_are_never_replaced(ready_node,monkeypatch):
    chain,key=bundle()
    mock_profile(monkeypatch,ready_node)
    original_detailed=remnawave.detailed_profile
    def with_files(*args):
        profile=original_detailed(*args)
        profile["config"]["inbounds"][0]["streamSettings"]["tlsSettings"]["certificates"]=[
          {"keyFile":"/opt/nginx/certs/test_privkey.key",
           "certificateFile":"/opt/nginx/certs/test_fullchain.pem"}]
        return profile
    monkeypatch.setattr(remnawave,"detailed_profile",with_files)
    monkeypatch.setattr(node_cert_sync,"_bundle_from_password",lambda *_:(chain,key))
    with pytest.raises(node_cert_sync.CertificateSyncError,match="файловый"):
        node_cert_sync.sync(ready_node["id"],"password")


def test_auto_enrollment_needs_explicit_consent(ready_node):
    with pytest.raises(node_cert_sync.CertificateSyncError,match="Подтверди"):
        node_cert_sync.enroll(ready_node["id"],"password",False)


def test_no_certificate_secrets_in_db_or_public_status(ready_node,monkeypatch):
    chain,key=bundle()
    mock_profile(monkeypatch,ready_node)
    monkeypatch.setattr(node_cert_sync,"_bundle_from_password",lambda *_:(chain,key))
    node_cert_sync.sync(ready_node["id"],"password")
    with storage.connect() as db:
        values=[tuple(row) for row in db.execute("SELECT * FROM node_tls_sync").fetchall()]
    assert "BEGIN PRIVATE KEY" not in str(values)
    assert chain.decode() not in str(values)
    status=node_cert_sync.status()
    assert "BEGIN" not in str(status)
    assert status["mode"]=="node_local_certbot"
    assert status["panel_mount_required"] is False
