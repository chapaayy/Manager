"""Regression tests for agent-mediated Certbot, no post-install SSH."""
from copy import deepcopy
from datetime import datetime,timedelta,timezone
import base64
import uuid

import pytest
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from v2 import agent_transport,node_cert_sync,remnawave,storage


@pytest.fixture
def ready_node(tmp_path,monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"db.sqlite"))
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    storage.init_db()
    agent_transport.initialize()
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
    def patch(pid,cfg):
        patches.append(deepcopy(cfg))
        current["config"]=deepcopy(cfg)
    monkeypatch.setattr(remnawave,"replace_profile_config",patch)
    restarted=[]
    monkeypatch.setattr(remnawave,"restart_node",lambda value:restarted.append(value))
    return current,patches,restarted,config


def test_node_tls_validation(ready_node):
    chain,key=bundle()
    assert node_cert_sync.validate_bundle(chain,key,"rus10.gowayot.com")["expires_at"]>0
    with pytest.raises(node_cert_sync.CertificateSyncError,match="другого домена"):
        node_cert_sync.validate_bundle(chain,key,"other.example.org")
    _,other=bundle()
    with pytest.raises(node_cert_sync.CertificateSyncError,match="не соответствует"):
        node_cert_sync.validate_bundle(chain,other,"rus10.gowayot.com")


def test_certificate_refresh_via_agent_only(ready_node,monkeypatch):
    current,patches,restarts,original=mock_profile(monkeypatch,ready_node)
    chain,key=bundle()
    payload={"domain":ready_node["domain"],"chain":base64.b64encode(chain).decode(),
             "key":base64.b64encode(key).decode()}
    result=node_cert_sync.apply_agent_export(ready_node["id"],payload)
    assert result["updated"] is True
    assert len(patches)==1 and len(restarts)==1
    assert patches[0]["routing"]==original["routing"]
    assert patches[0]["outbounds"]==original["outbounds"]
    assert patches[0]["inbounds"][0]["streamSettings"]["tlsSettings"]["certificates"][0]["key"]==key.decode().strip().splitlines()
    assert node_cert_sync.apply_agent_export(ready_node["id"],payload)["updated"] is False
    assert len(restarts)==1
    with storage.connect() as db:
        all_rows=[tuple(r) for r in db.execute("SELECT * FROM node_tls_sync")]
    assert "PRIVATE KEY" not in str(all_rows)
    assert "PRIVATE KEY" not in str(node_cert_sync.status())


def test_shared_profile_is_never_changed(ready_node,monkeypatch):
    chain,key=bundle()
    job=storage.get_install_job(ready_node["id"])
    monkeypatch.setattr(remnawave,"request",lambda *_:{
       "response":[{"uuid":job["remote_uuid"],"configProfile":{"activeConfigProfileUuid":job["profile_uuid"]}},
                   {"uuid":str(uuid.uuid4()),"configProfile":{"activeConfigProfileUuid":job["profile_uuid"]}}]})
    monkeypatch.setattr(remnawave,"detailed_profile",
        lambda *_:{"name":"XPPN RUS10 RU VLESS TLS","config":{"inbounds":[]}})
    monkeypatch.setattr(remnawave,"replace_profile_config",lambda *_:pytest.fail("shared profile changed"))
    with pytest.raises(node_cert_sync.CertificateSyncError,match="другой нодой"):
        node_cert_sync.apply_agent_export(ready_node["id"],{
            "domain":ready_node["domain"],"chain":base64.b64encode(chain).decode(),
            "key":base64.b64encode(key).decode()})


def test_existing_file_path_profile_never_rewritten(ready_node,monkeypatch):
    chain,key=bundle()
    mock_profile(monkeypatch,ready_node)
    original=remnawave.detailed_profile
    def file_profile(*a):
        p=original(*a)
        p["config"]["inbounds"][0]["streamSettings"]["tlsSettings"]["certificates"]=[
            {"keyFile":"/opt/nginx/certs/secret.key",
             "certificateFile":"/opt/nginx/certs/fullchain.pem"}]
        return p
    monkeypatch.setattr(remnawave,"detailed_profile",file_profile)
    with pytest.raises(node_cert_sync.CertificateSyncError,match="Файловый"):
        node_cert_sync.apply_agent_export(ready_node["id"],{
            "domain":ready_node["domain"],"chain":base64.b64encode(chain).decode(),
            "key":base64.b64encode(key).decode()})


def test_unassigned_other_nodes_do_not_block_dedicated_profile(ready_node,monkeypatch):
    current,patches,restarts,original=mock_profile(monkeypatch,ready_node)
    job=storage.get_install_job(ready_node["id"])
    other=str(uuid.uuid4())
    monkeypatch.setattr(remnawave,"request",lambda *_:{
      "response":[{"uuid":job["remote_uuid"],
                   "configProfile":{"activeConfigProfileUuid":job["profile_uuid"]}},
                  {"uuid":other,"configProfile":{"activeConfigProfileUuid":None}}]})
    chain,key=bundle()
    result=node_cert_sync.apply_agent_export(ready_node["id"],{
      "domain":ready_node["domain"],"chain":base64.b64encode(chain).decode(),
      "key":base64.b64encode(key).decode()})
    assert result["updated"] is True
    assert len(patches)==1 and len(restarts)==1


def test_unknown_other_node_profile_blocks_mutation(ready_node,monkeypatch):
    _,patches,restarts,_=mock_profile(monkeypatch,ready_node)
    job=storage.get_install_job(ready_node["id"])
    monkeypatch.setattr(remnawave,"request",lambda *_:{
      "response":[{"uuid":job["remote_uuid"],
                   "configProfile":{"activeConfigProfileUuid":job["profile_uuid"]}},
                  {"uuid":str(uuid.uuid4()),"name":"uninspectable-node"}]})
    chain,key=bundle()
    with pytest.raises(node_cert_sync.CertificateSyncError,match="не вернула привязки"):
        node_cert_sync.apply_agent_export(ready_node["id"],{
          "domain":ready_node["domain"],"chain":base64.b64encode(chain).decode(),
          "key":base64.b64encode(key).decode()})
    assert not patches and not restarts


def test_existing_identical_pem_string_does_not_restart(ready_node,monkeypatch):
    current,patches,restarts,_=mock_profile(monkeypatch,ready_node)
    chain,key=bundle()
    current["config"]["inbounds"][0]["streamSettings"]["tlsSettings"]["certificates"]=[
        {"key":key.decode(),"certificate":chain.decode()}]
    result=node_cert_sync.apply_agent_export(ready_node["id"],{
        "domain":ready_node["domain"],"chain":base64.b64encode(chain).decode(),
        "key":base64.b64encode(key).decode()})
    assert result["updated"] is False
    assert not patches and not restarts


def test_api_failure_detail_discards_any_private_key(ready_node,monkeypatch):
    job=storage.get_install_job(ready_node["id"])
    secret="-----BEGIN PRIVATE KEY----- SUPER_SECRET"
    monkeypatch.setattr(remnawave,"request",lambda *_:(_ for _ in ()).throw(
        remnawave.PanelError("Remnawave вернула HTTP 403 "+secret)))
    chain,key=bundle()
    with pytest.raises(node_cert_sync.CertificateSyncError,match="HTTP 403") as error:
        node_cert_sync.apply_agent_export(ready_node["id"],{
            "domain":ready_node["domain"],"chain":base64.b64encode(chain).decode(),
            "key":base64.b64encode(key).decode()})
    assert secret not in str(error.value)


def test_manual_tls_request_never_asks_ssh_password(ready_node):
    token=agent_transport.issue_token(ready_node["id"])
    task=node_cert_sync.sync(ready_node["id"])
    assert task["action"]=="cert.export"
    assert token not in str(task)
    assert "password" not in str(task)
