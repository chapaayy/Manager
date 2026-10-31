"""Tests for the outbound node agent queue and bounded auth protocol."""
import time
import uuid

import pytest
from cryptography.fernet import Fernet

from v2 import agent_transport,storage


@pytest.fixture
def node(tmp_path,monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"agents.db"))
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    storage.init_db()
    agent_transport.initialize()
    n=storage.create_node(code="RUS10",name="RUS10",domain="rus10.gowayot.com",
                          country="RU",role="regular")
    storage.create_install_job(n["id"],"1.1.1.1",22,"SHA256:"+"a"*43)
    storage.set_install_status(n["id"],"ready","installed")
    return n


def test_per_node_token_issued_then_rotated_and_revoked(node):
    secret=agent_transport.issue_token(node["id"])
    assert len(secret)>=40
    assert agent_transport.authenticate(node["id"],"Bearer "+secret)
    assert not agent_transport.authenticate(node["id"],"Bearer invalid")
    other=str(uuid.uuid4())
    assert not agent_transport.authenticate(other,"Bearer "+secret)
    newer=agent_transport.issue_token(node["id"])
    assert newer != secret
    assert not agent_transport.authenticate(node["id"],"Bearer "+secret)
    assert agent_transport.authenticate(node["id"],"Bearer "+newer)
    with storage.connect() as db:
        saved=db.execute("SELECT token_hash FROM manager_agents WHERE node_id=?",
                         (node["id"],)).fetchone()["token_hash"]
    assert secret not in saved and newer not in saved
    agent_transport.revoke(node["id"])
    assert not agent_transport.authenticate(node["id"],"Bearer "+newer)


def test_queue_dispatch_acknowledge_once_and_status(node):
    agent_transport.issue_token(node["id"])
    agent_transport.heartbeat(node["id"],{"version":"1.0.0","metrics":{
        "uptime_seconds":125,"load1":"0.1"}})
    status=agent_transport.nodes_status()[0]
    assert status["online"] is True and status["version"]=="1.0.0"
    job=agent_transport.enqueue(node["id"],"docker.status")
    polled=agent_transport.poll(node["id"])["job"]
    assert polled["id"]==job["id"]
    assert polled["action"]=="docker.status"
    assert agent_transport.poll(node["id"])["job"] is None
    agent_transport.report(node["id"],{"id":job["id"],"ok":True,
                                            "result":{"containers":[]}})
    result=agent_transport.job_status(node["id"],job["id"])
    assert result["status"]=="done" and result["result"]["containers"]==[]
    with pytest.raises(agent_transport.AgentError,match="уже завершено"):
        agent_transport.report(node["id"],{"id":job["id"],"ok":True,"result":{}})


def test_no_ssh_passwords_or_pem_in_general_job_results(node):
    agent_transport.issue_token(node["id"])
    with pytest.raises(agent_transport.AgentError,match="Неподдерживаемая"):
        agent_transport.enqueue(node["id"],"shell.exec",{"command":"id"})
    job=agent_transport.enqueue(node["id"],"docker.status")
    agent_transport.poll(node["id"])
    with pytest.raises(agent_transport.AgentError,match="Секретные"):
        agent_transport.report(node["id"],{"id":job["id"],"ok":True,
                                                 "result":{"key":"PRIVATE KEY"}})


def test_credential_rotation_invalidates_old_pending_tasks(node):
    agent_transport.issue_token(node["id"])
    job=agent_transport.enqueue(node["id"],"docker.status")
    agent_transport.issue_token(node["id"])
    assert agent_transport.job_status(node["id"],job["id"])["status"]=="failed"


def test_one_node_cannot_report_another_nodes_job(node):
    agent_transport.issue_token(node["id"])
    other=storage.create_node(code="RUS11",name="RUS11",domain="rus11.gowayot.com",
                              country="RU",role="regular")
    storage.create_install_job(other["id"],"8.8.8.8",22,"SHA256:"+"b"*43)
    storage.set_install_status(other["id"],"ready","installed")
    agent_transport.issue_token(other["id"])
    job=agent_transport.enqueue(node["id"],"docker.status")
    agent_transport.poll(node["id"])
    with pytest.raises(agent_transport.AgentError,match="неизвестно"):
        agent_transport.report(other["id"],{"id":job["id"],"ok":True,"result":{}})


def test_lease_timeout_is_not_automatically_retried(node,monkeypatch):
    agent_transport.issue_token(node["id"])
    job=agent_transport.enqueue(node["id"],"docker.restart",{"name":"remnanode"})
    agent_transport.poll(node["id"])
    with storage.transaction() as db:
        db.execute("UPDATE manager_agent_jobs SET updated_at=? WHERE id=?",
                   (int(time.time())-agent_transport.LEASE_SECONDS-5,job["id"]))
    assert agent_transport.poll(node["id"])["job"] is None
    assert agent_transport.job_status(node["id"],job["id"])["status"]=="failed"


def test_tls_error_shows_safe_diagnostic_without_private_key(node,monkeypatch):
    from v2 import node_cert_sync
    agent_transport.issue_token(node["id"])
    task=agent_transport.enqueue(node["id"],"cert.status")
    agent_transport.poll(node["id"])
    def fail(_node,data):
        raise node_cert_sync.CertificateSyncError("Xray-профиль используется другой нодой")
    monkeypatch.setattr(node_cert_sync,"apply_agent_status",fail)
    agent_transport.report(node["id"],{"id":task["id"],"ok":True,"result":{
        "domain":node["domain"],"certificate_sha256":"a"*64}})
    result=agent_transport.job_status(node["id"],task["id"])
    assert result["status"]=="failed"
    assert "другой нодой" in result["error"]
    with storage.connect() as db:
        error=db.execute("SELECT last_error FROM node_tls_sync WHERE node_id=?",
                         (node["id"],)).fetchone()["last_error"]
    assert error==result["error"]


def test_tls_unexpected_exception_keeps_details_private(node,monkeypatch):
    from v2 import node_cert_sync
    agent_transport.issue_token(node["id"])
    task=agent_transport.enqueue(node["id"],"cert.status")
    agent_transport.poll(node["id"])
    private="-----BEGIN PRIVATE KEY----- PRIVATE_MUST_NOT_LEAK"
    def fail(_node,data):
        raise RuntimeError(private)
    monkeypatch.setattr(node_cert_sync,"apply_agent_status",fail)
    agent_transport.report(node["id"],{"id":task["id"],"ok":True,
           "result":{"domain":node["domain"],"certificate_sha256":"a"*64}})
    state=agent_transport.job_status(node["id"],task["id"])
    assert state["status"]=="failed"
    assert "Внутренняя ошибка" in state["error"]
    assert private not in str(state)


def test_exporting_private_tls_key_is_disabled(node):
    with pytest.raises(agent_transport.AgentError,match="Неподдерживаемая"):
        agent_transport.enqueue(node["id"],"cert.export")
