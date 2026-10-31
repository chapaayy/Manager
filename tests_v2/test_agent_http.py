"""HTTP-level tests: node agents authenticate independently of admin cookies."""
import uuid

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from v2.app import app
from v2 import agent_transport,storage


@pytest.fixture
def api(tmp_path,monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"test-agents.db"))
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    monkeypatch.setenv("XPPN_V2_SESSION_SECRET","only-for-tests-1234567890123456789012345678")
    monkeypatch.setenv("XPPN_V2_ADMIN_PASSWORD","only-for-tests-password-123456789")
    monkeypatch.setenv("XPPN_V2_COOKIE_SECURE","0")
    with TestClient(app) as c:
        n=storage.create_node(code="RUS10",name="RUS10",domain="rus10.example.com",
                              country="RU",role="regular")
        storage.create_install_job(n["id"],"1.1.1.1",22,"SHA256:"+"a"*43)
        storage.set_install_status(n["id"],"ready","installed")
        token=agent_transport.issue_token(n["id"])
        yield c,n,token


def test_public_agent_http_api_rejects_missing_or_wrong_credentials(api):
    c,n,token=api
    assert c.post("/api/agent/v1/heartbeat",json={"version":"1","metrics":{}}).status_code==401
    bad={"X-Node-Id":n["id"],"Authorization":"Bearer wrong"}
    assert c.get("/api/agent/v1/pull",headers=bad).status_code==401
    good={"X-Node-Id":n["id"],"Authorization":"Bearer "+token}
    response=c.post("/api/agent/v1/heartbeat",
        json={"version":"1.0.0","metrics":{"uptime_seconds":500}},headers=good)
    assert response.status_code==200,response.text
    assert c.get("/api/agent/v1/pull",headers=good).status_code==200
    # Even a valid agent token does not grant admin-session access.
    assert c.get("/api/agents",headers=good).status_code==401
    assert c.post("/api/agents/"+n["id"]+"/tasks",json={"action":"docker.status"},
                  headers=good).status_code==401


def test_admin_agent_operations_require_cookie_and_csrf(api):
    c,n,token=api
    logged=c.post("/api/auth/login",json={"password":"only-for-tests-password-123456789"})
    assert logged.status_code==200
    path="/api/agents/"+n["id"]+"/tasks"
    assert c.post(path,json={"action":"docker.status"},headers={"X-CSRF-Token":""}).status_code==403
    csrf=logged.json()["csrf"]
    created=c.post(path,headers={"X-CSRF-Token":csrf},
                   json={"action":"docker.status"})
    assert created.status_code==200,created.text
    jid=created.json()["id"]
    good={"X-Node-Id":n["id"],"Authorization":"Bearer "+token}
    task=c.get("/api/agent/v1/pull",headers=good).json()["job"]
    assert task["id"]==jid
    reported=c.post("/api/agent/v1/report",headers=good,
                    json={"id":jid,"ok":True,"result":{"containers":[]}})
    assert reported.status_code==200,reported.text
    status=c.get("/api/agents/"+n["id"]+"/tasks/"+jid).json()
    assert status["status"]=="done"
    assert status["result"]["containers"]==[]
