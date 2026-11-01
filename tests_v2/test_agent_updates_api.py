"""Authenticated agent artifact transport and per-node update preference endpoints."""
import time
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from v2.app import app
from v2 import storage,agent_transport,agent_release


@pytest.fixture
def manager(tmp_path,monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"manager.db"))
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    monkeypatch.setenv("XPPN_V2_ADMIN_PASSWORD","test-password-1234567890")
    monkeypatch.setenv("XPPN_V2_SESSION_SECRET","test-only-secret-long-enough-123456789000")
    monkeypatch.setenv("XPPN_V2_COOKIE_SECURE","0")
    with TestClient(app) as client:
        r=client.post("/api/auth/login",json={"password":"test-password-1234567890"})
        assert r.status_code==200
        client.headers.update({"X-CSRF-Token":r.json()["csrf"]})
        n=storage.create_node(code="RUS10",name="RUS10",domain="rus10.gowayot.com",
                              role="regular",country="RU")
        storage.create_install_job(n["id"],"1.1.1.1",22,"SHA256:"+"a"*43)
        storage.set_install_status(n["id"],"ready","ready")
        token=agent_transport.issue_token(n["id"])
        agent_transport.heartbeat(n["id"],{"version":"1.2.0","metrics":{}})
        yield client,n,token


def test_auto_update_opt_in_and_legacy_requires_ssh(manager,monkeypatch):
    client,node,token=manager
    monkeypatch.setattr(agent_release,"release",lambda:{
        "version":"1.3.0","binaries":{"amd64":{"version":"1.3.0","sha256":"a"*64,"size":45000}}})
    endpoint="/api/agents/"+node["id"]
    r=client.get(endpoint+"/update-status")
    assert r.status_code==200
    assert r.json()["one_time_ssh_migration_required"]
    assert not r.json()["auto_update"]
    assert client.post(endpoint+"/update",json={"confirmed":True}).status_code==422
    assert client.put(endpoint+"/auto-update",json={"enabled":True}).json()["auto_update"]
    assert not client.put(endpoint+"/auto-update",json={"enabled":False}).json()["auto_update"]


def test_download_is_only_accessible_to_authenticated_node(manager,tmp_path,monkeypatch):
    client,node,token=manager
    binary=tmp_path/"agent-amd64"
    binary.write_bytes(b"A"*15000)
    monkeypatch.setattr(agent_release,"VERSION_FILE",Path(__file__).resolve().parents[1]/"v2/agent/main.go")
    monkeypatch.setattr(agent_release,"ROOT",tmp_path)
    url="/api/agent/v1/update/binary/amd64"
    assert client.get(url).status_code==401
    assert client.get(url,headers={"X-Node-Id":node["id"],
          "Authorization":"Bearer bad"}).status_code==401
    r=client.get(url,headers={"X-Node-Id":node["id"],
          "Authorization":"Bearer "+token})
    assert r.status_code==200 and r.content==b"A"*15000
    assert r.headers["cache-control"]=="no-store"
    release=client.get("/api/agent/v1/update/manifest",headers={
        "X-Node-Id":node["id"],"Authorization":"Bearer "+token})
    assert release.status_code==200
    assert release.json()["version"]=="1.5.0"
    assert release.json()["binaries"]["amd64"]["size"]==15000
    assert client.get("/api/agent/v1/update/manifest").status_code==401
    assert client.get("/api/agent/v1/update/binary/../../etc/passwd",
       headers={"X-Node-Id":node["id"],"Authorization":"Bearer "+token}).status_code!=200
    assert "trusted_agent_release()" in (Path(__file__).resolve().parents[1]/"v2/agent/helper.py").read_text()
    assert client.post("/api/agents/"+node["id"]+"/tasks",json={
       "action":"agent.update","confirmed":True,"payload":{"version":"1.3.0"}}).status_code==422
