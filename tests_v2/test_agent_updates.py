"""Safe Agent updates: per-node opt-in and SSH migration only when explicitly requested."""
import hashlib
import json
import time

import pytest
from cryptography.fernet import Fernet

from v2 import agent_release,agent_transport,agent_updates,storage


@pytest.fixture()
def node(tmp_path,monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"agents.db"))
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    storage.init_db()
    agent_transport.initialize()
    n=storage.create_node(code="RUS10",name="RUS10",domain="rus10.gowayot.com",
                          country="RU",role="regular")
    storage.create_install_job(n["id"],"1.1.1.1",22,"SHA256:"+"a"*43)
    storage.set_install_status(n["id"],"ready","ok")
    agent_transport.issue_token(n["id"])
    return n


def release_stub(monkeypatch):
    def rel():
        return {"version":"1.3.0","binaries":{
            "amd64":{"version":"1.3.0","size":123456,"sha256":"a"*64},
            "arm64":{"version":"1.3.0","size":123456,"sha256":"b"*64}}}
    monkeypatch.setattr(agent_release,"release",rel)


def test_release_semver_and_no_downgrades():
    assert agent_release.compare("1.3.0","1.2.0")==1
    assert agent_release.compare("1.2.0","1.3.0")==-1
    assert agent_release.compare("1.3.0","1.3.0")==0
    assert agent_release.compare("invalid","1.3.0")==0


def test_legacy_no_arch_can_request_one_time_ssh_update(node,monkeypatch):
    release_stub(monkeypatch)
    agent_transport.heartbeat(node["id"],{"version":"1.2.0","metrics":{}})
    st=agent_updates.current(node["id"])
    assert st["upgrade_needed"] and st["artifact_ready"]
    assert st["one_time_ssh_migration_required"]
    with pytest.raises(agent_updates.UpdateError,match="SSH"):
        agent_updates.manual(node["id"],confirmed=True)
    assert not agent_updates.current(node["id"])["auto_update"]
    from v2 import agent_bootstrap
    called=[]
    monkeypatch.setattr(agent_bootstrap,"upgrade_existing",lambda uid,password,approved:
                        called.append((uid,password,approved)) or
                        {"node_id":uid,"upgraded":True,"credentials_unchanged":True})
    out=agent_updates.manual(node["id"],confirmed=True,password="one-time-password")
    assert out["mode"]=="one-time-ssh" and out["credentials_unchanged"]
    assert called==[(node["id"],"one-time-password",True)]


def test_opt_in_auto_update_enqueues_once_with_allowlisted_digest(node,monkeypatch):
    release_stub(monkeypatch)
    agent_transport.heartbeat(node["id"],{"version":"1.3.0","metrics":{"architecture":"amd64"}})
    assert not agent_updates.auto_schedule(node["id"],"1.2.0",{"architecture":"amd64"})
    assert not agent_updates.auto_schedule(node["id"],"1.2.0",{"architecture":"foo"})
    assert agent_updates.set_auto(node["id"],True)["auto_update"]
    # Fake next release for a 1.3.0 node.
    monkeypatch.setattr(agent_release,"release",lambda:{
        "version":"1.4.0","binaries":{"amd64":{"version":"1.4.0","size":120000,"sha256":"b"*64}}})
    assert agent_updates.auto_schedule(node["id"],"1.3.0",{"architecture":"amd64"})
    assert not agent_updates.auto_schedule(node["id"],"1.3.0",{"architecture":"amd64"})
    with storage.connect() as db:
        jobs=db.execute("SELECT action,payload_json FROM manager_agent_jobs WHERE action='agent.update'").fetchall()
        assert len(jobs)==1
        assert jobs[0]["action"]=="agent.update"
        assert json.loads(jobs[0]["payload_json"])["sha256"]=="b"*64
    agent_updates.set_auto(node["id"],False)
    assert not agent_updates.current(node["id"])["auto_update"]


def test_manual_modern_update_only_queues_agent_and_uses_no_ssh(node,monkeypatch):
    monkeypatch.setattr(agent_release,"release",lambda:{
        "version":"1.4.0","binaries":{"amd64":{"version":"1.4.0","size":200000,"sha256":"a"*64}}})
    agent_transport.heartbeat(node["id"],{"version":"1.3.0","metrics":{"architecture":"amd64"}})
    with pytest.raises(agent_updates.UpdateError,match="Подтверди"):
        agent_updates.manual(node["id"],confirmed=False)
    outcome=agent_updates.manual(node["id"],confirmed=True)
    assert outcome["mode"]=="agent"
    assert agent_transport.poll(node["id"])["job"]["action"]=="agent.update"


def test_scripts_never_touch_remnawave_nginx_docker_or_token():
    from pathlib import Path
    root=Path(__file__).resolve().parents[1]/"v2/agent"
    for name in ("upgrade-agent.sh","agent-updater.sh"):
        raw=(root/name).read_text()
        assert "docker compose" not in raw
        assert "/etc/node-manager/agent.env" not in raw or "test -s /etc/node-manager/agent.env" in raw
        assert "AGENT_TOKEN=" not in raw
        assert "rm -rf /opt/" not in raw
    assert "update-pending" in (root/"agent-updater.sh").read_text()
    assert "rolled back" in (root/"agent-updater.sh").read_text()
