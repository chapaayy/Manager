"""First TLS check runs on the first ready Agent heartbeat, not after 120 seconds."""
import uuid

from cryptography.fernet import Fernet
from v2 import agent_transport, node_cert_sync, storage


def test_first_heartbeat_queues_one_cert_check_without_ssh_or_panel(tmp_path,monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB", str(tmp_path/"first-tls.db"))
    monkeypatch.setenv("XPPN_DATA_KEY", Fernet.generate_key().decode())
    storage.init_db()
    agent_transport.initialize()
    n=storage.create_node(code="RUS10",name="RUS10",domain="rus10.gowayot.com",
                          country="RU",role="regular")
    storage.create_install_job(n["id"],"192.0.2.1",22,"SHA256:"+"a"*43)
    storage.set_install_status(n["id"],"ready","ready",
                               remote_uuid=str(uuid.uuid4()),
                               profile_uuid=str(uuid.uuid4()))
    agent_transport.issue_token(n["id"])
    for _ in range(3):
        agent_transport.heartbeat(n["id"], {"version":"1.1.0","metrics":{}})
    with storage.connect() as db:
        rows=db.execute(
            "SELECT action,status FROM manager_agent_jobs WHERE node_id=?",
            (n["id"],)).fetchall()
    assert [(r["action"],r["status"]) for r in rows]==[("cert.status","queued")]
    row=next(x for x in node_cert_sync.status()["nodes"] if x["id"]==n["id"])
    assert row["checking"] and not row["checked"]
    assert agent_transport.poll(n["id"])["job"]["action"]=="cert.status"
    # Polling/heartbeats during pending verification cannot add duplicates.
    agent_transport.heartbeat(n["id"], {"version":"1.1.0","metrics":{}})
    with storage.connect() as db:
        count=db.execute(
            "SELECT COUNT(*) FROM manager_agent_jobs WHERE node_id=?",
            (n["id"],)).fetchone()[0]
    assert count==1


def test_missing_registration_does_not_automatically_queue(tmp_path,monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"unregistered.db"))
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    storage.init_db()
    agent_transport.initialize()
    n=storage.create_node(code="RUS10",name="RUS10",domain="rus10.gowayot.com",
                          country="RU",role="regular")
    storage.create_install_job(n["id"],"192.0.2.1",22,"SHA256:"+"a"*43)
    storage.set_install_status(n["id"],"registered","waiting")
    agent_transport.issue_token(n["id"])
    agent_transport.heartbeat(n["id"], {"version":"1.1.0","metrics":{}})
    assert node_cert_sync.queue_initial_check(n["id"]) is False
    with storage.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM manager_agent_jobs").fetchone()[0]==0
