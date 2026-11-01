"""Fast agent transport, saved SSH credentials and retired bridge topology."""
import asyncio
import time
import pytest
from cryptography.fernet import Fernet

from v2 import agent_transport, bundled, storage


@pytest.fixture()
def db(tmp_path,monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"manager.db"))
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    storage.init_db()
    agent_transport.initialize()
    bundled.seed_defaults()
    return tmp_path


def make_node():
    node=storage.create_node(code="RUS10",name="RUS10",domain="rus10.gowayot.com",
                             country="RU",role="regular")
    storage.create_install_job(node["id"],"8.8.8.8",22,"SHA256:"+"a"*43)
    storage.set_install_status(node["id"],"ready","ok")
    agent_transport.issue_token(node["id"])
    return node


def test_monitor_interval_defaults_to_five_and_allows_one_second(db):
    assert storage.monitoring_interval()==5
    assert storage.set_monitoring_interval(1)=={"monitor_interval":1.0}
    assert storage.monitoring_interval()==1
    with pytest.raises(ValueError):
        storage.set_monitoring_interval(.5)
    assert storage.set_monitoring_interval(60)["monitor_interval"]==60


def test_ssh_password_encrypted_and_never_returned_by_install_job(db):
    node=make_node()
    storage.save_node_ssh_password(node["id"],"super-secret-password")
    public=storage.node_ssh_credentials(node["id"])
    assert public["ip"]=="8.8.8.8" and public["port"]==22 and public["has_password"]
    assert "password" not in public
    assert storage.node_ssh_credentials(node["id"],include_secret=True)["password"]=="super-secret-password"
    install=storage.get_install_job(node["id"])
    assert "ssh_password_enc" not in install
    with storage.connect() as conn:
        enc=conn.execute("SELECT ssh_password_enc FROM node_installations WHERE node_id=?",
                         (node["id"],)).fetchone()[0]
    assert enc and "super-secret-password" not in enc


def test_long_poll_wakes_immediately_when_task_is_queued(db):
    node=make_node()
    async def scenario():
        async def waiter():
            start=time.monotonic()
            result=await agent_transport.long_poll(node["id"],2)
            return result,time.monotonic()-start
        task=asyncio.create_task(waiter())
        await asyncio.sleep(.05)
        queued=agent_transport.enqueue(node["id"],"system.status",{})
        result,elapsed=await task
        assert result["job"]["id"]==queued["id"]
        assert elapsed<.8
    asyncio.run(scenario())


def test_bridge_preset_is_demoted_and_direct_remains_installable(db):
    presets=__import__("v2.library",fromlist=["list_presets"]).list_presets()
    assert any(p["mode"]=="direct" for p in presets)
    assert not any(p["mode"]=="bridge" for p in presets)
    configs=__import__("v2.library",fromlist=["list_files"]).list_files()
    assert any("Bridge" in c["name"] and c["kind"]=="xray" for c in configs)
