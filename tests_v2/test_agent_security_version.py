"""Regression tests for SSH-security Agent version gating."""
import paramiko
import pytest
from cryptography.fernet import Fernet

from v2 import agent_bootstrap, agent_transport, storage, vps_install


@pytest.fixture()
def ready_node(tmp_path,monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"security.db"))
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    storage.init_db()
    agent_transport.initialize()
    node=storage.create_node(code="RUS10",name="RUS10",domain="rus10.gowayot.com",
                             country="RU",role="regular")
    storage.create_install_job(node["id"],"1.1.1.1",22,"SHA256:"+"a"*43)
    storage.set_install_status(node["id"],"ready","ready")
    agent_transport.issue_token(node["id"])
    return node


def test_version_comparison_accepts_newer_agent_versions():
    assert agent_bootstrap._version_at_least("1.4.0",(1,4,0))
    assert agent_bootstrap._version_at_least("1.5.0",(1,4,0))
    assert agent_bootstrap._version_at_least("1.6.0",(1,4,0))
    assert not agent_bootstrap._version_at_least("1.3.99",(1,4,0))
    assert not agent_bootstrap._version_at_least("broken",(1,4,0))


def test_security_helper_allows_agent_1_5_before_attempting_ssh(ready_node,monkeypatch):
    agent_transport.heartbeat(ready_node["id"],{"version":"1.5.0","metrics":{}})
    def reject_auth(*_args,**_kwargs):
        raise paramiko.AuthenticationException()
    monkeypatch.setattr(vps_install,"ssh_open",reject_auth)
    with pytest.raises(agent_bootstrap.AgentBootstrapError,match="неверный пароль"):
        agent_bootstrap.enable_ssh_security(ready_node["id"],"bad",True)


def test_security_helper_rejects_agent_1_3(ready_node,monkeypatch):
    agent_transport.heartbeat(ready_node["id"],{"version":"1.3.9","metrics":{}})
    monkeypatch.setattr(vps_install,"ssh_open",
                        lambda *_args,**_kwargs: pytest.fail("SSH must not be attempted"))
    with pytest.raises(agent_bootstrap.AgentBootstrapError,match="v1.4 или новее"):
        agent_bootstrap.enable_ssh_security(ready_node["id"],"bad",True)
