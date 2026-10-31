"""Regression: Go agent's sudo helper cannot work with empty capabilities."""
from pathlib import Path
from cryptography.fernet import Fernet
import pytest

from v2 import storage,agent_transport,agent_bootstrap,vps_install


def test_installer_keeps_sudo_capabilities_and_scopes_nginx_write():
    install=Path("v2/agent/install-agent.sh").read_text()
    repair=Path("v2/agent/repair-helper.sh").read_text()
    assert "CapabilityBoundingSet=\n" not in install
    assert "AmbientCapabilities=\n" in install
    assert "NoNewPrivileges=no" in install
    assert "NoNewPrivileges=no" in repair
    assert "User=nodemanager" in install and "Group=nodemanager" in install
    for setting in ("ProtectSystem=strict","ProtectKernelTunables=true",
                    "RestrictAddressFamilies=AF_INET","PrivateDevices=true"):
        assert setting not in install
    assert "ExecStartPost=/usr/bin/sudo -n /usr/local/libexec/node-manager-helper service.status" in install
    assert "CapabilityBoundingSet=~" in repair
    for setting in ("ProtectSystem=no","ProtectKernelTunables=no",
                    "PrivateDevices=no","ProtectHome=no","RestrictAddressFamilies="):
        assert setting in repair
    assert "node-manager-agent.service" in repair
    assert "AGENT_REPAIR_FAILURE" in repair
    assert "AGENT_REPAIR_SUCCESS" in repair
    assert "systemctl restart remnanode" not in repair
    assert "certbot renew" not in repair
    assert "remnawave" not in repair.lower()


@pytest.fixture
def connected(tmp_path,monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"test.db"))
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    storage.init_db()
    agent_transport.initialize()
    node=storage.create_node(code="RUS10",name="RUS10",domain="rus10.gowayot.com",
                             country="RU",role="regular")
    storage.create_install_job(node["id"],"1.1.1.1",22,"SHA256:"+"a"*43)
    storage.set_install_status(node["id"],"ready","connected")
    secret=agent_transport.issue_token(node["id"])
    agent_transport.heartbeat(node["id"],{"version":"1.0.0","metrics":{"uptime_seconds":10}})
    return node,secret


def test_repair_uses_existing_identity_and_only_touches_agent(connected,monkeypatch):
    node,token=connected
    class FakeTransport:
        closed=False
        def close(self):self.closed=True
    transport=FakeTransport()
    monkeypatch.setattr(vps_install,"ssh_open",lambda *_:(transport,"fp"))
    monkeypatch.setattr(vps_install,"verify_existing_install",lambda *_:None)
    commands=[]
    def run(_transport,cmd,**_kwargs):
        commands.append(cmd)
        return "AGENT_REPAIR_SUCCESS\n"
    monkeypatch.setattr(vps_install,"run_command",run)
    class FakeDestination:
        def __enter__(self):return self
        def __exit__(self,*_):pass
        def write(self,data):pass
    class FakeSFTP:
        def file(self,*_):return FakeDestination()
        def chmod(self,*_):pass
        def close(self):pass
    monkeypatch.setattr(agent_bootstrap.paramiko.SFTPClient,"from_transport",lambda *_:FakeSFTP())
    outcome=agent_bootstrap.repair_existing(node["id"],"password",True)
    assert outcome["repaired"] and outcome["credentials_unchanged"]
    assert transport.closed
    assert agent_transport.authenticate(node["id"],"Bearer "+token)
    assert sum("bash /root/.node-manager-agent-repair.sh" in x for x in commands)==1
    assert not any("remnanode" in x or "certbot" in x for x in commands)


def test_repair_requires_consent_and_prior_agent_connection(connected,monkeypatch):
    node,token=connected
    with pytest.raises(agent_bootstrap.AgentBootstrapError,match="Подтверди"):
        agent_bootstrap.repair_existing(node["id"],"secret",False)
    with storage.transaction() as db:
        db.execute("UPDATE manager_agents SET last_seen=0 WHERE node_id=?",(node["id"],))
    with pytest.raises(agent_bootstrap.AgentBootstrapError,match="Сначала установи"):
        agent_bootstrap.repair_existing(node["id"],"secret",True)


def test_ssh_repair_fails_without_exposing_password(connected,monkeypatch):
    node,_=connected
    monkeypatch.setattr(vps_install,"ssh_open",
                        lambda *_:(_ for _ in ()).throw(
                            agent_bootstrap.paramiko.AuthenticationException("password SHOULD_NOT_LEAK")))
    with pytest.raises(agent_bootstrap.AgentBootstrapError) as exc:
        agent_bootstrap.repair_existing(node["id"],"secret_password",True)
    assert "root не принят" in str(exc.value)
    assert "secret_password" not in str(exc.value)
    assert "SHOULD_NOT_LEAK" not in str(exc.value)
