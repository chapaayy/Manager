"""Agent bootstrap failure reporting: safe stages, retry, no leaked credentials."""
import io

import paramiko
import pytest
from cryptography.fernet import Fernet

from v2 import agent_bootstrap,agent_transport,storage,vps_install


@pytest.fixture
def existing_node(tmp_path,monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"agent-bootstrap.sqlite"))
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    storage.init_db()
    agent_transport.initialize()
    node=storage.create_node(code="RUS10",name="RUS10",country="RU",
                 domain="rus10.gowayot.com",role="regular")
    storage.create_install_job(node["id"],"1.1.1.1",22,"SHA256:"+"a"*43)
    storage.set_install_status(node["id"],"ready","running")
    return node


def test_stage_failure_only_exposes_allowlisted_label(monkeypatch):
    monkeypatch.setattr(vps_install,"run_command",lambda *_args,**_kw:"AGENT_FAILURE:service:1\n")
    result=agent_bootstrap._remote_bootstrap_failure(object())
    assert "запуск и проверка systemd-службы" in result
    assert "код 1" in result
    assert "AGENT_FAILURE" not in result


def test_bad_ssh_password_is_not_leaked(existing_node,monkeypatch):
    def wrong(*args):
        raise paramiko.AuthenticationException("sensitive password should not appear here")
    monkeypatch.setattr(vps_install,"ssh_open",wrong)
    with pytest.raises(agent_bootstrap.AgentBootstrapError,match="пароль root не принят") as exc:
        agent_bootstrap.install_existing(existing_node["id"],"rootsecret",True)
    assert "rootsecret" not in str(exc.value)
    assert "sensitive" not in str(exc.value)


def test_remote_script_failure_has_concrete_stage_without_shell_logs(existing_node,tmp_path,monkeypatch):
    root=tmp_path/"agent"
    root.mkdir()
    for name in ("agent-amd64","helper.py","install-agent.sh"):
        (root/name).write_bytes(b"test content")
    monkeypatch.setattr(agent_bootstrap,"ROOT",root)
    monkeypatch.setattr(agent_bootstrap,"manager_url",lambda:"https://manager.example.org")

    commands=[]
    def command(_transport,cmd,**kwargs):
        commands.append(cmd)
        if cmd=="uname -m":return "x86_64\n"
        if "bash /root/.node-manager-bootstrap/install.sh" in cmd:
            raise RuntimeError("internal secret token; should never reach UI")
        if "grep -E" in cmd:return "AGENT_FAILURE:sudoers:1\n"
        return ""
    monkeypatch.setattr(vps_install,"run_command",command)

    class DummyFile(io.BytesIO):
        def __enter__(self):return self
        def __exit__(self,*args):self.close()
    class DummySFTP:
        def file(self,*args):return DummyFile()
        def chmod(self,*args):pass
        def close(self):pass
    monkeypatch.setattr(paramiko.SFTPClient,"from_transport",lambda *_:DummySFTP())

    with pytest.raises(agent_bootstrap.AgentBootstrapError) as exc:
        agent_bootstrap.install_on_transport(object(),existing_node["id"])
    message=str(exc.value)
    assert "разрешённых привилегий агента" in message
    assert "secret token" not in message
    assert "AGENT_FAILURE" not in message
    assert agent_transport.nodes_status()[0]["installed"] is True
    assert agent_transport.nodes_status()[0]["last_seen"]==0
    assert any("grep -E" in cmd for cmd in commands)


def test_unreachable_remote_log_does_not_leak_exception(monkeypatch):
    monkeypatch.setattr(vps_install,"run_command",
                        lambda *_a,**_k:(_ for _ in ()).throw(OSError("dangerous secret")))
    assert "dangerous secret" not in agent_bootstrap._remote_bootstrap_failure(object())
