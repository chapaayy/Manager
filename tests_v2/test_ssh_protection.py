"""SSH-only protection operations: no change to VPN, SSH daemon or global firewall."""
import importlib.util
import ipaddress
from pathlib import Path
import pytest
from cryptography.fernet import Fernet
from v2 import agent_transport, storage

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("agent_helper_test",ROOT/"v2/agent/helper.py")
helper=importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def test_fail2ban_script_confined_to_ssh_and_admin_whitelist():
    content=(ROOT/"v2/agent/fail2ban-setup.sh").read_text()
    assert "backend = systemd" in content
    assert "maxretry = 6" in content and "findtime = 600" in content
    assert "bantime = 3600" in content
    assert "ignoreip = 127.0.0.1/8 ::1 $admin $panel_ip" in content
    assert "flock -n" in content
    assert "fail2ban-client -t" in content
    assert "fail2ban-client status sshd" in content
    assert "existing-fail2ban-needs-review" in content
    assert "rm -f -- \"$CONF\"" in content
    for dangerous in ("ufw enable","iptables -F","iptables -P","nft flush",
                      "systemctl restart ssh","systemctl stop ssh","docker restart",
                      "net.ipv4.ip_forward"):
        assert dangerous not in content


@pytest.mark.parametrize("invalid",["","127.0.0.1","192.168.0.1","10.0.0.1",
                                         "1.1.1.1; rm -rf /","example.com","::1"])
def test_helper_does_not_accept_invalid_admin_address(invalid):
    with pytest.raises(SystemExit):
        helper._admin_ipv4(invalid)
    assert helper._admin_ipv4("8.8.8.8")=="8.8.8.8"


def test_agent_ssh_actions_must_use_internal_confirmed_api(tmp_path,monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"agent.db"))
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    storage.init_db()
    agent_transport.initialize()
    node=storage.create_node(code="RUS10",name="RUS10",domain="rus10.gowayot.com",
                             country="RU",role="regular")
    storage.create_install_job(node["id"],"1.1.1.1",22,"SHA256:"+"a"*43)
    storage.set_install_status(node["id"],"ready","ok")
    agent_transport.issue_token(node["id"])
    assert "security.fail2ban.install" in agent_transport.ALLOWED
    assert "security.fail2ban.unban" in agent_transport.ALLOWED
    with pytest.raises(agent_transport.AgentError,match="отдельные"):
        agent_transport.enqueue(node["id"],"security.fail2ban.install",
                                {"admin_ip":"8.8.8.8","confirmed":True})
    j=agent_transport.enqueue(node["id"],"security.fail2ban.install",
                                {"admin_ip":"8.8.8.8","confirmed":True},internal=True)
    assert j["status"]=="queued"


def test_ssh_history_filters_unexpected_journal_lines(monkeypatch):
    sample=("2026-11-01T12:10:00+0000 host fail2ban.actions [sshd] Ban 8.8.8.8\n"
            "2026-11-01T12:11:00+0000 host fail2ban.actions [sshd] Unban 8.8.8.8\n"
            "2026-11-01T12:12:00+0000 host fail2ban.actions [nginx] Ban 1.2.3.4\n"
            "2026-11-01T12:12:00+0000 host fake secret\n")
    def inspect(args,timeout=5):
        if args[0]=="fail2ban-client":return "Banned IP list: 1.1.1.1 2.2.2.2\n"
        if args[0]=="journalctl":return sample
    monkeypatch.setattr(helper,"_inspect",inspect)
    state=helper._ssh_protection()
    assert state["banned_ips"]==["1.1.1.1","2.2.2.2"]
    assert [x["action"] for x in state["history"]]==["ban","unban"]
    assert not any(x["ip"]=="1.2.3.4" for x in state["history"])


def test_unban_only_existing_ssh_ip(monkeypatch):
    monkeypatch.setattr(helper,"_inspect",lambda args,timeout=5:"active")
    monkeypatch.setattr(helper,"_ssh_protection",lambda:{"banned_ips":["8.8.8.8"]})
    calls=[]
    monkeypatch.setattr(helper,"run",lambda args,**kw:calls.append(args))
    assert helper.unban_ssh_ip({"ip":"8.8.8.8","confirmed":True})=={"unbanned":"8.8.8.8"}
    assert calls==[["fail2ban-client","set","sshd","unbanip","8.8.8.8"]]
    with pytest.raises(SystemExit):
        helper.unban_ssh_ip({"ip":"9.9.9.9","confirmed":True})
