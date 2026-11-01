"""Structured per-node network/security desired state and safe application."""
import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from v2 import agent_transport, security_settings, storage

ROOT=Path(__file__).resolve().parents[1]

spec=importlib.util.spec_from_file_location("security_helper_test",ROOT/"v2/agent/helper.py")
helper=importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


@pytest.fixture()
def ready_node(tmp_path,monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"security-settings.db"))
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    storage.init_db()
    agent_transport.initialize()
    security_settings.initialize()
    node=storage.create_node(code="DE2",name="DE2",domain="de2.gowayot.com",
                             country="DE",role="regular")
    storage.create_install_job(node["id"],"1.1.1.1",22,"SHA256:"+"a"*43)
    storage.set_install_status(node["id"],"ready","ok")
    agent_transport.issue_token(node["id"])
    return node


def test_defaults_are_structured_and_revisioned(ready_node):
    state=security_settings.get(ready_node["id"])
    assert state["revision"]==0
    assert state["config"]["tcp"]=={
        "enabled":True,"congestion_control":"bbr","qdisc":"fq"}
    assert state["config"]["fail2ban"]["maxretry"]==6
    assert state["config"]["firewall"]["enabled"] is True
    assert state["config"]["logs"]["nginx"]["size_mb"]==20

    config=state["config"]
    config["fail2ban"]["maxretry"]=5
    saved=security_settings.save(ready_node["id"],config,0)
    assert saved["revision"]==1
    assert saved["config"]["fail2ban"]["maxretry"]==5
    with pytest.raises(ValueError,match="изменились"):
        security_settings.save(ready_node["id"],config,0)


def test_validation_rejects_unsafe_or_unbounded_values():
    config=security_settings.default_config()
    config["firewall"]["extra_allowed_sources"]=["1.2.3.4; rm -rf /"]
    with pytest.raises(ValueError,match="IP/CIDR"):
        security_settings.normalize(config)

    config=security_settings.default_config()
    config["fail2ban"]["maxretry"]=500
    with pytest.raises(ValueError,match="допустимо"):
        security_settings.normalize(config)

    config=security_settings.default_config()
    config["tcp"]["congestion_control"]="evil"
    with pytest.raises(ValueError,match="bbr"):
        security_settings.normalize(config)


def test_apply_always_includes_panel_ipv4(ready_node):
    storage.set_panel(url="https://panel.example.org",outbound_ip="8.8.8.8",
                      token="x"*32)
    state=security_settings.get(ready_node["id"])
    config=state["config"]
    config["firewall"]["extra_allowed_sources"]=["9.9.9.0/24"]
    security_settings.save(ready_node["id"],config,0)
    job=security_settings.queue_apply(ready_node["id"],1)
    assert job["action"]=="security.settings.apply"
    with storage.connect() as db:
        raw=db.execute("SELECT payload_json FROM manager_agent_jobs WHERE id=?",
                       (job["id"],)).fetchone()["payload_json"]
    payload=json.loads(raw)
    assert payload["config"]["firewall"]["panel_ip"]=="8.8.8.8"
    assert "8.8.8.8/32" in payload["config"]["firewall"]["allowed_sources"]
    assert "9.9.9.0/24" in payload["config"]["firewall"]["allowed_sources"]


def test_firewall_apply_requires_configured_panel_ipv4(ready_node):
    state=security_settings.get(ready_node["id"])
    security_settings.save(ready_node["id"],state["config"],0)
    with pytest.raises(ValueError,match="IPv4 Remnawave Panel"):
        security_settings.queue_apply(ready_node["id"],1)


def test_apply_rejects_stale_confirmed_revision(ready_node):
    first=security_settings.get(ready_node["id"])
    saved=security_settings.save(ready_node["id"],first["config"],0)
    changed=saved["config"]
    changed["fail2ban"]["maxretry"]=4
    security_settings.save(ready_node["id"],changed,saved["revision"])
    with pytest.raises(ValueError,match="изменился после подтверждения"):
        security_settings.queue_apply(ready_node["id"],saved["revision"])


def test_agent_security_apply_is_internal_only(ready_node):
    assert "security.settings.apply" in agent_transport.ALLOWED
    with pytest.raises(agent_transport.AgentError,match="отдельные"):
        agent_transport.enqueue(ready_node["id"],"security.settings.apply",
                                {"revision":1,"config":{}},internal=False)


def test_helper_uses_allowlisted_structured_security_operations():
    raw=(ROOT/"v2/agent/helper.py").read_text()
    assert '"security.settings.apply"' in raw
    assert "def apply_security_settings" in raw
    assert "XPPN_NODE_API4" in raw and "XPPN_NODE_API6" in raw
    assert "net.ipv4.tcp_congestion_control" in raw
    assert "/etc/logrotate.d/xppn-nginx" in raw
    assert "/etc/logrotate.d/xppn-remnanode" in raw
    assert "security_settings_supported" in raw
    for dangerous in ("iptables -F INPUT","iptables -P INPUT","nft flush ruleset",
                      "ufw --force reset","systemctl restart ssh.service"):
        assert dangerous not in raw


def test_security_ui_exposes_all_managed_groups():
    js=(ROOT/"v2/static/node-security.js").read_text()
    for marker in ("security-tcp-cc","security-tcp-qdisc","security-f2b-retry",
                   "security-f2b-find","security-f2b-ban","security-f2b-trusted",
                   "security-fw-extra","security-fw-ipv6",
                   "security-log-","-size","-archives",
                   "saveNodeSecuritySettings"):
        assert marker in js


def test_firewall_script_owns_only_dedicated_2222_chains():
    script=helper._firewall_script(
        "8.8.8.8",["8.8.8.8/32","9.9.9.0/24"],True,True,False)
    assert "XPPN_NODE_API4" in script and "XPPN_NODE_API6" in script
    assert "iptables -A XPPN_NODE_API4 -s 8.8.8.8/32 -j ACCEPT" in script
    assert "iptables -A XPPN_NODE_API4 -s 9.9.9.0/24 -j ACCEPT" in script
    assert "iptables -A XPPN_NODE_API4 -j DROP" in script
    assert "iptables -F INPUT" not in script
    assert "iptables -P INPUT" not in script
    assert "ip6tables -C INPUT -p tcp --dport \"$PORT\" -j DROP" not in script


def test_only_recognized_legacy_migration_removes_old_ipv6_drop():
    normal=helper._firewall_script(
        "8.8.8.8",["8.8.8.8/32"],True,True,False)
    migration=helper._firewall_script(
        "8.8.8.8",["8.8.8.8/32"],True,True,True)
    legacy='ip6tables -C INPUT -p tcp --dport "$PORT" -j DROP'
    assert legacy not in normal
    assert legacy in migration
