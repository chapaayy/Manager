"""Fresh-node security must have one implementation: the modular root helper."""
from pathlib import Path

from v2 import agent_transport, vps_install
from v2.xray import Endpoint

ROOT=Path(__file__).resolve().parents[1]


def helper_source():
    return "\n".join(
        path.read_text()
        for path in sorted((ROOT/"v2/agent/helperlib").glob("*.py"))
    )


def test_fresh_vps_bundle_uses_same_helper_as_agent():
    files=vps_install.render_files(
        Endpoint("DE2","de2.gowayot.com","DE"),
        "test-secret","1.1.1.1")
    assert "node-baseline.sh" not in files
    assert isinstance(files["agent-helper.py"],bytes)
    assert isinstance(files["agent-helperlib.zip"],bytes)
    installer=files["remote-install.sh"]
    assert "security.bootstrap" in installer
    assert "agent-helperlib.zip" in installer
    assert installer.index("security.bootstrap") < installer.index(
        "up -d remnanode")
    assert "iptables -I INPUT" not in installer
    assert "/etc/logrotate.d/xppn-remnanode" not in installer


def test_baseline_wrapper_has_no_duplicate_security_implementation():
    raw=(ROOT/"v2/data/node-baseline.sh").read_text()
    assert "security.bootstrap" in raw
    for duplicate in (
        "net.ipv4.tcp_congestion_control = bbr",
        "fail2ban-client -t",
        "iptables -I",
        "/etc/logrotate.d/xppn-nginx",
    ):
        assert duplicate not in raw


def test_tcp_baseline_is_two_managed_values_with_rollback():
    raw=(ROOT/"v2/agent/helperlib/security_tcp.py").read_text()
    assert "net.core.default_qdisc = " in raw
    assert "net.ipv4.tcp_congestion_control = " in raw
    assert "/etc/xppn-baseline-previous" in raw
    assert "tcp settings failed validation" in raw
    for name in (
        "tcp_rmem","tcp_wmem","nf_conntrack_max","tcp_mtu_probing",
        "netdev_max_backlog","tcp_fastopen","cake","Hysteria2",
    ):
        assert name not in raw


def test_fail2ban_is_ssh_only_and_firewall_never_changes_global_policy():
    f2b=(ROOT/"v2/agent/helperlib/security_fail2ban.py").read_text()
    firewall=(ROOT/"v2/agent/helperlib/security_firewall.py").read_text()
    assert "[sshd]" in f2b
    assert "backend = systemd" in f2b
    assert "maxretry" in f2b and "findtime" in f2b and "bantime" in f2b
    assert "fail2ban-client" in f2b
    assert "XPPN_NODE_API4" in firewall and "XPPN_NODE_API6" in firewall
    combined=f2b+"\n"+firewall
    for command in (
        "ufw enable","iptables -F INPUT","iptables -P INPUT",
        "nft flush ruleset","systemctl restart ssh.service",
        "systemctl stop ssh.service","net.ipv4.ip_forward =",
    ):
        assert command not in combined


def test_baseline_diagnostics_are_allowlisted_and_read_only():
    dispatcher=(ROOT/"v2/agent/helperlib/dispatcher.py").read_text()
    status=(ROOT/"v2/agent/helperlib/security_status.py").read_text()
    agent=(ROOT/"v2/agent/main.go").read_text()
    assert "baseline.status" in agent_transport.ALLOWED
    assert 'action == "baseline.status"' in dispatcher
    assert '"read_only": True' in status
    assert '"net_rx_bytes"' in agent and '"net_tx_bytes"' in agent
    assert '"net_rx_mbps"' in agent and '"net_tx_mbps"' in agent
    assert '"tcp_retrans_segs"' in agent
