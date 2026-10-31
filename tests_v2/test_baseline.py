"""Minimal baseline must never rewrite SSH, Docker or global firewall policy."""
from pathlib import Path

from v2 import vps_install, agent_transport
from v2.template_engine import Endpoint

ROOT=Path(__file__).resolve().parents[1]


def test_fresh_vps_bundle_contains_baseline_only():
    files=vps_install.render_files(Endpoint("DE2","de2.gowayot.com","DE"),
                                    "test-secret","1.1.1.1")
    assert "node-baseline.sh" in files
    installer=files["remote-install.sh"]
    assert "test \"$(docker inspect" in installer
    assert installer.index("STEP: REMNANODE_RUNNING") < installer.index("node-baseline.sh")
    assert "bash /root/.xppn-pending/node-baseline.sh ||" in installer


def test_two_sysctls_and_no_high_load_or_hysteria():
    raw=(ROOT/"v2/data/node-baseline.sh").read_text()
    assert raw.count("net.core.default_qdisc = fq")==1
    assert raw.count("net.ipv4.tcp_congestion_control = bbr")==1
    for name in ("tcp_rmem =", "tcp_wmem =", "nf_conntrack_max =",
                 "tcp_mtu_probing =", "netdev_max_backlog =",
                 "tcp_fastopen =", "cake", "Hysteria2"):
        assert name not in raw
    assert "bbr-reverted" in raw
    assert "old_cc" in raw and "old_qdisc" in raw


def test_fail2ban_ssh_only_with_verified_source_and_no_global_firewall_mutation():
    raw=(ROOT/"v2/data/node-baseline.sh").read_text()
    assert "backend = systemd" in raw
    assert "maxretry = 6" in raw
    assert "findtime = 600" in raw
    assert "bantime = 3600" in raw
    assert "ignoreip = 127.0.0.1/8 ::1 $peer $panel_ip" in raw
    assert "fail2ban-client -t" in raw
    assert "fail2ban-client status sshd" in raw
    assert "fail2ban-reverted" in raw
    assert "fail2ban-skipped-unknown-ssh-peer" in raw
    for command in ("ufw enable", "iptables -F", "iptables -P", "nft flush",
                    "systemctl restart ssh", "systemctl stop ssh",
                    "net.ipv4.ip_forward ="):
        assert command not in raw


def test_baseline_diagnostics_are_allowlisted_and_read_only():
    helper=(ROOT/"v2/agent/helper.py").read_text()
    agent=(ROOT/"v2/agent/main.go").read_text()
    assert '"baseline.status"' in agent_transport.ALLOWED
    assert '"baseline.status"' in helper
    assert '"baseline.status":true' in agent
    assert 'if action=="baseline.status":return baseline_status()' in helper
    assert '"read_only":True' in helper
    assert '"net_rx_bytes"' in agent and '"net_tx_bytes"' in agent
    assert '"tcp_retrans_segs"' in agent
