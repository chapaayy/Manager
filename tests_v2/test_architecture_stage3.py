"""Stage-3 guardrails for the modular privileged helper and fresh bootstrap."""
from pathlib import Path
import io
import zipfile

from v2 import helper_bundle, vps_install
from v2.xray import Endpoint

ROOT=Path(__file__).resolve().parents[1]


def test_root_helper_launcher_stays_tiny_and_modules_stay_focused():
    launcher=(ROOT/"v2/agent/helper.py").read_text().splitlines()
    assert len(launcher) < 100
    modules=list((ROOT/"v2/agent/helperlib").glob("*.py"))
    assert len(modules) >= 9
    for path in modules:
        assert len(path.read_text().splitlines()) < 340, path


def test_helper_bundle_is_deterministic_zip_with_no_extra_files():
    first=helper_bundle.library_zip_bytes()
    second=helper_bundle.library_zip_bytes()
    assert first==second
    with zipfile.ZipFile(io.BytesIO(first)) as archive:
        names=sorted(archive.namelist())
    assert "helperlib/common.py" in names
    assert "helperlib/security_firewall.py" in names
    assert "helperlib/security_service.py" in names
    assert all(name.startswith("helperlib/") and name.endswith(".py") for name in names)


def test_internal_bootstrap_actions_are_not_available_through_agent_sudo():
    launcher=(ROOT/"v2/agent/helper.py").read_text()
    common=(ROOT/"v2/agent/helperlib/common.py").read_text()
    worker=(ROOT/"v2/agent/fail2ban-setup.sh").read_text()
    agent=(ROOT/"v2/agent/main.go").read_text()
    assert '"security.bootstrap"' not in common
    assert '"security.fail2ban.bootstrap"' not in common
    assert 'Path("/root/.xppn-pending/agent-helper.py")' in launcher
    assert 'not os.environ.get("SUDO_USER")' in launcher
    assert 'bootstrap_fail2ban' in worker
    assert '/usr/local/libexec/node-manager-helper security.fail2ban.bootstrap' not in worker
    assert '"security.bootstrap":true' not in agent
    assert '"security.fail2ban.bootstrap":true' not in agent


def test_fresh_install_has_no_second_security_implementation():
    remote=(ROOT/"v2/data/remote-install.sh").read_text()
    baseline=(ROOT/"v2/data/node-baseline.sh").read_text()
    assert "security.bootstrap" in remote
    assert "security.bootstrap" in baseline
    assert "iptables -I INPUT" not in remote
    assert "cat >/etc/logrotate.d/" not in remote
    assert "net.ipv4.tcp_congestion_control" not in remote
    assert "[sshd]" not in remote
    assert "iptables -I INPUT" not in baseline
    assert "[sshd]" not in baseline


def test_fresh_install_stages_same_launcher_and_library_as_agent():
    files=vps_install.render_files(
        Endpoint("DE2","de2.gowayot.com","DE"),
        "secret-value-123456","1.1.1.1")
    assert files["agent-helper.py"]==helper_bundle.launcher_bytes()
    assert files["agent-helperlib.zip"]==helper_bundle.library_zip_bytes()
    installer=files["remote-install.sh"]
    assert installer.index("security.bootstrap") < installer.index("up -d remnanode")


def test_agent_install_and_upgrade_manage_helper_zip_as_one_unit():
    install=(ROOT/"v2/agent/install-agent.sh").read_text()
    upgrade=(ROOT/"v2/agent/upgrade-agent.sh").read_text()
    uninstall=(ROOT/"v2/agent/uninstall-agent.sh").read_text()
    assert "agent-helperlib.zip" in install
    assert "/usr/local/libexec/node-manager-helperlib.zip" in install
    assert "previous-helperlib.zip" in upgrade
    assert 'install -m 0644 "$stage/agent-helperlib.zip" "$helperlib"' in upgrade
    assert "node-manager-helperlib.zip" in uninstall


def test_fail2ban_worker_contains_no_configuration_logic():
    worker=(ROOT/"v2/agent/fail2ban-setup.sh").read_text()
    assert "bootstrap_fail2ban" in worker
    assert "/usr/local/libexec/node-manager-helper security.fail2ban.bootstrap" not in worker
    for duplicate in ("[sshd]","maxretry =","findtime =","bantime =","apt-get"):
        assert duplicate not in worker


def test_ssh_migration_rolls_back_the_complete_agent_bundle():
    upgrade=(ROOT/"v2/agent/upgrade-agent.sh").read_text()
    for artifact in (
        "previous-agent",
        "previous-helper",
        "previous-helperlib.zip",
        "previous-fail2ban",
        "previous-updater",
    ):
        assert artifact in upgrade
    assert upgrade.count('previous-updater') >= 4
    assert upgrade.count('previous-helperlib.zip') >= 4
    assert upgrade.count('previous-fail2ban') >= 4
