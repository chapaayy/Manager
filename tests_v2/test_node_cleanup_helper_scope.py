"""Static safety guardrails for irreversible privileged cleanup code."""
from pathlib import Path
import re


def test_destructive_helper_has_fixed_scope_and_no_global_docker_wipe():
    helper=Path("v2/agent/helperlib/cleanup.py").read_text()
    dispatcher=Path("v2/agent/helperlib/dispatcher.py").read_text()
    agent=Path("v2/agent/main.go").read_text()
    uninstall=Path("v2/agent/uninstall-agent.sh").read_text()
    assert 'action == "node.cleanup"' in dispatcher
    assert 'action == "node.cleanup.finish"' in dispatcher
    assert "cleanup target is different VPS" in helper
    assert "managed compose was modified" in helper
    assert '"docker", "compose"' in helper and '"down"' in helper
    assert '"certbot", "delete"' in helper
    assert "shutil.rmtree(path)" in helper
    assert re.search(r'"node\.cleanup"\s*:\s*true',agent)
    assert re.search(r'"node\.cleanup\.finish"\s*:\s*true',agent)
    assert "systemctl disable --now node-manager-agent.service" in uninstall
    assert "systemctl daemon-reload" in uninstall
    for danger in (
        "docker system prune","docker volume prune","apt-get purge",
        "rm -rf /opt","docker rm -f $(docker ps",
    ):
        assert danger not in helper
        assert danger not in uninstall


def test_delete_not_exposed_by_regular_agent_admin_api():
    source=Path("v2/agent_transport.py").read_text()
    assert 'action.startswith("node.cleanup") and not internal' in source
    assert 'internal: bool = False' in source
    lifecycle=Path("v2/nodes/lifecycle/legacy_cleanup.py").read_text()
    facade=Path("v2/node_lifecycle.py").read_text()
    assert 'internal=True' in lifecycle
    assert '"node.cleanup.finish"' in lifecycle
    assert '"node.cleanup"' not in facade


def test_cannot_remove_cloud_vps_with_this_tool():
    source=Path("v2/agent/helperlib/cleanup.py").read_text()
    assert "systemctl poweroff" not in source
    assert "reboot" not in source
    assert "docker.service" not in source
