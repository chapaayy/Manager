"""Static safety guardrails for irreversible privileged cleanup code."""
from pathlib import Path

def test_destructive_helper_has_fixed_scope_and_no_global_docker_wipe():
    helper=Path("v2/agent/helper.py").read_text()
    agent=Path("v2/agent/main.go").read_text()
    uninstall=Path("v2/agent/uninstall-agent.sh").read_text()
    assert 'if action=="node.cleanup":return _cleanup_managed(data)' in helper
    assert 'if action=="node.cleanup.finish":return _finish_cleanup(data)' in helper
    assert 'if actual!=requested:' in helper
    assert 'set(services)!=set(allowed)' in helper
    assert '["docker","compose","-f",str(file),"down","--timeout","5"]' in helper
    assert '["certbot","delete","--cert-name",name,"--non-interactive"]' in helper
    assert "shutil.rmtree(path)" in helper
    assert '"node.cleanup":true' in agent and '"node.cleanup.finish":true' in agent
    assert "systemctl disable --now node-manager-agent.service" in uninstall
    assert "systemctl daemon-reload" in uninstall
    for danger in ("docker system prune", "docker volume prune",
                   "apt-get purge", "rm -rf /opt", "docker rm -f $(docker ps"):
        assert danger not in helper
        assert danger not in uninstall


def test_delete_not_exposed_by_regular_agent_admin_api():
    source=Path("v2/agent_transport.py").read_text()
    assert 'action.startswith("node.cleanup") and not internal' in source
    assert 'internal: bool = False' in source
    lifecycle=Path("v2/node_lifecycle.py").read_text()
    assert 'internal=True' in lifecycle
    assert '"node.cleanup.finish"' in lifecycle


def test_cannot_remove_cloud_vps_with_this_tool():
    source=Path("v2/agent/helper.py").read_text()
    assert "systemctl poweroff" not in source
    assert "reboot" not in source
    assert "docker.service" not in source.split("def _cleanup_managed(request):")[1].split("def _finish_cleanup")[0]
