"""Stage-1 architecture boundaries and HTTP compatibility."""
from fastapi.routing import APIRoute

from v2.app import app
from v2 import storage
from v2.core import database, events


EXPECTED_ROUTES = {
    ("GET", "/"),
    ("GET", "/api/health"),
    ("POST", "/api/auth/login"),
    ("GET", "/api/auth/session"),
    ("POST", "/api/auth/logout"),
    ("GET", "/api/system/update"),
    ("POST", "/api/system/update/check"),
    ("POST", "/api/system/update"),
    ("GET", "/api/dashboard"),
    ("GET", "/api/settings/monitoring"),
    ("PUT", "/api/settings/monitoring"),
    ("GET", "/api/nodes/{node_id}/ssh-credentials"),
    ("PUT", "/api/nodes/{node_id}/ssh-credentials"),
    ("DELETE", "/api/nodes/{node_id}/ssh-credentials"),
    ("PUT", "/api/panel"),
    ("POST", "/api/panel/check"),
    ("PUT", "/api/panel/profile"),
    ("POST", "/api/vps/preview"),
    ("POST", "/api/vps/probe"),
    ("POST", "/api/vps/install"),
    ("GET", "/api/vps/jobs/{node_id}"),
    ("POST", "/api/vps/jobs/{node_id}/resume"),
    ("POST", "/api/vps/jobs/{node_id}/forget"),
    ("GET", "/api/node-certificates"),
    ("POST", "/api/node-certificates/{node_id}/migrate"),
    ("POST", "/api/node-certificates/{node_id}/sync"),
    ("POST", "/api/agent/v1/heartbeat"),
    ("GET", "/api/agent/v1/pull"),
    ("POST", "/api/agent/v1/report"),
    ("GET", "/api/agents"),
    ("GET", "/api/agents/{node_id}/monitoring"),
    ("GET", "/api/agents/{node_id}/update-status"),
    ("PUT", "/api/agents/{node_id}/auto-update"),
    ("POST", "/api/agents/{node_id}/update"),
    ("GET", "/api/agent/v1/update/manifest"),
    ("GET", "/api/agent/v1/update/binary/{arch}"),
    ("POST", "/api/agents/{node_id}/bootstrap"),
    ("POST", "/api/agents/{node_id}/repair-helper"),
    ("POST", "/api/agents/{node_id}/ssh-protection/helper"),
    ("POST", "/api/agents/{node_id}/ssh-protection/install"),
    ("POST", "/api/agents/{node_id}/ssh-protection/unban"),
    ("GET", "/api/nodes/{node_id}/security-settings"),
    ("PUT", "/api/nodes/{node_id}/security-settings"),
    ("POST", "/api/nodes/{node_id}/security-settings/apply"),
    ("POST", "/api/agents/{node_id}/tasks"),
    ("GET", "/api/agents/{node_id}/tasks/{job_id}"),
    ("POST", "/api/agents/{node_id}/revoke"),
    ("POST", "/api/nodes"),
    ("GET", "/api/nodes/{node_id}/removal-preview"),
    ("POST", "/api/nodes/{node_id}/remove"),
    ("GET", "/api/nodes/{node_id}/lifecycle"),
    ("PUT", "/api/nodes/{node_id}/archive"),
    ("POST", "/api/nodes/{node_id}/detach-dependencies"),
    ("POST", "/api/nodes/{node_id}/forget"),
    ("POST", "/api/nodes/{node_id}/abandon"),
    ("POST", "/api/nodes/{node_id}/delete-remnawave"),
    ("POST", "/api/nodes/{node_id}/full/start"),
    ("POST", "/api/nodes/{node_id}/full/advance"),
    ("DELETE", "/api/nodes/{node_id}"),
    ("POST", "/api/bridges"),
    ("GET", "/api/bridges/{bridge_id}"),
    ("POST", "/api/bridges/{bridge_id}/import"),
    ("POST", "/api/bridges/{bridge_id}/plans"),
    ("GET", "/api/plans/{plan_id}"),
    ("POST", "/api/plans/{plan_id}/approve"),
    ("GET", "/api/template/default"),
    ("GET", "/api/template/variables"),
    ("GET", "/api/configs"),
    ("POST", "/api/configs"),
    ("GET", "/api/configs/{config_id}"),
    ("PUT", "/api/configs/{config_id}"),
    ("DELETE", "/api/configs/{config_id}"),
    ("GET", "/api/presets"),
    ("POST", "/api/presets"),
    ("PUT", "/api/presets/{preset_id}"),
    ("DELETE", "/api/presets/{preset_id}"),
}


def test_http_surface_is_unchanged_after_router_split():
    actual = set()
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        for method in route.methods:
            if method not in {"HEAD", "OPTIONS"}:
                actual.add((method, route.path))
    assert actual == EXPECTED_ROUTES


def test_app_module_is_only_composition_root():
    source = open("v2/app.py", encoding="utf-8").read()
    assert len(source.splitlines()) < 50
    assert "app.include_router(router)" in source
    assert "@app.get" not in source and "@app.post" not in source


def test_storage_keeps_compatibility_aliases_for_core_primitives():
    assert storage.connect is database.connect
    assert storage.transaction is database.transaction
    assert storage.encrypt is database.encrypt
    assert storage.decrypt is database.decrypt
    assert storage.event is events.record
