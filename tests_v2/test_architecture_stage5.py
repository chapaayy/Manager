"""Stage-5 architecture guardrails: legacy isolation and production naming."""
from pathlib import Path

from v2 import migrate, template_engine
from v2.legacy import migrate_v1
from v2.xray import Endpoint, TemplateError
from v2.bridge import renderer as bridge_renderer

ROOT=Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT/path).read_text(encoding="utf-8")


def test_active_direct_code_does_not_depend_on_legacy_template_facade():
    active=[
        ROOT/"v2/agent_bootstrap.py",
        ROOT/"v2/vps_install.py",
        ROOT/"v2/preset_deploy.py",
        ROOT/"v2/core/errors.py",
        *sorted((ROOT/"v2/nodes").rglob("*.py")),
        *sorted((ROOT/"v2/integrations").rglob("*.py")),
        *sorted(
            path for path in (ROOT/"v2/api").glob("*.py")
            if path.name not in {"bridge.py","router.py"}
        ),
    ]
    for path in active:
        source=path.read_text(encoding="utf-8")
        assert "template_engine" not in source, path
        assert "bridge.renderer" not in source, path
        assert "bridge.service" not in source, path
        assert "bridge.repository" not in source, path


def test_bridge_implementation_is_physically_isolated():
    bridge=ROOT/"v2/bridge"
    for name in (
        "__init__.py","api.py","repository.py","service.py","renderer.py",
        "data/xray_bridge_template.json",
    ):
        assert (bridge/name).is_file(), name
    assert not (ROOT/"v2/data/xray_bridge_template.json").exists()
    assert "from ..bridge import api as bridge_api" in read("v2/api/router.py")
    assert "bridge_api.router" in read("v2/api/router.py")
    assert "from .bridge.repository import (" in read("v2/storage.py")


def test_old_bridge_paths_are_compatibility_only_and_stay_small():
    limits={
        "v2/template_engine.py":60,
        "v2/service.py":15,
        "v2/repositories/bridge.py":40,
        "v2/api/bridge.py":10,
    }
    for path,limit in limits.items():
        source=read(path)
        assert len(source.splitlines()) < limit, path
        assert "Compatibility" in source, path
    assert template_engine.Endpoint is Endpoint
    assert template_engine.TemplateError is TemplateError
    assert template_engine.render_bridge is bridge_renderer.render_bridge


def test_legacy_bridge_schema_is_preserved_until_explicit_db_migration():
    schema=read("v2/repositories/schema.py")
    for table in ("bridges","bridge_exits","plans"):
        assert "CREATE TABLE IF NOT EXISTS "+table in schema
    api=read("v2/bridge/api.py")
    assert "HTTPException(410" in api
    assert "Система мостов временно отключена" in api


def test_v1_migration_is_outside_active_runtime_with_compat_entrypoint():
    shim=read("v2/migrate.py")
    implementation=read("v2/legacy/migrate_v1.py")
    assert len(shim.splitlines()) < 20
    assert "compatibility" in shim.lower()
    assert "mode=ro" in implementation
    assert migrate.migrate_panel is migrate_v1.migrate_panel
    assert migrate.inspect_legacy is migrate_v1.inspect_legacy


def test_production_uses_non_preview_file_names():
    install=read("v2/install.sh")
    updater=read("v2/host_updater.py")
    activation=read("v2/activate-web-updates.sh")
    compose=read("v2/compose.yml")
    assert 'ENVFILE="$APP/v2/.env"' in install
    assert '-f "$APP/v2/compose.yml"' in install
    assert 'PRIMARY_ENV = APP / "v2" / ".env"' in updater
    assert 'PRIMARY_COMPOSE = APP / "v2" / "compose.yml"' in updater
    assert 'ENVFILE="$APP/v2/.env"' in activation
    assert '-f "$APP/v2/compose.yml"' in activation
    assert "path: .env" in compose
    assert "path: .env.preview" not in compose
    assert (ROOT/"v2/.env.example").is_file()
    assert not (ROOT/"v2/.env.preview.example").exists()


def test_old_preview_compose_is_explicit_transition_compatibility():
    compatibility=read("v2/compose.preview.yml")
    assert compatibility.startswith("# COMPATIBILITY ONLY:")
    assert "previously" in compatibility
    install=read("v2/install.sh")
    updater=read("v2/host_updater.py")
    # Existing secrets are copied forward; old updater path remains a fallback.
    assert 'LEGACY_ENVFILE="$APP/v2/.env.preview"' in install
    assert 'LEGACY_ENV = APP / "v2" / ".env.preview"' in updater
    assert 'LEGACY_COMPOSE = APP / "v2" / "compose.preview.yml"' in updater
    architecture=read("v2/ARCHITECTURE.md")
    assert "stable legacy identity" in architecture
    assert "SQLite volume" in architecture


def test_development_install_is_physically_separate_from_production():
    dev=read("v2/dev-install.sh")
    compose=read("v2/compose.dev.yml")
    wrapper=read("v2/preview-install.sh")
    assert 'TARGET="/opt/xppn-manager-v2-dev"' in dev
    assert "xppn-v2-dev" in dev
    assert "8791" in dev
    assert "name: xppn-v2-dev" in compose
    assert "8791:8000" in compose
    assert "v2-dev-data" in compose
    assert "dev-install.sh" in wrapper
    assert len(wrapper.splitlines()) < 10


def test_stale_preview_product_language_is_gone():
    dashboard=read("v2/api/dashboard.py")
    installer=read("v2/install.sh")
    assert '"phase": "single-panel"' in dashboard
    assert "preview-only" not in dashboard
    assert "XPPN Manager v2.3" in installer
    assert "Установка VPN-нод в v2 пока не подключена" not in installer


def test_architecture_document_covers_runtime_and_legacy_boundaries():
    doc=read("v2/ARCHITECTURE.md")
    for heading in (
        "## 2. Dependency direction",
        "## 4. Disabled Bridge subsystem",
        "## 7. Agent and privileged helper",
        "## 8. TLS ownership",
        "## 9. Node filesystem",
        "## 10. Manager VPS filesystem",
        "## 11. Docker Compose naming",
        "## 15. Compatibility shims",
    ):
        assert heading in doc
    for path in (
        "/opt/xppn-manager-v2/v2/.env",
        "/data/xppn-v2.db",
        "/opt/nginx/certs/",
        "/usr/local/bin/node-manager-agent",
    ):
        assert path in doc
