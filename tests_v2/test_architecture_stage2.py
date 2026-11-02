"""Stage-2 node-domain architecture guardrails."""
from pathlib import Path

LEGACY_FACADES = {
    "v2/vps_install.py": 80,
    "v2/node_lifecycle.py": 60,
    "v2/node_removal.py": 40,
    "v2/node_cert_sync.py": 45,
    "v2/node_local_tls.py": 40,
    "v2/security_settings.py": 35,
    "v2/remnawave.py": 100,
}

DOMAIN_LIMIT = 330
FORBIDDEN_LEGACY_IMPORTS = (
    "vps_install",
    "node_lifecycle",
    "node_removal",
    "node_cert_sync",
    "node_local_tls",
    "security_settings",
)


def test_legacy_modules_are_small_compatibility_facades():
    for filename, maximum in LEGACY_FACADES.items():
        lines = Path(filename).read_text(encoding="utf-8").splitlines()
        assert len(lines) <= maximum, (filename, len(lines), maximum)


def test_node_domain_files_remain_focused():
    for path in Path("v2/nodes").rglob("*.py"):
        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) <= DOMAIN_LIMIT, (str(path), len(lines))


def test_new_node_domain_does_not_depend_on_legacy_facades():
    for path in Path("v2/nodes").rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        for legacy in FORBIDDEN_LEGACY_IMPORTS:
            assert f"import {legacy}" not in source, (path, legacy)
            assert f"from ... import {legacy}" not in source, (path, legacy)
            assert f"from .. import {legacy}" not in source, (path, legacy)


def test_install_is_split_by_responsibility():
    root = Path("v2/nodes/install")
    for name in ("ssh.py", "render.py", "remote.py", "registration.py", "service.py"):
        assert (root / name).is_file()


def test_tls_has_one_profile_ownership_source():
    shared = Path("v2/nodes/profile_ownership.py").read_text(encoding="utf-8")
    assert "def attached_profile" in shared
    assert "def profile_users" in shared
    assert "def expected_profile_name" in shared
    removal = Path("v2/nodes/removal/remote.py").read_text(encoding="utf-8")
    assert "from ..profile_ownership import" in removal
    tls = Path("v2/nodes/tls/profile.py").read_text(encoding="utf-8")
    assert "from ..profile_ownership import" in tls


def test_legacy_full_cleanup_is_physically_isolated():
    lifecycle = Path("v2/nodes/lifecycle")
    legacy = (lifecycle / "legacy_cleanup.py").read_text(encoding="utf-8")
    state = (lifecycle / "state.py").read_text(encoding="utf-8")
    assert '"node.cleanup"' in legacy
    assert '"node.cleanup.finish"' in legacy
    assert '"node.cleanup"' not in state
    assert '"node.cleanup.finish"' not in state


def test_remnawave_transport_is_separate_from_resources():
    client = Path("v2/integrations/remnawave/client.py").read_text(encoding="utf-8")
    profiles = Path("v2/integrations/remnawave/profiles.py").read_text(encoding="utf-8")
    nodes = Path("v2/integrations/remnawave/nodes.py").read_text(encoding="utf-8")
    assert "http.client" in client
    assert "http.client" not in profiles
    assert "http.client" not in nodes
    assert "socket.create_connection" in client
