"""Only Manager records and explicit Remnawave API objects may be removed."""
import uuid

import pytest
from cryptography.fernet import Fernet

from v2 import agent_transport, node_lifecycle, node_removal, remnawave, storage


@pytest.fixture
def item(tmp_path, monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB", str(tmp_path / "delete.sqlite"))
    monkeypatch.setenv("XPPN_DATA_KEY", Fernet.generate_key().decode())
    storage.init_db()
    agent_transport.initialize()
    node_lifecycle.initialize()
    node = storage.create_node(code="RUS10", name="RUS10",
                               domain="rus10.gowayot.com", country="RU", role="regular")
    storage.create_install_job(node["id"], "192.0.2.10", 22, "SHA256:" + "a"*43)
    node_id, profile_id = str(uuid.uuid4()), str(uuid.uuid4())
    storage.set_install_status(node["id"], "ready", "ok",
                               remote_uuid=node_id, profile_uuid=profile_id)
    agent_token = agent_transport.issue_token(node["id"])
    return node, node_id, profile_id, agent_token


def fake_api(monkeypatch, remote, profile, *, shared=False):
    rows = [{"uuid": remote, "name": "RUS10",
             "configProfile": {"activeConfigProfileUuid": profile}}]
    other = str(uuid.uuid4())
    if shared:
        rows.append({"uuid": other, "name": "NL1",
                     "configProfile": {"activeConfigProfileUuid": profile}})
    profiles = [{"uuid": profile, "name": "XPPN RUS10 RU VLESS TLS"}]
    operations = []

    def request(method, path, *_):
        if (method, path) != ("GET", "/api/nodes"):
            raise AssertionError("Unexpected Remnawave call")
        return {"response": list(rows)}

    def delete_node(uid):
        assert uid == remote
        operations.append(("node", uid))
        rows[:] = [r for r in rows if r["uuid"] != uid]

    def delete_profile(uid):
        assert uid == profile
        operations.append(("profile", uid))
        profiles.clear()

    monkeypatch.setattr(remnawave, "request", request)
    monkeypatch.setattr(remnawave, "list_profiles", lambda: list(profiles))
    monkeypatch.setattr(remnawave, "detailed_profile", lambda *_: {
        "name": "XPPN RUS10 RU VLESS TLS", "config": {"inbounds": []}})
    monkeypatch.setattr(remnawave, "delete_node", delete_node)
    monkeypatch.setattr(remnawave, "delete_profile", delete_profile)
    return operations, rows, profiles, other


def test_manager_only_never_calls_remnawave_or_agent_even_in_finalize_ack(item, monkeypatch):
    node, remote, profile, token = item
    node_lifecycle._set(node["id"], phase="finalize_ack")
    monkeypatch.setattr(remnawave, "request", lambda *_: pytest.fail("No API"))
    monkeypatch.setattr(agent_transport, "enqueue", lambda *_1, **_2: pytest.fail("No agent"))
    result = node_removal.remove(node["id"], node["code"],
                                 delete_remote=False, delete_profile=False)
    assert result["deleted"] and result["vps_touched"] is False
    assert agent_transport.authenticate(node["id"], "Bearer " + token) is False
    with pytest.raises(LookupError):
        storage.get_node(node["id"])


def test_default_removes_own_profile_and_node_without_agent(item, monkeypatch):
    node, remote, profile, token = item
    actions, *_ = fake_api(monkeypatch, remote, profile)
    monkeypatch.setattr(agent_transport, "enqueue", lambda *_1, **_2: pytest.fail("No agent"))
    info = node_removal.preview(node["id"])
    assert info["profile_owned"] and info["shared_nodes"] == []
    out = node_removal.remove(node["id"], node["code"],
                              delete_remote=True, delete_profile=True)
    assert out["deleted"] and out["node_removed"] and out["profile_removed"]
    assert actions == [("node", remote), ("profile", profile)]
    assert agent_transport.authenticate(node["id"], "Bearer " + token) is False


def test_shared_profile_is_retained_by_default_and_other_node_untouched(item, monkeypatch):
    node, remote, profile, token = item
    actions, rows, profiles, other = fake_api(monkeypatch, remote, profile, shared=True)
    info = node_removal.preview(node["id"])
    assert [s["name"] for s in info["shared_nodes"]] == ["NL1"]
    out = node_removal.remove(node["id"], node["code"],
                              delete_remote=True, delete_profile=False)
    assert out["deleted"] and out["profile_retained"]
    assert actions == [("node", remote)]
    assert rows[0]["uuid"] == other and profiles[0]["uuid"] == profile


def test_shared_profile_needs_matching_name_and_exact_impacted_ids(item, monkeypatch):
    node, remote, profile, token = item
    actions, rows, profiles, other = fake_api(monkeypatch, remote, profile, shared=True)
    for name, ids in [("", [other]), ("XPPN RUS10 RU VLESS TLS", []),
                      ("wrong", [other])]:
        with pytest.raises(node_removal.RemovalError, match="явно подтвердить"):
            node_removal.remove(node["id"], node["code"],
                                delete_remote=True, delete_profile=True,
                                shared_confirmation=name, expected_shared_ids=ids)
    assert not actions
    assert storage.get_node(node["id"])
    out = node_removal.remove(node["id"], node["code"],
                              delete_remote=True, delete_profile=True,
                              shared_confirmation="XPPN RUS10 RU VLESS TLS",
                              expected_shared_ids=[other])
    assert out["profile_removed"]
    assert actions == [("node", remote), ("profile", profile)]
    assert rows[0]["uuid"] == other  # other node was never directly modified


def test_shared_profile_changed_since_preview_refuses_before_writes(item, monkeypatch):
    node, remote, profile, token = item
    actions, rows, _, other = fake_api(monkeypatch, remote, profile, shared=True)
    rows.append({"uuid": str(uuid.uuid4()), "name": "DE1",
                 "configProfile": {"activeConfigProfileUuid": profile}})
    with pytest.raises(node_removal.RemovalError):
        node_removal.remove(node["id"], node["code"], delete_remote=True,
                            delete_profile=True,
                            shared_confirmation="XPPN RUS10 RU VLESS TLS",
                            expected_shared_ids=[other])
    assert actions == []


def test_remote_api_failure_keeps_record_for_retry(item, monkeypatch):
    node, remote, profile, token = item
    actions, rows, profiles, _ = fake_api(monkeypatch, remote, profile)
    def error(_uid):
        raise remnawave.PanelError("HTTP 503")
    monkeypatch.setattr(remnawave, "delete_node", error)
    with pytest.raises(node_removal.RemovalError, match="API"):
        node_removal.remove(node["id"], node["code"],
                            delete_remote=True, delete_profile=True)
    assert storage.get_install_job(node["id"])["remote_uuid"] == remote
    assert storage.get_node(node["id"])
    assert actions == []


def test_profile_api_failure_can_retry_without_deleting_node_twice(item, monkeypatch):
    node, remote, profile, token = item
    actions, rows, profiles, _ = fake_api(monkeypatch, remote, profile)
    def error(_uid):
        raise remnawave.PanelError("HTTP 503")
    monkeypatch.setattr(remnawave, "delete_profile", error)
    with pytest.raises(node_removal.RemovalError, match="API"):
        node_removal.remove(node["id"], node["code"],
                            delete_remote=True, delete_profile=True)
    assert storage.get_install_job(node["id"])["remote_uuid"] == ""
    assert storage.get_install_job(node["id"])["profile_uuid"] == profile
    assert actions == [("node", remote)]
    def success(uid):
        profiles.clear()
        actions.append(("profile", uid))
    monkeypatch.setattr(remnawave, "delete_profile", success)
    out = node_removal.remove(node["id"], node["code"],
                              delete_remote=True, delete_profile=True)
    assert out["deleted"]
    assert actions == [("node", remote), ("profile", profile)]


def test_not_owned_profile_is_kept_when_removing_remote_node(item, monkeypatch):
    node, remote, profile, token = item
    actions, rows, profiles, _ = fake_api(monkeypatch, remote, profile)
    monkeypatch.setattr(remnawave, "detailed_profile", lambda *_: {
        "name": "Somebody Else's Profile", "config": {"inbounds": []}})
    with pytest.raises(node_removal.RemovalError, match="не совпадает"):
        node_removal.remove(node["id"], node["code"],
                            delete_remote=True, delete_profile=True)
    assert actions == []
    out = node_removal.remove(node["id"], node["code"],
                              delete_remote=True, delete_profile=False)
    assert out["deleted"] and out["profile_retained"]
    assert actions == [("node", remote)]


def test_cannot_start_new_cleanup_with_unfinished_legacy_cleanup(item):
    node, remote, profile, token = item
    agent_transport.enqueue(node["id"], "node.cleanup",
                            {"domain": node["domain"]}, internal=True)
    with pytest.raises(node_removal.RemovalError, match="незавершённая"):
        node_removal.remove(node["id"], node["code"],
                            delete_remote=False, delete_profile=False)


def test_preview_api_unavailable_still_allows_local_only(item, monkeypatch):
    node, remote, profile, token = item
    monkeypatch.setattr(remnawave, "request", lambda *_:
                        (_ for _ in ()).throw(remnawave.PanelError("HTTP 503")))
    preview = node_removal.preview(node["id"])
    assert not preview["remnawave_available"]
    assert node_removal.remove(node["id"], node["code"],
                               delete_remote=False, delete_profile=False)["deleted"]
