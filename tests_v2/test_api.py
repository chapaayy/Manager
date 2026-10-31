"""XPPN v2 API security and one-panel bridge planning. No network or VPS required."""
import json
import os
import sqlite3
import uuid
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from v2.app import app
from v2 import storage, remnawave
from v2.template_engine import Endpoint,Exit,render_bridge


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"v2.sqlite"))
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    monkeypatch.setenv("XPPN_V2_SESSION_SECRET","test_only_secret_please_never_use_in_prod_0123456789")
    monkeypatch.setenv("XPPN_V2_ADMIN_PASSWORD","test_admin_password_123456789")
    monkeypatch.setenv("XPPN_V2_COOKIE_SECURE","0")
    with TestClient(app) as c:
        login=c.post("/api/auth/login",json={"password":"test_admin_password_123456789"})
        assert login.status_code==200,login.text
        c.headers.update({"X-CSRF-Token":login.json()["csrf"]})
        yield c


def add_node(client,code,role,domain,country):
    result=client.post("/api/nodes",json={
        "code":code,"name":code+" "+role,
        "country":country,"domain":domain,"role":role})
    assert result.status_code==200,result.text
    return result.json()


def test_v2_isolated_single_panel_and_authentication(client):
    with storage.connect() as c:
        names={row["name"] for row in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "panel" in names
    assert "nodes" in names and "bridges" in names
    assert "projects" not in names and "deployment_profiles" not in names
    assert client.get("/api/projects").status_code==404
    assert client.get("/api/health").json()["deployment"] is False
    no_cookie=TestClient(app)
    assert no_cookie.get("/api/dashboard").status_code==401
    assert no_cookie.post("/api/nodes",json={}).status_code==401
    no_csrf=client.post("/api/nodes",json={},headers={"X-CSRF-Token":""})
    assert no_csrf.status_code==403


def test_one_panel_token_is_encrypted_and_never_returned(client):
    token="very_secret_api_token_that_is_long"
    r=client.put("/api/panel",json={
        "url":"https://panel.gowayot.com","token":token,"outbound_ip":""})
    assert r.status_code==200,r.text
    assert r.json()["url"]=="https://panel.gowayot.com"
    assert token not in json.dumps(r.json())
    assert "token_enc" not in json.dumps(r.json())
    assert r.json()["has_token"]
    with storage.connect() as c:
        row=c.execute("SELECT token_enc FROM panel WHERE id=1").fetchone()
    assert token not in row["token_enc"]
    assert storage.get_panel_token()==token
    bad=client.put("/api/panel",json={"url":"https://other.example.com","token":"","outbound_ip":""})
    assert bad.status_code==422
    assert storage.get_panel()["url"]=="https://panel.gowayot.com"


def test_bridge_import_is_read_only_and_new_exit_diff_keeps_active_json(client):
    ru=add_node(client,"RUS1","entry","rus1.gowayot.com","RU")
    de=add_node(client,"DE1","exit","de1.gowayot.com","DE")
    nl=add_node(client,"NL1","exit","nl1.gowayot.com","NL")
    create=client.post("/api/bridges",json={"name":"RU Bridge","entry_id":ru["id"]})
    assert create.status_code==200,create.text
    bridge=create.json()
    olduuid=str(uuid.uuid4())
    current=render_bridge(Endpoint("RUS1","rus1.gowayot.com","RU"),[
        Exit(Endpoint("DE1","de1.gowayot.com","DE"),olduuid)])
    current["log"]["loglevel"]="warning"
    import_result=client.post("/api/bridges/"+bridge["id"]+"/import",json={
        "config":current,"revision":0,"confirm_read_only":True})
    assert import_result.status_code==200,import_result.text
    summary=client.get("/api/dashboard").json()
    assert summary["bridges"][0]["has_snapshot"]
    assert olduuid not in json.dumps(summary)
    new_uuid=str(uuid.uuid4())
    plan_response=client.post("/api/bridges/"+bridge["id"]+"/plans",json={
        "exit_id":nl["id"],"outgoing_uuid":new_uuid})
    assert plan_response.status_code==200,plan_response.text
    plan=plan_response.json()
    assert plan["status"]=="draft"
    assert plan["inbound_port"]==8444
    assert "TO_NL1_VLESS_TLS_OUT" in plan["diff"]
    assert olduuid not in json.dumps(plan)
    assert new_uuid not in json.dumps(plan)
    assert plan["config"]["routing"]["rules"][:8] == current["routing"]["rules"]
    assert plan["requires_live_apply"]
    assert storage.get_snapshot(bridge["id"])==current
    assert not storage.get_bridge(bridge["id"])["exits"]
    approved=client.post("/api/plans/"+plan["id"]+"/approve")
    assert approved.status_code==200
    assert approved.json()["status"]=="approved"
    assert not storage.get_bridge(bridge["id"])["exits"]
    # A second concurrent plan would be based on stale source.
    second=client.post("/api/bridges/"+bridge["id"]+"/plans",json={"exit_id":de["id"]})
    assert second.status_code==422
    assert new_uuid not in json.dumps(client.get("/api/plans/"+plan["id"]).json())


def test_import_requires_confirmation_and_revision(client):
    ru=add_node(client,"RU1","entry","ru1.example.com","RU")
    bridge=client.post("/api/bridges",json={"name":"RU1","entry_id":ru["id"]}).json()
    config=render_bridge(Endpoint("RU1","ru1.example.com","RU"),[
        Exit(Endpoint("DE1","de1.example.com","DE"),str(uuid.uuid4()))])
    r=client.post("/api/bridges/"+bridge["id"]+"/import",json={
        "config":config,"revision":0,"confirm_read_only":False})
    assert r.status_code==422
    assert storage.get_snapshot(bridge["id"]) is None
    r=client.post("/api/bridges/"+bridge["id"]+"/import",json={
        "config":config,"revision":0,"confirm_read_only":True})
    assert r.status_code==200
    stale=client.post("/api/bridges/"+bridge["id"]+"/import",json={
        "config":config,"revision":0,"confirm_read_only":True})
    assert stale.status_code==422


def test_saved_library_config_encrypted_and_preset_files_are_shared(client):
    content='{"inbounds":[{"tag":"{{source.code}}"}],"outbounds":[]}'
    file=client.post("/api/configs",json={
        "name":"Xray Bridge Source","kind":"xray","content":content}).json()
    assert file["revision"]==1
    with storage.connect() as c:
        raw=c.execute("SELECT content_enc FROM library_configs WHERE id=?",(file["id"],)).fetchone()[0]
    assert content not in raw
    preset=client.post("/api/presets",json={
        "name":"Bridge DE","description":"Russia to Germany","config_ids":[file["id"]]})
    assert preset.status_code==200,preset.text
    assert preset.json()["items"][0]["kind"]=="xray"
    updated=client.put("/api/configs/"+file["id"],json={
        "name":"Xray Bridge Source v2","kind":"xray",
        "content":content.replace("source.code","source.domain"),"revision":1})
    assert updated.status_code==200
    assert updated.json()["revision"]==2
    assert next(p for p in client.get("/api/presets").json() if p["id"]==preset.json()["id"])["items"][0]["revision"]==2
    assert client.delete("/api/configs/"+file["id"]).status_code==422
    assert client.delete("/api/presets/"+preset.json()["id"]).status_code==200
    assert client.delete("/api/configs/"+file["id"]).status_code==200
    # Malformed JSON is never accepted as Xray.
    invalid=client.post("/api/configs",json={"name":"bad","kind":"xray","content":"{not json}"})
    assert invalid.status_code==422



def test_first_vps_preview_is_resolved_but_read_only(client):
    response=client.post("/api/vps/preview",json={
        "code":"de1","domain":"de1.gowayot.com","country":"DE"})
    assert response.status_code==200,response.text
    plan=response.json()
    assert plan["xray"]["inbounds"][0]["tag"]=="DE1_VLESS_TLS_IN"
    assert plan["xray"]["inbounds"][0]["settings"]["fallbacks"][0]["dest"]=="127.0.0.1:8080"
    assert "de1.gowayot.com" in plan["nginx"]
    assert any(x["key"]=="source.domain" for x in plan["variables"])
    assert storage.list_nodes()==[]
    assert "SECRET_KEY" not in json.dumps(plan)


def test_first_vps_install_requires_explicit_clean_confirmation(client):
    response=client.post("/api/vps/install",json={
        "code":"DE1","country":"DE","name":"Germany DE1",
        "domain":"de1.gowayot.com","role":"regular",
        "ip":"1.1.1.1","port":22,"password":"example-ssh-password",
        "fingerprint":"SHA256:"+("a"*43),"confirm_clean":False,
        "panel_ip":"1.1.1.1"})
    assert response.status_code==422
    assert storage.list_nodes()==[]



def test_delete_unused_draft_only_after_confirmation_and_auth(client):
    draft=add_node(client,"RUS10","regular","rus10.gowayot.com","RU")
    response=client.delete("/api/nodes/"+draft["id"])
    assert response.status_code==200,response.text
    assert response.json()["deleted"] is True
    assert all(n["id"]!=draft["id"] for n in storage.list_nodes())
    assert client.delete("/api/nodes/"+draft["id"]).status_code==404
    # Never delete a VPS if its deployment has already been queued.
    live=add_node(client,"DE11","regular","de11.gowayot.com","DE")
    storage.create_install_job(live["id"],"1.1.1.1",22,"SHA256:"+("a"*43))
    blocked=client.delete("/api/nodes/"+live["id"])
    assert blocked.status_code==422
    assert storage.get_node(live["id"])["status"]=="queued"


def test_unused_draft_deletion_refuses_bridge_references(client):
    entry=add_node(client,"RUS11","entry","rus11.gowayot.com","RU")
    bridge=client.post("/api/bridges",json={"name":"Test bridge","entry_id":entry["id"]})
    assert bridge.status_code==200,bridge.text
    denied=client.delete("/api/nodes/"+entry["id"])
    assert denied.status_code==422
    assert entry["id"] in [n["id"] for n in storage.list_nodes()]


def test_one_time_rus10_test_cleanup_is_precise_and_idempotent(client):
    response=client.post("/api/nodes",json={
        "code":"RUS10","name":"RUS10","country":"RU",
        "domain":"rus10.gowayot.com","role":"regular"})
    assert response.status_code==200,response.text
    test=response.json()
    real=add_node(client,"DE11","regular","de11.gowayot.com","DE")
    # A fresh app has already recorded the migration marker on startup.
    # Simulate upgrading an older DB that did not run this migration yet.
    with storage.transaction() as c:
        c.execute("DELETE FROM starter_seeds WHERE name=?",
                  ("cleanup:test-rus10-gowayot:2026-10",))
    assert storage.remove_one_time_test_rus10() is True
    assert [n["id"] for n in storage.list_nodes()]==[real["id"]]
    # The cleanup is never applied again, even if user later adds a new draft.
    response2=client.post("/api/nodes",json={
        "code":"RUS10","name":"RUS10","country":"RU",
        "domain":"rus10.gowayot.com","role":"regular"})
    assert response2.status_code==200,response2.text
    again=response2.json()
    assert storage.remove_one_time_test_rus10() is False
    assert storage.get_node(again["id"])["status"]=="planned"


def test_one_time_cleanup_never_removes_attached_test_draft(client):
    response=client.post("/api/nodes",json={
        "code":"RUS10","name":"RUS10","country":"RU",
        "domain":"rus10.gowayot.com","role":"regular"})
    assert response.status_code==200,response.text
    test=response.json()
    storage.create_install_job(test["id"],"1.1.1.1",22,"SHA256:"+("a"*43))
    with storage.transaction() as c:
        c.execute("DELETE FROM starter_seeds WHERE name=?",
                  ("cleanup:test-rus10-gowayot:2026-10",))
    assert storage.remove_one_time_test_rus10() is False
    assert storage.get_node(test["id"])["status"]=="queued"


def test_duplicate_domains_have_human_readable_message(client):
    add_node(client,"DE11","regular","de11.gowayot.com","DE")
    r=client.post("/api/nodes",json={
      "code":"DE12","name":"Different code","country":"DE",
      "domain":"de11.gowayot.com","role":"regular"})
    assert r.status_code==422
    assert "уже добавлен" in r.json()["detail"]
    assert "UNIQUE constraint" not in r.text


def test_manager_only_removal_api_rejects_old_vps_wipe(client, monkeypatch):
    node = add_node(client, "RUS10", "regular", "rus10.gowayot.com", "RU")
    monkeypatch.setattr(remnawave, "request",
                        lambda *_args: pytest.fail("No Remnawave call for local removal"))
    preview = client.get("/api/nodes/" + node["id"] + "/removal-preview")
    assert preview.status_code == 200, preview.text
    assert preview.json()["remnawave_available"] is True
    old = client.post("/api/nodes/" + node["id"] + "/full/start", json={"code": "RUS10"})
    assert old.status_code == 410
    old = client.post("/api/nodes/" + node["id"] + "/full/advance", json={"code": "RUS10"})
    assert old.status_code == 410
    removed = client.post("/api/nodes/" + node["id"] + "/remove", json={
        "code": "RUS10", "remove_remote": False, "delete_profile": False})
    assert removed.status_code == 200, removed.text
    assert removed.json()["vps_touched"] is False
    assert all(n["id"] != node["id"] for n in storage.list_nodes())


def test_vps_preview_uses_selected_direct_or_bridge_library_preset(client):
    presets=client.get("/api/presets").json()
    direct=next(p for p in presets if p["mode"]=="direct")
    bridge=next(p for p in presets if p["mode"]=="bridge")
    base={"code":"RUS10","domain":"rus10.gowayot.com","country":"RU"}
    for preset,role,inbounds in ((direct,"regular",1),(bridge,"entry",2)):
        response=client.post("/api/vps/preview",json={
            **base,"preset_id":preset["id"],"role":role})
        assert response.status_code==200,response.text
        data=response.json()
        assert data["preset_mode"]==preset["mode"]
        assert len(data["xray"]["inbounds"])==inbounds
        assert "SECRET_KEY" not in response.text
    invalid=client.post("/api/vps/preview",json={
        **base,"preset_id":bridge["id"],"role":"regular"})
    assert invalid.status_code==422
    assert storage.list_nodes()==[]
