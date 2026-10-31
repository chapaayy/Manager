"""Preset-backed installation: only snapshots, never real SSH or Remnawave."""
import json
from pathlib import Path
import pytest
from cryptography.fernet import Fernet

from v2 import bundled, library, preset_deploy, storage, vps_install
from v2.template_engine import Endpoint, validate_rendered


@pytest.fixture
def ready(tmp_path,monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"presets.sqlite"))
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    storage.init_db()
    bundled.seed_defaults()
    return Endpoint("RUS10","rus10.gowayot.com","RU")


def _presets():
    return {p["mode"]:p for p in library.list_presets()}


def test_two_xray_templates_and_two_install_presets_seed_idempotently(ready):
    bundles=_presets()
    assert set(bundles)=={"direct","bridge"}
    configs=library.list_files()
    assert len(configs)==5
    assert sum(c["kind"]=="xray" for c in configs)==2
    assert all({i["kind"] for i in p["items"]}==
               {"xray","nginx","nginx_compose","node_compose"}
               for p in bundles.values())
    bundled.seed_defaults()
    assert len(library.list_files())==5
    assert len(library.list_presets())==2


def test_direct_template_is_rendered_from_actual_library_file(ready):
    preset=_presets()["direct"]
    snap=preset_deploy.render_snapshot(preset["id"],ready,"regular")
    x=snap["xray"]
    validate_rendered(x)
    assert snap["mode"]=="direct"
    assert len(x["inbounds"])==1
    assert x["inbounds"][0]["tag"]=="RUS10_VLESS_TLS_IN"
    assert x["inbounds"][0]["port"]==443
    assert x["routing"]["rules"][-1]["outboundTag"]=="DIRECT"
    assert x["inbounds"][0]["streamSettings"]["tlsSettings"]["certificates"][0]["keyFile"]==(
        "/opt/nginx/certs/rus10.gowayot.com_privkey.key")
    assert "{{" not in json.dumps(x)


def test_bridge_bootstraps_two_inbounds_but_no_unverified_exit(ready):
    preset=_presets()["bridge"]
    snap=preset_deploy.render_snapshot(preset["id"],ready,"entry")
    x=snap["xray"]
    validate_rendered(x)
    assert snap["mode"]=="bridge"
    assert len(x["inbounds"])==2
    assert {i["port"] for i in x["inbounds"]}=={443,8443}
    assert all("rus10.gowayot.com" in json.dumps(i) for i in x["inbounds"])
    assert [o["tag"] for o in x["outbounds"]]==["BLOCKED"]
    assert all(r["outboundTag"]=="BLOCKED" for r in x["routing"]["rules"])
    assert "exit.domain" not in json.dumps(x)
    assert "bridge.user_id" not in json.dumps(x)
    assert "до создания реальных" in snap["note"]


def test_role_mismatch_refused_before_writes(ready):
    bundles=_presets()
    with pytest.raises(ValueError,match="не соответствует"):
        preset_deploy.render_snapshot(bundles["bridge"]["id"],ready,"regular")
    with pytest.raises(ValueError,match="не соответствует"):
        preset_deploy.render_snapshot(bundles["direct"]["id"],ready,"entry")


def test_edited_xray_library_file_is_used_without_modifying_existing_nodes(ready):
    cfg=next(c for c in library.list_files() if c["name"]=="XPPN · Xray Direct VLESS TLS")
    old=library.get_file(cfg["id"])
    changed=old["content"].replace('"warning"','"info"')
    assert changed!=old["content"]
    library.save_file(name=cfg["name"],kind="xray",content=changed,
                      file_id=cfg["id"],revision=cfg["revision"])
    snap=preset_deploy.render_snapshot(_presets()["direct"]["id"],ready,"exit")
    assert snap["xray"]["log"]["loglevel"]=="info"
    assert snap["revisions"]["xray"]==2


def test_immutable_snapshot_after_library_change(ready):
    p=_presets()["direct"]
    snap=preset_deploy.render_snapshot(p["id"],ready,"regular")
    n=storage.create_node(code=ready.code,name=ready.code,domain=ready.domain,
                          country=ready.country,role="regular")
    storage.create_install_job(n["id"],"192.0.2.5",22,"SHA256:"+"a"*43)
    storage.save_install_preset(n["id"],p["id"],snap)
    assert "preset_snapshot_enc" not in storage.get_install_job(n["id"])
    cfg=next(c for c in library.list_files() if c["name"]=="XPPN · Xray Direct VLESS TLS")
    source=library.get_file(cfg["id"])
    library.save_file(name=cfg["name"],kind="xray",
                      content=source["content"].replace('"warning"','"info"'),
                      file_id=cfg["id"],revision=cfg["revision"])
    persisted=storage.get_install_preset(n["id"])
    assert persisted["xray"]["log"]["loglevel"]=="warning"
    assert persisted["preset_id"]==p["id"]


def test_compose_changes_are_restricted_but_log_rotation_customization_allowed(ready):
    p=_presets()["direct"]
    conf=next(c for c in library.list_files() if c["kind"]=="nginx_compose")
    current=library.get_file(conf["id"])
    safe=current["content"].replace('max-file: "3"','max-file: "5"')
    library.save_file(name=conf["name"],kind=conf["kind"],content=safe,
                      file_id=conf["id"],revision=conf["revision"])
    assert 'max-file: "5"' in preset_deploy.render_snapshot(p["id"],ready,"regular")["nginx_compose"]
    edited=library.get_file(conf["id"])
    unsafe=edited["content"].replace('"127.0.0.1:8080:8080"','"0.0.0.0:8080:8080"')
    library.save_file(name=conf["name"],kind=conf["kind"],content=unsafe,
                      file_id=conf["id"],revision=edited["revision"])
    with pytest.raises(ValueError,match="Compose"):
        preset_deploy.render_snapshot(p["id"],ready,"regular")


def test_preview_mentions_mode_without_secret_or_panel_operations(ready):
    preset=_presets()["bridge"]
    report=vps_install.preview_plan(ready,preset["id"],"entry")
    assert report["name"]=="XPPN RUS10 RU BRIDGE VLESS TLS"
    assert report["preset_mode"]=="bridge"
    assert "SECRET_KEY" not in json.dumps(report)
    assert report["xray"]["outbounds"]==[{"tag":"BLOCKED","protocol":"blackhole"}]
