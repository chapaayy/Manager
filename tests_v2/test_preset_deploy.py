"""Preset-backed direct-node installation; bridge topology is inactive."""
import json
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


def direct():
    return next(p for p in library.list_presets() if p["mode"]=="direct")


def test_two_xray_files_but_only_one_active_install_bundle(ready):
    configs=library.list_files()
    presets=library.list_presets()
    assert len(configs)==5
    assert sum(c["kind"]=="xray" for c in configs)==2
    assert len(presets)==1
    assert presets[0]["mode"]=="direct"
    assert {i["kind"] for i in presets[0]["items"]}=={
        "xray","nginx","nginx_compose","node_compose"}
    assert any(c["name"]=="XPPN · Xray Bridge VLESS TLS" for c in configs)
    bundled.seed_defaults()
    assert len(library.list_files())==5
    assert len(library.list_presets())==1


def test_direct_template_is_rendered_from_actual_library_file(ready):
    p=direct()
    snap=preset_deploy.render_snapshot(p["id"],ready,"regular")
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


def test_bridge_file_can_be_kept_as_library_only_but_not_install_preset(ready):
    bridge=next(c for c in library.list_files() if c["name"]=="XPPN · Xray Bridge VLESS TLS")
    with pytest.raises(ValueError,match="отключена"):
        library.save_preset(name="Legacy bridge",description="",config_ids=[bridge["id"]],mode="bridge")
    custom=library.save_preset(name="Bridge archive",description="library only",
                               config_ids=[bridge["id"]],mode="custom")
    with pytest.raises(ValueError,match="предназначен"):
        preset_deploy.render_snapshot(custom["id"],ready,"regular")


def test_edited_direct_xray_library_file_is_used(ready):
    cfg=next(c for c in library.list_files() if c["name"]=="XPPN · Xray Direct VLESS TLS")
    old=library.get_file(cfg["id"])
    changed=old["content"].replace('"warning"','"info"')
    library.save_file(name=cfg["name"],kind="xray",content=changed,
                      file_id=cfg["id"],revision=cfg["revision"])
    snap=preset_deploy.render_snapshot(direct()["id"],ready,"regular")
    assert snap["xray"]["log"]["loglevel"]=="info"
    assert snap["revisions"]["xray"]==2


def test_immutable_snapshot_and_independent_node_config_selection(ready):
    p=direct()
    snap=preset_deploy.render_snapshot(p["id"],ready,"regular")
    n=storage.create_node(code=ready.code,name=ready.code,domain=ready.domain,
                          country=ready.country,role="regular")
    storage.create_install_job(n["id"],"192.0.2.5",22,"SHA256:"+"a"*43)
    storage.save_install_preset(n["id"],p["id"],snap)
    storage.set_node_config_choices_from_preset(n["id"],p["id"])
    choices=storage.get_node_config_choices(n["id"])["choices"]
    assert set(choices)=={"xray","nginx","nginx_compose","node_compose"}
    cfg=next(c for c in library.list_files() if c["name"]=="XPPN · Xray Direct VLESS TLS")
    source=library.get_file(cfg["id"])
    library.save_file(name=cfg["name"],kind="xray",
                      content=source["content"].replace('"warning"','"info"'),
                      file_id=cfg["id"],revision=cfg["revision"])
    persisted=storage.get_install_preset(n["id"])
    assert persisted["xray"]["log"]["loglevel"]=="warning"
    # Selection references the library file and therefore exposes its new revision
    # only after querying the choice again; frozen install snapshot is unchanged.
    assert storage.get_node_config_choices(n["id"])["choices"]["xray"]["revision"]==2


def test_compose_changes_are_restricted_but_log_rotation_customization_allowed(ready):
    p=direct()
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


def test_preview_is_direct_only_and_contains_no_secret(ready):
    p=direct()
    report=vps_install.preview_plan(ready,p["id"],"regular")
    assert report["name"]=="XPPN RUS10 RU VLESS TLS"
    assert report["preset_mode"]=="direct"
    assert "SECRET_KEY" not in json.dumps(report)
    assert {o["tag"] for o in report["xray"]["outbounds"]}=={"DIRECT","BLOCKED"}
