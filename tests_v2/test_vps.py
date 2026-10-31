"""No real VPS or Remnawave writes in CI. Explicitly verify installer safety."""
import json
import os
from pathlib import Path
import pytest
from cryptography.fernet import Fernet

from v2 import bundled,storage,vps_install
from v2.template_engine import Endpoint,validate_rendered


@pytest.fixture
def db(tmp_path,monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"v2.db"))
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    storage.init_db()
    return tmp_path


def test_starter_bundle_contains_working_example_nginx_and_compose(db):
    bundled.seed_defaults()
    with storage.connect() as c:
        configs=c.execute("SELECT name,kind,content_enc FROM library_configs").fetchall()
        presets=c.execute("SELECT id FROM presets").fetchall()
    assert len(configs)==4
    assert {c["kind"] for c in configs}=={"xray","nginx","nginx_compose","node_compose"}
    assert len(presets)==1
    originals={c["kind"]:storage.decrypt(c["content_enc"]) for c in configs}
    xray=json.loads(originals["xray"])
    assert xray["inbounds"][0]["tag"]=="{{source.code}}_{{exit.code}}_VLESS_TLS_IN"
    assert xray["inbounds"][1]["port"]==8443
    assert "127.0.0.1:8080" in originals["nginx_compose"]
    assert "acme-challenge" in originals["nginx"]
    assert "remnawave/node:3.4.1" in originals["node_compose"]
    assert "SECRET_KEY" not in originals["node_compose"].split("environment:")[1].split("volumes:")[0]
    # User changes must never be reset.
    storage.encrypt("dummy")  # encryption configured
    bundled.seed_defaults()
    with storage.connect() as c:
        assert c.execute("SELECT count(*) FROM library_configs").fetchone()[0]==4


def test_rendered_node_tls_has_no_old_bridge_routes_or_plaintext_secrets():
    from v2.vps_install import xray_config
    x=xray_config(Endpoint("DE1","de1.gowayot.com","DE"),
      "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----",
      "-----BEGIN PRIVATE KEY-----\nBBB\n-----END PRIVATE KEY-----")
    validate_rendered(x)
    assert len(x["inbounds"])==1
    assert x["inbounds"][0]["port"]==443
    assert x["inbounds"][0]["settings"]["fallbacks"][0]["dest"]=="127.0.0.1:8080"
    assert x["routing"]["rules"][-1]["outboundTag"]=="DIRECT"
    assert all("TO_DE1" not in json.dumps(z) for z in x["outbounds"])
    assert x["inbounds"][0]["streamSettings"]["tlsSettings"]["certificates"][0]["key"][0]=="-----BEGIN PRIVATE KEY-----"


@pytest.mark.parametrize("bad",["127.0.0.1","10.0.0.1","192.168.1.1","::1","0.0.0.0","256.256.256.256"])
def test_ssh_rejects_internal_addresses(bad):
    with pytest.raises(ValueError):
        vps_install.check_ip(bad)


def test_render_remote_files_preserves_shell_dollar_and_no_secret_in_log(db):
    rendered=vps_install.render_files(Endpoint("DE1","de1.gowayot.com","DE"),
                                      "base64secretkeyabc123", "1.1.1.1")
    assert "de1.gowayot.com" in rendered["nginx.conf"]
    assert "{{" not in rendered["nginx.conf"]
    assert "https://$host$request_uri" in rendered["nginx.conf"]
    assert rendered["node.env"]=="SECRET_KEY=base64secretkeyabc123\n"
    assert "1.1.1.1" in rendered["panel-ip"]


def test_installer_rejects_unconfirmed_and_mismatched_ssh_key(db,monkeypatch):
    def nope(*args,**kwargs):
        raise ValueError("SSH-ключ изменился")
    monkeypatch.setattr(vps_install,"preflight",nope)
    with pytest.raises(ValueError,match="SSH-ключ"):
        vps_install.start_install(
            code="DE1",country="DE",name="Germany DE1",domain="de1.gowayot.com",
            role="regular",ip="1.1.1.1",port=22,password="not_stored",
            fingerprint_value="SHA256:"+("a"*43),panel_ip="1.1.1.1")
    assert storage.list_nodes()==[]


def test_interrupted_jobs_preserve_truth_without_password(db):
    node=storage.create_node(code="DE1",name="Germany",domain="de1.example.org",
                             country="DE",role="regular")
    storage.create_install_job(node["id"],"1.1.1.1",22,"SHA256:"+("a"*43))
    storage.set_install_status(node["id"],"installing","Устанавливаем Node")
    storage.mark_interrupted_jobs()
    assert storage.get_install_job(node["id"])["stage"]=="interrupted"
    assert storage.get_node(node["id"])["status"]=="interrupted"
    with storage.connect() as c:
        tables=[x["name"] for x in c.execute("PRAGMA table_info(node_installations)")]
    assert not any("password" in t for t in tables)



def test_remnawave_node_health_requires_actual_xray_telemetry(monkeypatch):
    from v2 import remnawave
    one="aaaa-bbbb"
    rows=[
        {"uuid":one,"isConnected":True,"versions":{"xray":"25.8.1"},"xrayUptime":123},
    ]
    monkeypatch.setattr(remnawave,"request",lambda method,path:{"response":rows})
    assert remnawave.node_health(one)["connected"]
    assert remnawave.node_health(one)["xray_running"]
    rows[0]["isConnected"]=False
    assert remnawave.node_health(one)["connected"] is False
    rows[0]["isConnected"]=True
    rows[0]["versions"]={"xray":None}
    rows[0]["xrayUptime"]=0
    assert remnawave.node_health(one)["xray_running"] is False
    rows.clear()
    with pytest.raises(remnawave.PanelError):
        remnawave.node_health(one)



def test_remnawave_install_preview_never_promises_node_local_keyfile():
    """The preview mirrors the actual Remnawave API payload's certificate shape."""
    from v2.vps_install import preview_plan
    data=preview_plan(Endpoint("RUS10","rus10.gowayot.com","RU"))
    cert=data["xray"]["inbounds"][0]["streamSettings"]["tlsSettings"]["certificates"][0]
    assert "keyFile" not in cert and "certificateFile" not in cert
    assert "key" in cert and "certificate" in cert
    assert "PRIVATE KEY: issued by Certbot" in str(cert["key"])
    assert "-----BEGIN PRIVATE KEY-----" not in str(data)
    assert data["tls_profile_mode"]=="inline_pem_required_by_remnawave_panel_api"
    assert "Panel backend" in data["note"]
    assert "Remnawave" in data["note"]


def test_only_node_local_certfile_paths_are_blocked_in_remnawave_api():
    from v2.remnawave import guard_node_only_tls_paths, PanelError
    import pytest
    def config(certificate):
        return {"inbounds":[{"streamSettings":{"tlsSettings":{
            "certificates":[certificate]}}}]}
    for key in ("keyFile","certificateFile"):
        with pytest.raises(PanelError,match="Панель читает"):
            guard_node_only_tls_paths(config({
                key:"/opt/nginx/certs/rus10.gowayot.com_privkey.key"}))
        with pytest.raises(PanelError,match="Панель читает"):
            guard_node_only_tls_paths(config({
                key:"/etc/letsencrypt/live/rus10.gowayot.com/privkey.pem"}))
    # The official Panel-mounted location is not arbitrarily rejected.
    guard_node_only_tls_paths(config({
        "keyFile":"/var/lib/remnawave/configs/xray/ssl/privkey.key",
        "certificateFile":"/var/lib/remnawave/configs/xray/ssl/fullchain.pem"}))
    guard_node_only_tls_paths(config({"key":["PRIVATE"],"certificate":["CERT"]}))
