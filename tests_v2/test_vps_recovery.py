"""Regression coverage for recovery of a partially installed VPS (no live SSH/API)."""
import pytest
from cryptography.fernet import Fernet
from v2 import storage, vps_install
from v2.template_engine import Endpoint


@pytest.fixture
def failed_job(tmp_path, monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB", str(tmp_path / "recovery.db"))
    monkeypatch.setenv("XPPN_DATA_KEY", Fernet.generate_key().decode())
    storage.init_db()
    node = storage.create_node(code="RUS10", name="RUS10", country="RU",
                               domain="rus10.gowayot.com", role="regular")
    storage.create_install_job(node["id"], "1.1.1.1", 22, "SHA256:" + "a"*43)
    storage.set_install_status(node["id"], "failed", "Remnawave вернула HTTP 400")
    return node


def test_forget_only_failed_record_and_never_remote(failed_job):
    result = storage.delete_failed_install(failed_job["id"])
    assert result["deleted"] is True
    assert result["remote_untouched"] is True
    assert storage.list_nodes() == []
    with storage.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM node_installations").fetchone()[0] == 0


def test_cannot_delete_queued_installation(failed_job):
    storage.queue_resume_install(failed_job["id"])
    with pytest.raises(ValueError, match="завершённые"):
        storage.delete_failed_install(failed_job["id"])
    assert storage.get_install_job(failed_job["id"])["stage"] == "queued"


def test_cannot_delete_registered_or_linked_nodes(failed_job):
    storage.set_install_status(failed_job["id"], "failed", "Error",
                               remote_uuid="remnawave-registration-id")
    with pytest.raises(ValueError, match="зарегистрирована"):
        storage.delete_failed_install(failed_job["id"])


def test_atomic_resume_does_not_allow_concurrent_second_job(failed_job):
    queued = storage.queue_resume_install(failed_job["id"])
    assert queued["stage"] == "queued"
    assert storage.get_node(failed_job["id"])["status"] == "queued"
    with pytest.raises(ValueError, match="после ошибки"):
        storage.queue_resume_install(failed_job["id"])


def test_resume_uses_same_ip_and_fingerprint_without_reinstall(failed_job, monkeypatch):
    observed = {}
    class DummyTransport:
        def close(self): observed["closed"] = True
    def fake_ssh(ip, port, password, fingerprint):
        observed["ssh"] = (ip,port,password,fingerprint)
        return DummyTransport(), fingerprint
    monkeypatch.setattr(vps_install,"ssh_open",fake_ssh)
    monkeypatch.setattr(vps_install,"verify_existing_install",
                        lambda transport, source: observed.setdefault("checked",source.domain))
    monkeypatch.setattr(vps_install.POOL,"submit",
                        lambda fn,*args: observed.setdefault("worker",(fn.__name__, args)))
    with pytest.raises(ValueError, match="Подтверди"):
        vps_install.start_resume(failed_job["id"], "test-root-password", False)
    result=vps_install.start_resume(failed_job["id"], "test-root-password", True)
    assert result["stage"]=="queued"
    assert observed["ssh"]==("1.1.1.1",22,"test-root-password","SHA256:"+"a"*43)
    assert observed["checked"]=="rus10.gowayot.com"
    assert observed["closed"]
    assert observed["worker"][0]=="resume_registration"
    assert storage.get_install_job(failed_job["id"])["stage"]=="queued"


def test_resume_rejects_missing_service_or_wrong_domain(monkeypatch):
    node=Endpoint("RUS10","rus10.gowayot.com","RU")
    monkeypatch.setattr(vps_install,"run_command",lambda *a,**k:"DOMAIN=someone.else.org\n")
    with pytest.raises(ValueError, match="Домен"):
        vps_install.verify_existing_install(object(),node)
    monkeypatch.setattr(vps_install,"run_command",
                        lambda *a,**k: (_ for _ in ()).throw(RuntimeError("remote failed")))
    with pytest.raises(ValueError, match="не подтверждены"):
        vps_install.verify_existing_install(object(),node)


def test_resume_cannot_repeat_create_profile_after_uncertain_creation(failed_job, monkeypatch):
    from v2 import remnawave
    monkeypatch.setattr(remnawave,"list_profiles",lambda:[{
        "name":"XPPN RUS10 RU VLESS TLS","uuid":"someone-profile","inbounds":[]}])
    monkeypatch.setattr(remnawave,"create_profile",
                        lambda *a,**kw: (_ for _ in ()).throw(AssertionError("Duplicate")))
    with pytest.raises(ValueError,match="уже существует профиль"):
        vps_install.complete_panel_registration(failed_job["id"],
            Endpoint("RUS10","rus10.gowayot.com","RU"))


def test_successful_panel_resume_persists_profile_and_remote_id(failed_job,monkeypatch):
    from v2 import remnawave
    source=Endpoint("RUS10","rus10.gowayot.com","RU")
    monkeypatch.setattr(remnawave,"list_profiles",lambda:[])
    monkeypatch.setattr(vps_install,"xray_config",lambda *args:{"inbounds":[]})
    monkeypatch.setattr(remnawave,"create_profile",lambda *args:{
        "uuid":"profile-id",
        "inbounds":[{"uuid":"inbound-id","tag":"RUS10_VLESS_TLS_IN"}]})
    monkeypatch.setattr(remnawave,"register_node",lambda *args:"remote-node-id")
    monkeypatch.setattr(remnawave,"node_health",
        lambda *args:{"connected":True,"xray_running":True,"xray_version":"25.1"})
    vps_install.complete_panel_registration(failed_job["id"],source)
    job=storage.get_install_job(failed_job["id"])
    assert job["stage"]=="ready"
    assert job["profile_uuid"]=="profile-id"
    assert job["remote_uuid"]=="remote-node-id"


def test_partial_resume_cannot_delete_working_node(failed_job):
    storage.set_install_status(failed_job["id"], "ready", "Xray online",
                               remote_uuid="remnawave-node")
    with pytest.raises(ValueError):
        storage.delete_failed_install(failed_job["id"])


def test_new_xray_profile_name_has_only_remnawave_allowed_characters():
    import re
    source=Endpoint("RUS10","rus10.gowayot.com","RU")
    expected="XPPN RUS10 RU VLESS TLS"
    assert vps_install.config_profile_name(source)==expected
    assert vps_install.preview_plan(source)["name"]==expected
    assert re.fullmatch(r"[A-Za-z0-9_ -]+",expected)


@pytest.mark.parametrize("invalid",[
    "XPPN RUS10 · RU · VLESS TLS",
    "XPPN RUS10 / RU",
    "XPPN RUS10 🇷🇺",
    "XPPN RUS10\\nRU",
])
def test_remnawave_rejects_invalid_profile_name_before_api(invalid,monkeypatch):
    from v2 import remnawave
    def forbidden(*args,**kwargs):
        raise AssertionError("API was called with invalid profile name")
    monkeypatch.setattr(remnawave,"request",forbidden)
    with pytest.raises(remnawave.PanelError,match="Название профиля"):
        remnawave.create_profile(invalid,{"inbounds":[]})


def test_remnawave_accepts_valid_profile_name(monkeypatch):
    from v2 import remnawave
    expected="XPPN RUS10 RU VLESS TLS"
    def fake_request(method,path,body):
        assert (method,path)==("POST","/api/config-profiles")
        assert body["name"]==expected
        return {"response":{"uuid":"profile-uuid"}}
    monkeypatch.setattr(remnawave,"request",fake_request)
    monkeypatch.setattr(remnawave,"list_profiles",
                        lambda:[{"uuid":"profile-uuid","name":expected,"inbounds":[]}])
    result=remnawave.create_profile(expected,{"inbounds":[]})
    assert result["uuid"]=="profile-uuid"
