"""Web update button cannot accept commands, repos or paths; host updater has fixed scope."""
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from cryptography.fernet import Fernet
from v2 import storage, web_updates, host_updater
from v2.app import app


@pytest.fixture()
def installed_updater(tmp_path, monkeypatch):
    shared=tmp_path/"updater"
    shared.mkdir()
    monkeypatch.setattr(web_updates, "SHARED", shared)
    first="a"*40
    (shared/"status.json").write_text(json.dumps({
        "state":"idle","message":"Готово","installed_sha":first,"updated_at":1
    }))
    return shared


def test_updater_button_requires_auth_and_csrf(tmp_path, installed_updater, monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB", str(tmp_path/"v2.db"))
    monkeypatch.setenv("XPPN_DATA_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("XPPN_V2_SESSION_SECRET","test_only_secret_please_never_use_in_prod_0123456789")
    monkeypatch.setenv("XPPN_V2_ADMIN_PASSWORD","test_admin_password_123456789")
    monkeypatch.delenv("XPPN_V2_ADMIN_PASSWORD_HASH",raising=False)
    monkeypatch.setenv("XPPN_V2_COOKIE_SECURE","0")
    with TestClient(app) as client:
        assert client.get("/api/system/update").status_code==401
        assert client.post("/api/system/update").status_code==401
        creds=client.post("/api/auth/login",json={"password":"test_admin_password_123456789"})
        assert creds.status_code==200
        assert client.post("/api/system/update").status_code==403
        client.headers["X-CSRF-Token"]=creds.json()["csrf"]
        status=client.get("/api/system/update").json()
        assert status["installed_sha"]=="a"*40
        assert status["enabled"] is True
        # POST ignores parameters: only the fixed empty marker is written.
        started=client.post("/api/system/update",json={
            "command":"rm -rf /", "branch":"some-other-branch"})
        assert started.status_code==200,started.text
        request=installed_updater/"request"
        assert request.is_file()
        assert request.read_bytes()==b""
        assert client.post("/api/system/update").status_code==409


def test_github_fixed_read_only_check(installed_updater, monkeypatch):
    class Response:
        status=200
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def read(self):return json.dumps([{"sha":"b"*40}]).encode()
    captured=[]
    def mock_open(req,timeout):
        captured.append((req.full_url,timeout))
        return Response()
    monkeypatch.setattr(web_updates.urllib.request,"urlopen",mock_open)
    result=web_updates.check_available()
    assert result["update_available"] is True
    assert result["latest_sha"]=="b"*40
    assert captured[0][0].startswith("https://api.github.com/repos/chapaayy/Manager/commits?")
    assert "sha=v2%2Frebuild-single-panel" in captured[0][0]


def test_disabled_when_not_bootstrapped(tmp_path,monkeypatch):
    shared=tmp_path/"empty"
    shared.mkdir()
    monkeypatch.setattr(web_updates,"SHARED",shared)
    assert web_updates.status()["enabled"] is False
    with pytest.raises(ValueError):
        web_updates.request_update()


def test_worker_performs_allowlisted_update_and_healthcheck(tmp_path,monkeypatch):
    state=tmp_path/"state";state.mkdir()
    appdir=tmp_path/"app";appdir.mkdir()
    (appdir/".git").mkdir()
    config=tmp_path/"mode.json"
    config.write_text(json.dumps({"mode":"public","network":""}))
    monkeypatch.setattr(host_updater,"STATE",state)
    monkeypatch.setattr(host_updater,"APP",appdir)
    monkeypatch.setattr(host_updater,"CONFIG",config)
    old="a"*40
    new="b"*40
    commands=[]
    def run(*args, timeout=150):
        commands.append(args)
        if args[:3]==("git","remote","get-url"):return host_updater.REPO
        if args[:3]==("git","branch","--show-current"):return host_updater.BRANCH
        if args[:3]==("git","status","--porcelain"):return ""
        if args[:2]==("git","rev-parse"):return new if args[2]=="FETCH_HEAD" else old
        return ""
    monkeypatch.setattr(host_updater,"call",run)
    monkeypatch.setattr(host_updater,"snapshot",lambda stamp:None)
    monkeypatch.setattr(host_updater,"restart",lambda:None)
    # No real git subprocess used by the worker in this test.
    class Completed: returncode=0
    monkeypatch.setattr(host_updater.subprocess,"run",lambda *a,**kw:Completed())
    host_updater.perform_update()
    status=json.loads((state/"status.json").read_text())
    assert status["state"]=="succeeded"
    assert status["installed_sha"]==new
    assert ("git","merge","--ff-only",new) in commands
    assert not any("rm" in part for command in commands for part in command)


def test_worker_rolls_back_bad_build(tmp_path,monkeypatch):
    state=tmp_path/"state";state.mkdir()
    appdir=tmp_path/"app";appdir.mkdir();(appdir/".git").mkdir()
    config=tmp_path/"mode.json";config.write_text('{"mode":"public"}')
    monkeypatch.setattr(host_updater,"STATE",state)
    monkeypatch.setattr(host_updater,"APP",appdir)
    monkeypatch.setattr(host_updater,"CONFIG",config)
    old="a"*40;new="b"*40
    commands=[]
    def fake_call(*args,timeout=150):
        commands.append(args)
        if args[:3]==("git","remote","get-url"):return host_updater.REPO
        if args[:3]==("git","branch","--show-current"):return host_updater.BRANCH
        if args[:3]==("git","status","--porcelain"):return ""
        if args[:2]==("git","rev-parse"):return new if args[2]=="FETCH_HEAD" else old
        return ""
    monkeypatch.setattr(host_updater,"call",fake_call)
    monkeypatch.setattr(host_updater,"snapshot",lambda _:None)
    class Completed: returncode=0
    monkeypatch.setattr(host_updater.subprocess,"run",lambda *a,**kw:Completed())
    started=[]
    def restart():
        started.append("restart")
        if len(started)==1:
            raise RuntimeError("health failed")
    monkeypatch.setattr(host_updater,"restart",restart)
    host_updater.perform_update()
    result=json.loads((state/"status.json").read_text())
    assert result["state"]=="failed"
    assert result["rolled_back"] is True
    assert ("git","reset","--hard",old) in commands
    assert len(started)==2
