"""Domain installer: credentials and existing Caddy integration without deployment."""
from pathlib import Path
import hashlib
import hmac

import pytest

from v2.setup_env import configure, SetupError, read_env
from v2.caddy_sites import candidate, START, END
from v2.app import _password_ok, _username


def test_new_domain_login_and_hash_only(tmp_path,monkeypatch):
    env=tmp_path / ".env.preview"
    result=configure(env,"admin.gowayot.com","xppnadmin","a long and unique passphrase here")
    assert result["domain"]=="admin.gowayot.com"
    assert result["username"]=="xppnadmin"
    raw=env.read_text()
    assert "a long and unique passphrase here" not in raw
    assert "XPPN_V2_ADMIN_PASSWORD=" not in raw
    assert "XPPN_V2_COOKIE_SECURE=1" in raw
    assert "XPPN_V2_ADMIN_PASSWORD_HASH=pbkdf2_sha256$600000$" in raw
    assert oct(env.stat().st_mode & 0o777)=="0o600"
    _, values=read_env(env)
    monkeypatch.setenv("XPPN_V2_ADMIN_PASSWORD_HASH",values["XPPN_V2_ADMIN_PASSWORD_HASH"])
    monkeypatch.setenv("XPPN_V2_ADMIN_USER",values["XPPN_V2_ADMIN_USER"])
    monkeypatch.delenv("XPPN_V2_ADMIN_PASSWORD",raising=False)
    assert _username()=="xppnadmin"
    assert _password_ok("a long and unique passphrase here")
    assert not _password_ok("different wrong password")


def test_upgrade_keeps_secrets_and_original_hash(tmp_path):
    env=tmp_path / ".env.preview"
    configure(env,"v2a.gowayot.com","admin","very long password of mine")
    _, one=read_env(env)
    configure(env,"v2b.gowayot.com","operator","")
    _, two=read_env(env)
    for field in ("XPPN_DATA_KEY","XPPN_V2_SESSION_SECRET","XPPN_V2_ADMIN_PASSWORD_HASH"):
        assert one[field]==two[field]
    assert two["XPPN_V2_ADMIN_USER"]=="operator"
    assert two["XPPN_V2_DOMAIN"]=="v2b.gowayot.com"
    assert not any(line.startswith("XPPN_V2_ADMIN_PASSWORD=") for line in env.read_text().splitlines())


def test_legacy_preview_plaintext_password_is_migrated(tmp_path):
    env=tmp_path / ".env.preview"
    env.write_text("XPPN_V2_ADMIN_PASSWORD=previous-preview-password-long-enough\n"
                   "XPPN_V2_SESSION_SECRET="+("z"*50)+"\n"
                   "XPPN_V2_DB=/data/xppn-v2.db\n")
    configure(env,"admin.gowayot.com","admin","")
    raw=env.read_text()
    assert "previous-preview-password-long-enough" not in raw
    assert "XPPN_V2_ADMIN_PASSWORD=previous-preview-password-long-enough" not in raw
    assert "XPPN_V2_ADMIN_PASSWORD_HASH=pbkdf2_sha256$" in raw


@pytest.mark.parametrize("bad",["127.0.0.1","localhost","http://panel.example.com","domain.local",
                               "example.com:80","test.example.com","-broken.org"])
def test_bad_domains_fail_without_writing_file(tmp_path,bad):
    path=tmp_path / ".env.preview"
    with pytest.raises(SetupError):
        configure(path,bad,"admin","long valid password for admin")
    assert not path.exists()


def test_caddy_replacement_is_idempotent_and_preserves_v1():
    original='''{$XPPN_DOMAIN} {
  reverse_proxy manager:8000
}
'''
    first=candidate(original,"v2.gowayot.com")
    assert first.count(START)==1 and first.count(END)==1
    assert "reverse_proxy manager:8000" in first
    assert "reverse_proxy manager-v2:8000" in first
    assert "v2.gowayot.com {" in first
    second=candidate(first,"new.gowayot.com")
    assert "v2.gowayot.com {" not in second
    assert "new.gowayot.com {" in second
    assert "reverse_proxy manager:8000" in second
    assert second.count(START)==1
    assert candidate(second,"new.gowayot.com")==second


def test_caddy_refuses_duplicate_or_corrupted_sites():
    original="admin.gowayot.com {\n reverse_proxy old:8000\n}\n"
    with pytest.raises(SetupError):
        candidate(original,"admin.gowayot.com")
    with pytest.raises(SetupError):
        candidate("v1.example.org {}\n"+START, "admin.gowayot.com")


def test_app_http_login_requires_correct_username(tmp_path,monkeypatch):
    from cryptography.fernet import Fernet
    from fastapi.testclient import TestClient
    from v2.app import app
    from v2 import storage
    env=tmp_path / ".env.preview"
    configure(env,"dashboard.gowayot.com","myoperator","a passphrase that passes all checks")
    _, values=read_env(env)
    for key,val in values.items():
        monkeypatch.setenv(key,val)
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"auth.db"))
    monkeypatch.setenv("XPPN_V2_COOKIE_SECURE","0") # TestClient on plain HTTP
    with TestClient(app) as c:
        wrong=c.post("/api/auth/login",json={"username":"wrong-user","password":"a passphrase that passes all checks"})
        assert wrong.status_code==401
        login=c.post("/api/auth/login",json={"username":"myoperator","password":"a passphrase that passes all checks"})
        assert login.status_code==200
        assert login.json()["csrf"]
        assert c.get("/api/dashboard").status_code==200
