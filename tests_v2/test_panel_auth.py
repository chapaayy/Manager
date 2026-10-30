"""Remnawave + optional Caddy Auth Portal: real API headers, migration and safe 401 UX."""
import json
import sqlite3

import pytest
from cryptography.fernet import Fernet

from v2 import remnawave, storage


@pytest.fixture
def panel_db(tmp_path, monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB", str(tmp_path / "single.sqlite"))
    monkeypatch.setenv("XPPN_DATA_KEY", Fernet.generate_key().decode())
    storage.init_db()
    return tmp_path


def test_existing_v2_database_gets_additional_auth_without_reset(tmp_path, monkeypatch):
    path = tmp_path / "previous.db"
    monkeypatch.setenv("XPPN_V2_DB", str(path))
    monkeypatch.setenv("XPPN_DATA_KEY", Fernet.generate_key().decode())
    # Previous v2 schema lacked an optional Auth Portal API key.
    with sqlite3.connect(path) as db:
        db.execute("""CREATE TABLE panel (
          id INTEGER PRIMARY KEY CHECK(id=1),url TEXT NOT NULL DEFAULT '',
          outbound_ip TEXT NOT NULL DEFAULT '',token_enc TEXT NOT NULL DEFAULT '',
          config_profile_uuid TEXT NOT NULL DEFAULT '',
          inbound_uuids_json TEXT NOT NULL DEFAULT '[]',
          updated_at INTEGER NOT NULL DEFAULT 0)""")
        db.execute("INSERT INTO panel(id,url,token_enc) VALUES(1,?,?)", (
            "https://panel.guessway.com",storage.encrypt("remnawave-secret-token")))
    storage.init_db()
    assert storage.get_panel()["has_token"]
    assert not storage.get_panel()["has_caddy_api_key"]
    assert storage.get_panel_token() == "remnawave-secret-token"
    storage.set_panel(url="https://panel.guessway.com", caddy_api_key="caddy-portal-secret")
    assert storage.get_panel()["has_caddy_api_key"]
    assert storage.get_caddy_api_key() == "caddy-portal-secret"
    assert storage.get_panel_token() == "remnawave-secret-token"
    with storage.connect() as db:
        row = db.execute("SELECT token_enc,caddy_api_key_enc FROM panel").fetchone()
    assert "secret" not in row["token_enc"] and "secret" not in row["caddy_api_key_enc"]
    assert "caddy_api_key_enc" not in json.dumps(storage.get_panel())


def test_remnawave_requests_both_headers_without_revealing_values(panel_db,monkeypatch):
    storage.set_panel(url="https://panel.guessway.com",
                      token="sample-token-for-Remnawave",
                      caddy_api_key="secret-caddy-api-key")
    monkeypatch.setattr(remnawave.socket,"getaddrinfo",lambda host,port,**kwargs:[
        (2,1,6,"",("1.1.1.1",443))
    ])
    calls=[]
    class Connection:
        def __init__(self,hostname,ip):
            assert hostname=="panel.guessway.com"
        def request(self,method,path,headers):
            calls.append((method,path,headers))
        def getresponse(self):
            return type("Resp",(),{"status":200,"read":lambda self,n:b'{"response":{}}'})()
        def close(self):
            pass
    monkeypatch.setattr(remnawave,"PinnedHTTPS",Connection)
    assert remnawave.request("GET","/api/config-profiles")=={"response":{}}
    assert calls[0][2]["Authorization"]=="Bearer sample-token-for-Remnawave"
    assert calls[0][2]["X-Api-Key"]=="secret-caddy-api-key"
    assert "sample-token-for-Remnawave" not in json.dumps(storage.get_panel())


@pytest.mark.parametrize("status", [401,403,302])
def test_errors_identify_endpoint_and_never_expose_secrets(panel_db,monkeypatch,status):
    storage.set_panel(url="https://panel.guessway.com",
                      token="sensitive-Remnawave-token",
                      caddy_api_key="sensitive-Caddy-key")
    monkeypatch.setattr(remnawave.socket,"getaddrinfo",lambda *a,**kw:[
        (2,1,6,"",("1.1.1.1",443))
    ])
    class Connection:
        def __init__(self,*args):pass
        def request(self,*args,**kwargs):pass
        def getresponse(self):
            return type("Resp",(),{"status":status})()
        def close(self):pass
    monkeypatch.setattr(remnawave,"PinnedHTTPS",Connection)
    with pytest.raises(remnawave.PanelError) as error:
        remnawave.request("GET","/api/config-profiles")
    assert str(status) in str(error.value)
    assert "/api/config-profiles" in str(error.value)
    assert "sensitive-" not in str(error.value)


def test_no_caddy_key_no_extra_header(panel_db, monkeypatch):
    storage.set_panel(url="https://panel.guessway.com",token="Bearer token-wrapped")
    monkeypatch.setattr(remnawave.socket,"getaddrinfo",lambda *a,**kw:[
        (2,1,6,"",("1.1.1.1",443))
    ])
    class Connection:
        def __init__(self,*args):pass
        def request(self,method,path,headers:dict):
            captured.update(headers)
        def getresponse(self):
            return type("Resp",(),{"status":200,"read":lambda self,n:b'{"response":{}}'})()
        def close(self):pass
    captured={}
    monkeypatch.setattr(remnawave,"PinnedHTTPS",Connection)
    remnawave.request("GET","/api/config-profiles")
    assert captured["Authorization"]=="Bearer token-wrapped"
    assert "X-Api-Key" not in captured
