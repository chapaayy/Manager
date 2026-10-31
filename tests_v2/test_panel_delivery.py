"""Remote Remnawave cert receiver tests (no SSH/network or real secrets)."""
import hashlib
import pytest
from cryptography.fernet import Fernet
from v2 import panel_delivery, certificates, storage


@pytest.fixture
def db(tmp_path,monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"db.sqlite"))
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    storage.init_db()
    return tmp_path


def test_remote_mode_requires_enrollment_and_enable(db):
    with storage.transaction() as c:
        c.execute("UPDATE certificate_settings SET mode='remote',enabled=1")
    assert not certificates.enabled()
    assert not panel_delivery.available()
    with storage.transaction() as c:
        c.execute("""UPDATE certificate_settings SET remote_ip='1.1.1.1',remote_port=22,
                     remote_fingerprint=?,remote_key_enc=?""",
                  ("SHA256:"+"a"*43,storage.encrypt("test-ssh-key")))
    assert panel_delivery.available()
    assert certificates.enabled()


def test_cannot_enroll_without_explicit_consent(db):
    with pytest.raises(panel_delivery.DeliveryError,match="Подтверди"):
        panel_delivery.enroll("1.1.1.1",22,"SHA256:"+"a"*43,"password",False)
    with pytest.raises(ValueError,match="публичный"):
        panel_delivery.enroll("127.0.0.1",22,"SHA256:"+"a"*43,"password",True)


def test_remote_publish_requires_acknowledged_digest(db,monkeypatch):
    cert=b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"
    key=b"-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----\n"
    digest=hashlib.sha256(cert+key).hexdigest()
    with storage.transaction() as c:
        c.execute("""UPDATE certificate_settings SET mode='remote',enabled=1,
                     remote_ip='1.1.1.1',remote_port=22,remote_fingerprint=?,
                     remote_key_enc=?""",("SHA256:"+"a"*43,storage.encrypt("fake-key")))
    class Channel:
        def __init__(self): self.sent=b"";self.delivered=False
        def settimeout(self,n): pass
        def exec_command(self,command): assert command=="xppn-panel-certificate-delivery"
        def sendall(self,payload): self.sent+=payload
        def shutdown_write(self): pass
        def exit_status_ready(self): return True
        def recv_ready(self): return not self.delivered
        def recv(self,size): self.delivered=True;return ("OK "+digest).encode()
        def recv_stderr_ready(self): return False
        def recv_exit_status(self): return 0
        def close(self): pass
    class Transport:
        def __init__(self): self.channel=Channel()
        def open_session(self,timeout):return self.channel
        def close(self):pass
    t=Transport()
    monkeypatch.setattr(panel_delivery,"_connect",lambda *a:t)
    panel_delivery.deliver("RUS10","rus10.gowayot.com",cert,key)
    assert b"PRIVATE KEY" not in t.channel.sent  # base64 on the SSH channel, not plaintext
    assert b"rus10.gowayot.com" in t.channel.sent


def test_remote_panel_credentials_do_not_appear_in_status(db):
    with storage.transaction() as c:
        c.execute("""UPDATE certificate_settings SET mode='remote',enabled=1,
                     remote_ip='1.1.1.1',remote_fingerprint=?,remote_key_enc=?""",
                  ("SHA256:"+"a"*43,storage.encrypt("TEST_PRIVATE_PANEL_SSH_KEY")))
    status=certificates.status()
    assert status["mode"]=="remote"
    assert "TEST_PRIVATE_PANEL_SSH_KEY" not in str(status)
