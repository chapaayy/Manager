"""First VPS workflows: one primary panel, no hidden inbound prompts, read-only preflight."""
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from cryptography.fernet import Fernet
from fastapi import HTTPException
from starlette.requests import Request
import pytest
from manager import app, store, projects, remna_api, sshbootstrap

PROFILE='11111111-2222-4333-8444-555555555555'
INBOUND='aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
FP='SHA256:'+'A'*43


@pytest.fixture
def first_node(monkeypatch):
    with tempfile.TemporaryDirectory() as directory:
        old_db,old_fernet,old_hub=store.DB,store.FERNET,app.HUB_URL
        store.DB=str(Path(directory)/'first-node.db')
        store.FERNET=Fernet(Fernet.generate_key())
        store.init_db()
        app.HUB_URL='https://manager.example.com'
        monkeypatch.setattr(sshbootstrap,'check_credentials',lambda *a:True)
        dispatched=[]
        monkeypatch.setattr(app.executor,'submit',lambda *a: dispatched.append(a) or SimpleNamespace())
        try:yield dispatched
        finally:
            app.HUB_URL=old_hub
            store.DB,store.FERNET=old_db,old_fernet


def request():
    return Request({'type':'http','method':'POST','path':'/api/ssh/enroll',
                    'headers':[],'client':('127.0.0.1',40000),'scheme':'https','server':('localhost',443)})


def enrollment(mode,profile='',**overrides):
    return app.Enroll(ip='1.1.1.1',port=22,password='test_root',
        fingerprint=FP,name='NL1',preset=mode,profile_id=profile,**overrides)


def test_agent_only_works_before_remnawave_is_configured(first_node):
    result=app.ssh_enroll(enrollment('agent','default-agent'),request(),True)
    assert result['state']=='installing'
    assert len(first_node)==1
    with store.connect() as c:
        node=c.execute('SELECT preset,project_id,panel_auto_profile_uuid FROM nodes WHERE id=?',(result['id'],)).fetchone()
    assert node['preset']=='agent'
    assert node['project_id']=='default' and not node['panel_auto_profile_uuid']


@pytest.mark.parametrize('mode,profile', [('node','default-node'),('full','default-tls')])
def test_node_modes_require_panel_first_but_no_ssh_write(first_node,mode,profile):
    with pytest.raises(HTTPException) as error:
        app.ssh_enroll(enrollment(mode,profile,domain='nl1.example.com',confirm_clean=True),request(),True)
    assert error.value.status_code==422
    assert not first_node
    with store.connect() as c:
        assert c.execute('SELECT COUNT(*) FROM nodes').fetchone()[0]==0


def test_full_install_reuses_saved_panel_selection(first_node,monkeypatch):
    projects.update_project('default',{'name':'Основной проект','panel_url':'https://panel.example.com',
        'panel_ip':'8.8.8.8','api_token':'TEST_API_TOKEN_1234567890123456','secret_key':'A'*44})
    with store.connect() as c:
        c.execute('UPDATE projects SET panel_config_profile_uuid=?,panel_active_inbounds=? WHERE id=?',
                  (PROFILE,json.dumps([INBOUND]),'default'))
    monkeypatch.setattr(remna_api,'get_profiles',lambda _: [
        {'uuid':PROFILE,'name':'default','inbounds':[{'uuid':INBOUND,'protocol':'vless'}]}])
    result=app.ssh_enroll(enrollment('full','default-tls',domain='nl1.example.com',
         country_code='NL',confirm_clean=True),request(),True)
    assert result['state']=='installing' and len(first_node)==1
    with store.connect() as c:
        row=c.execute('SELECT panel_auto_profile_uuid,panel_auto_inbounds,pending_install_enc FROM nodes WHERE id=?',
                      (result['id'],)).fetchone()
    assert row['panel_auto_profile_uuid']==PROFILE
    assert json.loads(row['panel_auto_inbounds'])==[INBOUND]
    payload=json.loads(store.FERNET.decrypt(row['pending_install_enc'].encode()).decode())
    assert payload['panel_ip']=='8.8.8.8' and payload['version']=='3.4.2'
    assert payload['domain']=='nl1.example.com' and payload['confirm_clean']


def test_read_only_preflight_returns_warnings_and_never_starts_install(monkeypatch,first_node):
    class Future:
        def result(self,timeout):
            assert timeout==35
            return {'os':'ubuntu','arch':'x86_64','ports_in_use':[443],'warnings':['Occupied port 443'],'read_only':True}
    monkeypatch.setattr(app.executor,'submit',lambda *a:Future())
    result=app.ssh_preflight(app.ReadOnlyPreflight(ip='1.1.1.1',port=22,password='test',fingerprint=FP),request(),True)
    assert result['read_only'] and 443 in result['ports_in_use']
    with store.connect() as c:assert c.execute('SELECT COUNT(*) FROM nodes').fetchone()[0]==0


def test_profile_loader_follows_empty_list_into_detail_endpoint(monkeypatch):
    paths=[]
    def fake(pid,method,path,body=None):
        paths.append(path)
        if path=='/api/config-profiles':
            return {'response':{'configProfiles':[{'uuid':PROFILE,'name':'one','inbounds':[]}]}}
        if path.endswith('/inbounds'):
            return {'response':{'inbounds':[{'uuid':INBOUND,'tag':'VLESS TLS','protocol':'vless'}]}}
        raise AssertionError(path)
    monkeypatch.setattr(remna_api,'request',fake)
    profiles=remna_api.get_profiles('default')
    assert [x['uuid'] for x in profiles[0]['inbounds']]==[INBOUND]
    assert paths==['/api/config-profiles',f'/api/config-profiles/{PROFILE}/inbounds']
