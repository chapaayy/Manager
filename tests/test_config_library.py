"""Config library, encrypted storage, reusable multi-file presets and safe editing."""
import os
import tempfile
from pathlib import Path
from cryptography.fernet import Fernet
import pytest
from fastapi import HTTPException

os.environ.setdefault('XPPN_DATA_KEY',Fernet.generate_key().decode())
os.environ.setdefault('XPPN_SESSION_SECRET','tests-only-session-secret-1234567890abcdef')
from manager import app, store, config_library


def endpoint(url, method='GET'):
    return next(r.endpoint for r in app.app.routes
                if getattr(r,'path','')==url and method in getattr(r,'methods',set()))


@pytest.fixture
def state():
    with tempfile.TemporaryDirectory() as folder:
        old_db, old_fernet=store.DB, store.FERNET
        store.DB=str(Path(folder)/'test.db')
        store.FERNET=Fernet(Fernet.generate_key())
        store.init_db()
        try:
            yield
        finally:
            store.DB, store.FERNET=old_db, old_fernet


def make_file(kind='nginx',name='Fallback NL',content='server { listen 443; }'):
    return endpoint('/api/config-library','POST')(
        config_library.LibraryBody(name=name,kind=kind,content=content),True)


def test_can_create_encrypted_file_without_nodes(state):
    item=make_file(content='MY-SECRET-VALUE')
    assert item['revision']==1
    with store.connect() as c:
        stored=c.execute('SELECT content_enc FROM library_configs WHERE id=?',(item['id'],)).fetchone()['content_enc']
    assert 'MY-SECRET-VALUE' not in stored
    detail=endpoint('/api/config-library/{config_id}')(item['id'],True)
    assert detail['content']=='MY-SECRET-VALUE'
    all_files=endpoint('/api/config-library')(True)
    assert len(all_files)==1 and 'content' not in all_files[0]


def test_file_revision_conflict_protection(state):
    item=make_file()
    update=endpoint('/api/config-library/{config_id}','PUT')
    first=update(item['id'], config_library.LibraryBody(name='Fallback NL v2',kind='nginx',content='new',revision=1), True)
    assert first['revision']==2
    with pytest.raises(HTTPException) as error:
        update(item['id'],config_library.LibraryBody(name='Stale',kind='nginx',content='stale',revision=1),True)
    assert error.value.status_code==409
    with pytest.raises(HTTPException) as error:
        update(item['id'],config_library.LibraryBody(name='Wrong kind',kind='node_compose',content='x',revision=2),True)
    assert error.value.status_code==409


def test_bundles_files_and_preserves_config_on_preset_delete(state):
    nginx=make_file()
    compose=make_file(kind='node_compose',name='Remnawave compose',content='services: {}')
    preset=endpoint('/api/config-presets','POST')(
        config_library.PresetBody(name='NL production',config_ids=[nginx['id'],compose['id']]),True)
    assert {x['kind'] for x in preset['items']}=={'nginx','node_compose'}
    with pytest.raises(HTTPException) as err:
        endpoint('/api/config-library/{config_id}','DELETE')(nginx['id'],True)
    assert err.value.status_code==409
    assert endpoint('/api/config-presets','GET')(True)[0]['name']=='NL production'
    assert endpoint('/api/config-presets/{preset_id}','DELETE')(preset['id'],True)['ok']
    assert endpoint('/api/config-library/{config_id}','DELETE')(nginx['id'],True)['ok']
    assert endpoint('/api/config-library/{config_id}','GET')(compose['id'],True)['content']=='services: {}'


def test_rejects_same_type_twice_in_preset(state):
    a=make_file()
    b=make_file(name='Another nginx')
    with pytest.raises(HTTPException) as err:
        endpoint('/api/config-presets','POST')(
            config_library.PresetBody(name='Bad bundle',config_ids=[a['id'],b['id']]),True)
    assert err.value.status_code==422


def test_bundle_files_follow_explicit_library_revisions(state):
    nginx=make_file()
    preset=endpoint('/api/config-presets','POST')(
        config_library.PresetBody(name='NL',config_ids=[nginx['id']]),True)
    endpoint('/api/config-library/{config_id}','PUT')(
        nginx['id'],config_library.LibraryBody(name='Nginx after edit',kind='nginx',content='new',revision=1),True)
    updated=endpoint('/api/config-presets','GET')(True)[0]
    assert updated['id']==preset['id'] and updated['items'][0]['revision']==2
    assert updated['items'][0]['config_name']=='Nginx after edit'


def test_existing_node_management_route_is_preserved():
    assert endpoint('/api/nodes/{node_id}/configs/{name}','PUT')
    assert endpoint('/api/nodes/{node_id}/configs/{name}/apply','POST')
    for pattern in ('/api/config-library','/api/config-presets'):
        routes=[r for r in app.app.routes if getattr(r,'path','')==pattern]
        assert routes and all(r.dependant.dependencies for r in routes)
