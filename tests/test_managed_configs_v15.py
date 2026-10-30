"""Central config snapshots, encrypted version history, and safe application gates."""
import hashlib
import json
import tempfile
import time
import uuid
from pathlib import Path
from cryptography.fernet import Fernet
import pytest
from fastapi import HTTPException
from manager import app, store

@pytest.fixture
def manager_db():
    with tempfile.TemporaryDirectory() as folder:
        old_db,old_cipher=store.DB,store.FERNET
        store.DB=str(Path(folder)/'manager.sqlite')
        store.FERNET=Fernet(Fernet.generate_key())
        store.init_db()
        node=str(uuid.uuid4())
        with store.connect() as c:
            c.execute('''INSERT INTO nodes(id,name,ip,token_hash,signing_key_enc,ssh_fingerprint,stage,last_seen,
              telemetry,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)''',
              (node,'Test VPS','8.8.8.8','t',store.FERNET.encrypt(('ab'*32).encode()).decode(),
               'SHA256:test','ready',int(time.time()),json.dumps({'hostname':'test','files':{'nginx':True},
               'containers':[{'Names':'nginx','State':'running'}],'capabilities':['config.read','config.write']}),int(time.time())))
        try:yield node
        finally:store.DB,store.FERNET=old_db,old_cipher


def done(node,jid,output):
    job=store.take_job(node)
    assert job['id']==jid
    assert store.finish_job(node,jid,'success',output)
    app.reconcile_config_job(node,jid,True,output)


def test_import_then_edit_and_apply_without_remote_read(manager_db):
    node=manager_db; name='nginx'; initial='events {}\n'
    j=app.import_config(node,name,True)
    digest=hashlib.sha256(initial.encode()).hexdigest()
    done(node,j['id'],json.dumps({'content':initial,'sha256':digest,'name':name}))
    snap=app.stored_config(node,name,True)
    assert snap['content']==initial and snap['remote_sha']==digest
    assert snap['status']=='synced'
    with store.connect() as c:
        assert initial not in c.execute('SELECT content_enc FROM managed_configs WHERE node_id=?',(node,)).fetchone()['content_enc']
    modified='events { worker_connections 1024; }\n'
    saved=app.save_draft(node,name,app.DraftConfig(content=modified,revision=snap['revision']),True)
    assert saved['status']=='draft'
    with pytest.raises(HTTPException) as e:
        app.save_draft(node,name,app.DraftConfig(content='stale',revision=snap['revision']),True)
    assert e.value.status_code==409
    action=app.apply_draft(node,name,True)
    pending=store.take_job(node)
    assert pending['id']==action['id']
    assert pending['payload']=={'name':name,'content':modified,'sha256':digest}
    applied=hashlib.sha256(modified.encode()).hexdigest()
    assert store.finish_job(node,action['id'],'success',json.dumps({'sha256':applied}))
    app.reconcile_config_job(node,action['id'],True,json.dumps({'sha256':applied}))
    new=app.stored_config(node,name,True)
    assert new['status']=='synced' and new['remote_sha']==applied
    assert len(app.config_history(node,name,True))==2


def test_import_cannot_overwrite_unapplied_draft(manager_db):
    node=manager_db;initial='events {}\n'
    jid=app.import_config(node,'nginx',True)['id']
    done(node,jid,json.dumps({'content':initial,'sha256':hashlib.sha256(initial.encode()).hexdigest()}))
    snap=app.stored_config(node,'nginx',True)
    app.save_draft(node,'nginx',app.DraftConfig(content='events {x;}\n',revision=snap['revision']),True)
    with pytest.raises(HTTPException) as e:app.import_config(node,'nginx',True)
    assert e.value.status_code==409


def test_unknown_log_source_is_rejected():
    from agent import helper
    for source in ['../../etc/shadow','journal.ssh',None]:
        with pytest.raises(ValueError):helper.read_logs({'source':source,'lines':100})
    with pytest.raises(ValueError):helper.read_logs({'source':'xray.error','lines':99999})


def test_import_result_never_persists_config_plaintext(manager_db):
    node=manager_db
    content='server { secret_key SOME-PRIVATE-KEY; }\n'
    jid=app.import_config(node,'nginx',True)['id']
    assert store.take_job(node)['id']==jid
    response=app.result(node,app.AgentResult(job_id=jid,success=True,
              output=json.dumps({'content':content,'sha256':hashlib.sha256(content.encode()).hexdigest()})),None,True)
    with store.connect() as c:
        row=c.execute('SELECT output FROM jobs WHERE id=?',(jid,)).fetchone()
    assert content not in row['output']
    assert app.stored_config(node,'nginx',True)['content']==content


def test_batch_log_policy_queues_only_compatible_nodes(manager_db):
    node=manager_db
    with store.connect() as c:
        telemetry=json.loads(c.execute('SELECT telemetry FROM nodes WHERE id=?',(node,)).fetchone()['telemetry'])
        telemetry['capabilities'].append('logs.policy')
        c.execute('UPDATE nodes SET telemetry=? WHERE id=?',(json.dumps(telemetry),node))
    output=app.batch_log_policy(app.BatchPolicy(node_ids=[node],preset='standard'),True)
    assert output['results'][0]['status']=='queued'
    with store.connect() as c:
        assert c.execute('SELECT command FROM jobs WHERE id=?',(output['results'][0]['id'],)).fetchone()['command']=='logs.policy'
