"""Destructive node lifecycle regression tests. No external VPS or API access."""
import uuid

import pytest
from cryptography.fernet import Fernet

from v2 import storage,agent_transport,node_lifecycle,remnawave


@pytest.fixture
def setup(tmp_path,monkeypatch):
    monkeypatch.setenv("XPPN_V2_DB",str(tmp_path/"nodes.sqlite"))
    monkeypatch.setenv("XPPN_DATA_KEY",Fernet.generate_key().decode())
    storage.init_db()
    agent_transport.initialize()
    node_lifecycle.initialize()
    n=storage.create_node(code="RUS10",name="RUS10",domain="rus10.gowayot.com",
                          country="RU",role="regular")
    storage.create_install_job(n["id"],"1.1.1.1",22,"SHA256:"+"a"*43)
    remote_uuid=str(uuid.uuid4())
    profile_uuid=str(uuid.uuid4())
    storage.set_install_status(n["id"],"ready","connected",
                               remote_uuid=remote_uuid,profile_uuid=profile_uuid)
    token=agent_transport.issue_token(n["id"])
    agent_transport.heartbeat(n["id"],{"version":"1.1.0","metrics":{}})
    return n,remote_uuid,profile_uuid,token


def test_archive_and_restore_do_not_modify_server(setup):
    node,remote,profile,token=setup
    assert node_lifecycle.archive(node["id"],True)["archived"]
    rows=storage.list_nodes()
    assert rows[0]["archived"] == 1
    assert storage.get_install_job(node["id"])["remote_uuid"] == remote
    assert agent_transport.authenticate(node["id"],"Bearer "+token)
    assert not node_lifecycle.archive(node["id"],False)["archived"]


def test_forget_requires_exact_code_and_revokes_token_without_server_changes(setup,monkeypatch):
    node,remote,profile,token=setup
    monkeypatch.setattr(remnawave,"delete_node",lambda *_:pytest.fail("must not call API"))
    with pytest.raises(node_lifecycle.LifecycleError,match="точный код"):
        node_lifecycle.forget(node["id"],"RUS11")
    outcome=node_lifecycle.forget(node["id"],node["code"])
    assert outcome["server_deleted"] is False
    assert agent_transport.authenticate(node["id"],"Bearer "+token) is False
    with pytest.raises(LookupError):
        storage.get_node(node["id"])


def fake_remnawave(monkeypatch,remote,profile,other=None):
    rows=[{"uuid":remote,"configProfile":{"activeConfigProfileUuid":profile}}]
    if other is not None:
        rows.append({"uuid":str(uuid.uuid4()),"configProfile":{
            "activeConfigProfileUuid":other}})
    events=[]
    monkeypatch.setattr(remnawave,"request",lambda method,path,*_:{
        "response":list(rows)})
    monkeypatch.setattr(remnawave,"detailed_profile",lambda *_:{
        "name":"XPPN RUS10 RU VLESS TLS","config":{"inbounds":[]}})
    def remove_node(uid):
        events.append(("node",uid))
        rows[:]=[x for x in rows if x["uuid"]!=uid]
    monkeypatch.setattr(remnawave,"delete_node",remove_node)
    monkeypatch.setattr(remnawave,"delete_profile",lambda uid:events.append(("profile",uid)))
    return events,rows


def test_delete_remnawave_only_keeps_vps_and_agent(setup,monkeypatch):
    n,remote,profile,token=setup
    events,rows=fake_remnawave(monkeypatch,remote,profile,other=None)
    outcome=node_lifecycle.delete_remnawave(n["id"],n["code"],True)
    assert outcome["node_removed"] is True and outcome["profile_removed"] is True
    assert events==[("node",remote),("profile",profile)]
    assert storage.get_install_job(n["id"])["remote_uuid"]==""
    assert storage.get_install_job(n["id"])["profile_uuid"]==""
    assert agent_transport.authenticate(n["id"],"Bearer "+token)


def test_shared_profile_is_never_deleted(setup,monkeypatch):
    n,remote,profile,token=setup
    events,rows=fake_remnawave(monkeypatch,remote,profile,other=profile)
    with pytest.raises(node_lifecycle.LifecycleError,match="другой нодой"):
        node_lifecycle.delete_remnawave(n["id"],n["code"],True)
    assert events==[]
    assert storage.get_install_job(n["id"])["remote_uuid"]==remote


def test_unassigned_other_node_is_safe_for_deleting_owned_profile(setup,monkeypatch):
    n,remote,profile,_=setup
    events,rows=fake_remnawave(monkeypatch,remote,profile,other=None)
    rows.append({"uuid":str(uuid.uuid4()),
                 "configProfile":{"activeConfigProfileUuid":None}})
    outcome=node_lifecycle.delete_remnawave(n["id"],n["code"],True)
    assert outcome["profile_removed"] and events==[("node",remote),("profile",profile)]


def test_remnawave_profile_delete_failure_can_be_retried(setup,monkeypatch):
    n,remote,profile,token=setup
    events,rows=fake_remnawave(monkeypatch,remote,profile)
    calls=0
    def fail_once(uid):
        nonlocal calls
        calls+=1
        if calls==1:raise remnawave.PanelError("HTTP 503")
        events.append(("profile",uid))
    monkeypatch.setattr(remnawave,"delete_profile",fail_once)
    with pytest.raises(node_lifecycle.LifecycleError,match="не подтвердило"):
        node_lifecycle.delete_remnawave(n["id"],n["code"],True)
    assert storage.get_install_job(n["id"])["remote_uuid"]==""
    assert storage.get_install_job(n["id"])["profile_uuid"]==profile
    outcome=node_lifecycle.delete_remnawave(n["id"],n["code"],True)
    assert outcome["profile_removed"] and calls==2


def test_full_cleanup_is_staged_not_claimed_verified(setup,monkeypatch):
    n,remote,profile,token=setup
    events,rows=fake_remnawave(monkeypatch,remote,profile)
    begin=node_lifecycle.begin_full(n["id"],n["code"],True)
    assert begin["phase"]=="preparing"
    jid=begin["job_id"]
    with pytest.raises(agent_transport.AgentError,match="через мастер удаления"):
        agent_transport.enqueue(n["id"],"node.cleanup",{"domain":n["domain"]})
    with pytest.raises(agent_transport.AgentError,match="проходит удаление"):
        agent_transport.enqueue(n["id"],"docker.restart",{"name":"remnanode"})
    job=agent_transport.poll(n["id"])["job"]
    assert job["action"]=="node.cleanup" and job["id"]==jid
    assert job["payload"]=={"domain":n["domain"]}
    agent_transport.report(n["id"],{"id":jid,"ok":True,"result":{"cleaned":True,
        "node":n["domain"],"containers_removed":True,"agent_remains":True}})
    progress=node_lifecycle.advance_full(n["id"],n["code"])
    assert progress["phase"]=="finalizing"
    assert events==[("node",remote),("profile",profile)]
    final=agent_transport.poll(n["id"])["job"]
    assert final["action"]=="node.cleanup.finish"
    agent_transport.report(n["id"],{"id":final["id"],"ok":True,
                                  "result":{"scheduled":True,"verified_removed":False}})
    progress=node_lifecycle.advance_full(n["id"],n["code"])
    assert progress["phase"]=="finalize_ack"
    assert progress["shutdown_scheduled"] is True
    assert storage.get_node(n["id"])["code"]=="RUS10"
    assert node_lifecycle.forget(n["id"],n["code"])["deleted"]
    assert agent_transport.authenticate(n["id"],"Bearer "+token) is False


def test_cannot_full_delete_old_agent_without_update(setup):
    n,*_=setup
    with storage.transaction() as db:
        db.execute("UPDATE manager_agents SET version='1.0.0' WHERE node_id=?",(n["id"],))
    with pytest.raises(node_lifecycle.LifecycleError,match="1.1"):
        node_lifecycle.begin_full(n["id"],n["code"],True)


def test_pending_agent_tasks_block_full_cleanup(setup):
    n,*_=setup
    agent_transport.enqueue(n["id"],"docker.status")
    with pytest.raises(node_lifecycle.LifecycleError,match="незавершённые"):
        node_lifecycle.begin_full(n["id"],n["code"],True)


def test_bridge_dependencies_block_deletion(setup):
    n,*_=setup
    with storage.transaction() as db:
        db.execute("INSERT INTO bridges(id,name,entry_id,created_at) VALUES(?,?,?,?)",
                   (str(uuid.uuid4()),"test",n["id"],0))
    for fn in [lambda:node_lifecycle.forget(n["id"],n["code"]),
               lambda:node_lifecycle.begin_full(n["id"],n["code"],True)]:
        with pytest.raises(node_lifecycle.LifecycleError,match="мостом"):
            fn()


def test_cleanup_acknowledgement_for_wrong_vps_never_deletes_panel_node(setup,monkeypatch):
    n,remote,profile,_=setup
    monkeypatch.setattr(remnawave,"delete_node",lambda *_:pytest.fail("must not delete remote"))
    node_lifecycle.begin_full(n["id"],n["code"],True)
    job=agent_transport.poll(n["id"])["job"]
    agent_transport.report(n["id"],{"id":job["id"],"ok":True,"result":{
        "cleaned":True,"node":"other.example.org",
        "containers_removed":True,"agent_remains":True}})
    with pytest.raises(node_lifecycle.LifecycleError,match="нужной VPS"):
        node_lifecycle.advance_full(n["id"],n["code"])
    assert storage.get_install_job(n["id"])["remote_uuid"]==remote
    assert node_lifecycle.preview(n["id"])["phase"]=="preparing"
