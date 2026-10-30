"""Component inventory and command gating tests; no live VPS access."""
import json
import time
import pytest
from fastapi import HTTPException
from manager import app

def test_agent_only_has_no_fake_components():
    telemetry={'hostname':'test','containers':[{'Names':'xppn-agent','State':'running'}],
               'files':{'node_compose':False,'nginx_compose':False,'nginx':False}}
    inv=app.component_inventory(telemetry)
    assert inv['agent']['running']
    assert not inv['nginx']['installed']
    assert not inv['remnanode']['installed']
    assert not inv['configs']['node_compose']

def test_host_commands_for_absent_services_are_rejected():
    row={'telemetry':json.dumps({'hostname':'test','containers':[{'Names':'xppn-agent','State':'running'}],
        'files':{'nginx':False,'node_compose':False,'nginx_compose':False},'capabilities':['network.status']}),
        'last_seen':int(time.time())}
    for command,payload in [('docker.action',{'container':'remnanode'}),
                            ('docker.logs',{'container':'nginx'}),
                            ('node.upgrade',{'version':'3.4.2'}),
                            ('node.deploy',{}),
                            ('config.read',{'name':'nginx'}),
                            ('ssl.renew',{})]:
        with pytest.raises(HTTPException) as ex:app.require_component_command(command,payload,row)
        assert ex.value.status_code==409
    assert app.require_component_command('node.install',{'version':'3.4.2'},row)['agent']['running']

def test_running_node_can_be_operated_on_but_not_reinstalled():
    row={'last_seen':int(time.time()),'telemetry':json.dumps({'hostname':'test',
       'files':{'node_compose':True},
       'containers':[{'Names':'remnanode','State':'running','Image':'remnawave/node:3.4.2'}]})}
    assert app.require_component_command('docker.logs',{'container':'remnanode'},row)['remnanode']['running']
    with pytest.raises(HTTPException):app.require_component_command('node.install',{},row)
    with pytest.raises(HTTPException):app.require_component_command('legacy.install',{},row)

def test_old_helper_network_command_blocked_until_upgraded():
    row={'last_seen':int(time.time()),'telemetry':json.dumps({'hostname':'test','files':{},'containers':[]})}
    with pytest.raises(HTTPException) as ex:
        app.require_component_command('network.status',{},row)
    assert ex.value.status_code==409

def test_full_stack_needs_explicit_project_tls_template():
    app.validate_job('project.stack.install',{
        'version':'3.4.2','domain':'de.example.com','confirm_clean':True,'profile_id':'default-tls'})
    with pytest.raises(HTTPException):
        app.validate_job('project.stack.install',{
            'version':'3.4.2','domain':'de.example.com','confirm_clean':True})
