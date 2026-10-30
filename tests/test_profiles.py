import os
import tempfile
import unittest
from pathlib import Path
from cryptography.fernet import Fernet
os.environ.setdefault("XPPN_DATA_KEY",Fernet.generate_key().decode())
from manager import store

class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.old_db, self.old_fernet=store.DB,store.FERNET
        store.DB=str(Path(self.tmp.name)/'db.sqlite')
        store.FERNET=Fernet(Fernet.generate_key())
        store.init_db()

    def tearDown(self):
        store.DB,store.FERNET=self.old_db,self.old_fernet
        self.tmp.cleanup()

    def make_node(self,preset,payload=None):
        encrypted=store.FERNET.encrypt(__import__('json').dumps(payload).encode()).decode() if payload else ''
        with store.connect() as db:
            db.execute('INSERT INTO nodes(id,name,ip,preset,stage,pending_install_enc,token_hash,signing_key_enc,ssh_fingerprint,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',(
                'node1','test','1.1.1.1',preset,'waiting',encrypted,store.hash_token('x'*40),store.FERNET.encrypt(('a'*64).encode()).decode(),'SHA256:test',1))

    def test_agent_only_unlocks_on_heartbeat(self):
        self.make_node('agent')
        self.assertEqual(store.start_profile_if_ready('node1'),'ready')
        with store.connect() as c:
            self.assertEqual(c.execute("SELECT stage FROM nodes WHERE id='node1'").fetchone()['stage'],'ready')
            self.assertIsNone(c.execute('SELECT id FROM jobs').fetchone())

    def test_full_profile_queued_once_and_requires_healthy_containers(self):
        self.make_node('full',{'panel_ip':'1.1.1.1','secret_key':'MY_SECRET_DO_NOT_LOG','version':'3.4.2','domain':'node.example.org','confirm_clean':True})
        self.assertEqual(store.start_profile_if_ready('node1'),'provisioning')
        self.assertIsNone(store.start_profile_if_ready('node1'))
        with store.connect() as db:
            row=db.execute("SELECT pending_install_enc,install_job_id,stage FROM nodes WHERE id='node1'").fetchone()
            self.assertEqual(row['pending_install_enc'],'')
            self.assertEqual(row['stage'],'provisioning')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],1)
        job=store.take_job('node1')
        self.assertEqual(job['command'],'legacy.install')
        self.assertEqual(job['payload']['secret_key'],'MY_SECRET_DO_NOT_LOG')
        self.assertTrue(store.finish_job('node1',job['id'],'success','OK'))
        store.installation_job_result('node1',job['id'],True,'OK')
        store.verify_telemetry('node1',{'containers':[{'Names':'remnanode','State':'running'}]})
        with store.connect() as db:
            self.assertEqual(db.execute("SELECT stage FROM nodes WHERE id='node1'").fetchone()['stage'],'verifying')
        store.verify_telemetry('node1',{'containers':[{'Names':'remnanode','State':'running'},{'Names':'nginx','State':'running'}]})
        with store.connect() as db:
            self.assertEqual(db.execute("SELECT stage FROM nodes WHERE id='node1'").fetchone()['stage'],'ready')
        self.assertNotIn('MY_SECRET_DO_NOT_LOG',str(store.logs_since('node1',0)))

    def test_failed_agent_recovers_only_after_authenticated_telemetry(self):
        self.make_node('agent')
        with store.connect() as db:
            db.execute("UPDATE nodes SET stage='failed',error='Bootstrap exit code 1' WHERE id='node1'")
        self.assertFalse(store.recover_agent_if_healthy('node1',{}))
        with store.connect() as db:
            self.assertEqual(db.execute("SELECT stage FROM nodes WHERE id='node1'").fetchone()['stage'],'failed')
        self.assertTrue(store.recover_agent_if_healthy('node1',{'hostname':'test-vps'}))
        with store.connect() as db:
            node=db.execute("SELECT stage,error FROM nodes WHERE id='node1'").fetchone()
            self.assertEqual(node['stage'],'ready')
            self.assertEqual(node['error'],'')
        self.assertFalse(store.recover_agent_if_healthy('node1',{'hostname':'test-vps'}))

    def test_failed_node_preset_is_not_auto_recovered(self):
        self.make_node('node')
        with store.connect() as db:
            db.execute("UPDATE nodes SET stage='failed',error='partial install' WHERE id='node1'")
        self.assertFalse(store.recover_agent_if_healthy('node1',{'hostname':'test-vps'}))
        with store.connect() as db:
            self.assertEqual(db.execute("SELECT stage FROM nodes WHERE id='node1'").fetchone()['stage'],'failed')

    def test_failed_profile_does_not_unlock_buttons(self):
        self.make_node('node',{'panel_ip':'1.1.1.1','secret_key':'a'*50,'version':'3.4.2'})
        store.start_profile_if_ready('node1')
        job=store.take_job('node1')
        store.finish_job('node1',job['id'],'error','Error')
        store.installation_job_result('node1',job['id'],False,'Error')
        with store.connect() as db:
            self.assertEqual(db.execute("SELECT stage FROM nodes WHERE id='node1'").fetchone()['stage'],'failed')

    def test_install_logs_cursor(self):
        self.make_node('agent')
        store.log_install('node1','Connecting')
        e=store.logs_since('node1',0)
        self.assertEqual(len(e),1)
        self.assertEqual(e[0]['message'],'Connecting')
        store.log_install('node1','Installed')
        self.assertEqual(len(store.logs_since('node1',e[0]['id'])),1)

if __name__=='__main__':unittest.main()
