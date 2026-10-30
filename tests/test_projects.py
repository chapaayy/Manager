"""New projects and transport catalog: live SQLite migration and secret isolation."""
import os
import tempfile
import unittest
from pathlib import Path
from cryptography.fernet import Fernet
os.environ.setdefault('XPPN_DATA_KEY', Fernet.generate_key().decode())
from manager import store, projects

class ProjectTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.old_db,self.old_fernet=store.DB,store.FERNET
        store.DB=str(Path(self.tmp.name)/'manager.db')
        store.FERNET=Fernet(Fernet.generate_key())
        store.init_db()

    def tearDown(self):
        store.DB,store.FERNET=self.old_db,self.old_fernet
        self.tmp.cleanup()

    def test_migration_reentrant_and_old_node_defaults(self):
        with store.connect() as c:
            c.execute('INSERT INTO nodes(id,name,ip,token_hash,ssh_fingerprint,created_at) VALUES(?,?,?,?,?,?)',('old','Old','8.8.8.8','x','SHA256:test',1))
        store.init_db()
        with store.connect() as c:
            r=c.execute('SELECT project_id,profile_snapshot FROM nodes WHERE id=?',('old',)).fetchone()
            self.assertEqual(r['project_id'],'default')
            self.assertEqual(r['profile_snapshot'],'{}')
            self.assertEqual(c.execute('SELECT COUNT(*) FROM deployment_profiles WHERE project_id=?',('default',)).fetchone()[0],7)

    def test_secrets_only_in_project_and_no_cross_project(self):
        p1=projects.create_project({'name':'VPN One','panel_url':'https://panel1.example.org','panel_ip':'1.1.1.1',
            'secret_key':'EXAMPLE_BUT_NOT_REAL_SECRET','api_token':'EXAMPLE_TOKEN_123456'})
        p2=projects.create_project({'name':'VPN Two','panel_ip':'8.8.8.8','secret_key':'SECOND_DIFFERENT_KEY'})
        with store.connect() as c:
            r1=c.execute('SELECT * FROM projects WHERE id=?',(p1,)).fetchone()
            r2=c.execute('SELECT * FROM projects WHERE id=?',(p2,)).fetchone()
            fs=c.execute('SELECT * FROM deployment_profiles WHERE project_id=?',(p1,)).fetchall()
        safe=projects.project_view(r1)
        self.assertTrue(safe['has_api_token'])
        self.assertNotIn('secret_key_enc',safe)
        self.assertNotIn('EXAMPLE_TOKEN',str(safe))
        self.assertNotIn('EXAMPLE_BUT_NOT_REAL_SECRET',str(dict(r1)))
        self.assertEqual(projects.project_secret(p1)['secret_key'],'EXAMPLE_BUT_NOT_REAL_SECRET')
        self.assertNotEqual(projects.project_secret(p2)['secret_key'],projects.project_secret(p1)['secret_key'])
        self.assertEqual(len(fs),7)
        projects.update_project(p1,{'name':'VPN One','secret_key':'','api_token':'','panel_ip':'1.0.0.1'})
        self.assertEqual(projects.project_secret(p1)['secret_key'],'EXAMPLE_BUT_NOT_REAL_SECRET')
        self.assertEqual(projects.project_secret(p1)['panel_ip'],'1.0.0.1')

    def test_profile_updates_dont_mutate_snapshots(self):
        p=projects.create_project({'name':'New VPN'})
        profile_id=projects.add_profile(p,{'name':'Test Hysteria','mode':'node','transport':'hysteria2','settings':{'port':8443,'udp_idle_timeout':65}})
        with store.connect() as c:
            row=c.execute('SELECT * FROM deployment_profiles WHERE id=?',(profile_id,)).fetchone()
        snapshot=projects.profile_view(row)
        preview=projects.profile_preview(snapshot,'nl1.example.org')
        self.assertEqual(preview['inbound']['protocol'],'hysteria')
        self.assertEqual(preview['inbound']['streamSettings']['hysteriaSettings']['version'],2)
        self.assertFalse(preview['applies_automatically'])
        projects.update_profile(profile_id,{'name':'Test Hysteria','mode':'node','transport':'hysteria2','settings':{'port':443}})
        with store.connect() as c:
            new=projects.profile_view(c.execute('SELECT * FROM deployment_profiles WHERE id=?',(profile_id,)).fetchone())
        self.assertEqual(new['revision'],2)
        self.assertEqual(snapshot['revision'],1)
        self.assertEqual(snapshot['settings']['port'],8443)

    def test_invalid_configs_are_rejected(self):
        for value in [
            {'name':'Wrong','mode':'full','transport':'hysteria2'},
            {'name':'Wrong','mode':'agent','transport':'tls-raw'},
            {'name':'Wrong','mode':'node','transport':'hysteria2','settings':{'port':70000}},
            {'name':'Wrong','mode':'node','transport':'xhttp-tls','settings':{'xhttp_path':'/ok; rm -rf /'}},
            {'name':'Wrong','mode':'node','transport':'hysteria2','settings':{'bbr':'yes'}},
            {'name':'Wrong','mode':'node','transport':'hysteria2','settings':{'udp_idle_timeout':'60'}},
            {'name':'Wrong','mode':'node','transport':'hysteria2','settings':{'custom_script':'rm -rf /'}},
        ]:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):projects.validate_profile(value)
        with self.assertRaises(ValueError):projects.create_project({'name':'Oops','panel_ip':'127.0.0.1'})

if __name__=='__main__':unittest.main()
