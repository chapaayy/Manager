import os
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from cryptography.fernet import Fernet
os.environ.setdefault('XPPN_DATA_KEY',Fernet.generate_key().decode())
from manager import store, projects, remna_api

class PanelAPITests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.old_db,self.old_fernet=store.DB,store.FERNET
        store.DB=str(Path(self.temp.name)/'data.db');store.FERNET=Fernet(Fernet.generate_key());store.init_db()
        self.pid=projects.create_project({'name':'panel','panel_url':'https://panel.example.com','panel_ip':'8.8.8.8','api_token':'very_secret_api_token_dont_log'})
    def tearDown(self):
        store.DB,store.FERNET=self.old_db,self.old_fernet;self.temp.cleanup()
    def test_remnawave_registration_uses_matching_profile_only(self):
        profiles={'response':{'configProfiles':[{'uuid':'profile-123','name':'main','inbounds':[{'uuid':'inbound-1','tag':'XHTTP'},{'uuid':'inbound-2','tag':'HY2'}]}]}}
        calls=[]
        def fake_request(pid,method,path,body=None):
            calls.append((pid,method,path,body))
            if path=='/api/config-profiles':return profiles
            if method=='GET':return {'response':[]}
            if method=='POST':return {'response':{'uuid':'created-new-node'}}
            self.fail('Unexpected request')
        with patch.object(remna_api,'request',fake_request):
            uid=remna_api.register_node(self.pid,'NL1','nl1.example.org','NL','profile-123',['inbound-2'])
            self.assertEqual(uid,'created-new-node')
            self.assertEqual(calls[-1][3]['configProfile']['activeInbounds'],['inbound-2'])
            self.assertEqual(calls[-1][3]['port'],2222)
            with self.assertRaises(remna_api.PanelError):remna_api.register_node(self.pid,'NL1','nl1.example.org','NL','profile-123',['not-in-profile'])
    def test_does_not_overwrite_existing_remnawave_node(self):
        def fake(pid,method,path,body=None):
            if path=='/api/config-profiles':return {'response':{'configProfiles':[{'uuid':'p','name':'p','inbounds':[{'uuid':'i','tag':'a'}]}]}}
            if method=='GET':return {'response':[{'uuid':'old','name':'NL1','address':'nl1.example.org'}]}
            self.fail('Must not POST duplicate')
        with patch.object(remna_api,'request',fake):
            with self.assertRaises(remna_api.PanelError):remna_api.register_node(self.pid,'NL1','nl1.example.org','NL','p',['i'])
    def test_ssrf_checks_and_only_get_post_allowlisted(self):
        with self.assertRaises(remna_api.PanelError):remna_api._target('http://127.0.0.1')
        with patch.object(remna_api.socket,'getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',443))]):
            with self.assertRaises(remna_api.PanelError):remna_api._target('https://panel.example.com')
        with self.assertRaises(remna_api.PanelError):remna_api.request(self.pid,'PATCH','/api/nodes')

if __name__=='__main__':unittest.main()
