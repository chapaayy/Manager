import os
import tempfile
import unittest
from pathlib import Path
from cryptography.fernet import Fernet

tmp=tempfile.TemporaryDirectory()
os.environ['XPPN_DB']=str(Path(tmp.name)/'manager.db')
os.environ['XPPN_DATA_KEY']=Fernet.generate_key().decode()
from manager import store

class StoreTests(unittest.TestCase):
    def setUp(self):
        store.init_db()
        with store.connect() as db:
            db.execute('DELETE FROM jobs');db.execute('DELETE FROM nodes')
            db.execute('INSERT INTO nodes(id,name,ip,token_hash,signing_key_enc,ssh_fingerprint,created_at) VALUES(?,?,?,?,?,?,?)',
                       ('node1','test','1.1.1.1',store.hash_token('x'*40),store.FERNET.encrypt(('a'*64).encode()).decode(),'SHA256:key',1))
    def test_token_and_secret_encryption(self):
        self.assertTrue(store.auth_node('node1','x'*40))
        self.assertFalse(store.auth_node('node1','z'*40))
        store.queue_job('node1','job1','node.install',{'secret_key':'MYPRIVATEKEY'})
        with store.connect() as db:
            row=db.execute('SELECT * FROM jobs WHERE id=?',('job1',)).fetchone()
            self.assertNotIn('MYPRIVATEKEY',row['encrypted_payload'])
        job=store.take_job('node1')
        self.assertEqual(job['payload']['secret_key'],'MYPRIVATEKEY')
        self.assertEqual(len(job['signature']),64)
        self.assertEqual(job['signed']['command'],'node.install')
        self.assertIsNone(store.take_job('node1'))
        self.assertTrue(store.finish_job('node1','job1','success','okay'))
        with store.connect() as db:
            row=db.execute('SELECT * FROM jobs WHERE id=?',('job1',)).fetchone()
            self.assertEqual(row['encrypted_payload'],'')

if __name__=='__main__':unittest.main()
