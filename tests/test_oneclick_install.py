"""One-file install and admin bootstrap regression tests."""
import os
import tempfile
import unittest
from pathlib import Path
from cryptography.fernet import Fernet

os.environ.setdefault('XPPN_DATA_KEY', Fernet.generate_key().decode())
from manager import cli, store

ROOT=Path(__file__).resolve().parents[1]

class OneClickInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.old_db=store.DB
        self.old_user=os.environ.get('XPPN_ADMIN_USER')
        self.old_password=os.environ.get('XPPN_ADMIN_PASSWORD')
        store.DB=str(Path(self.tmp.name)/'data.db')
        os.environ['XPPN_ADMIN_USER']='myadmin'
        os.environ['XPPN_ADMIN_PASSWORD']='strong-unique-test-password-2026'

    def tearDown(self):
        store.DB=self.old_db
        self.tmp.cleanup()
        for k,v in [('XPPN_ADMIN_USER',self.old_user),('XPPN_ADMIN_PASSWORD',self.old_password)]:
            if v is None:os.environ.pop(k,None)
            else:os.environ[k]=v

    def test_creates_admin_with_argon2_hash(self):
        self.assertEqual(cli.provision_env(),0)
        with store.connect() as c:
            row=c.execute('SELECT username,password_hash FROM admins').fetchone()
        self.assertEqual(row['username'],'myadmin')
        self.assertNotIn('strong-unique',row['password_hash'])

    def test_existing_admin_and_hash_preserved_if_password_empty(self):
        self.assertEqual(cli.provision_env(),0)
        with store.connect() as c:
            before=c.execute('SELECT username,password_hash FROM admins').fetchone()
        os.environ['XPPN_ADMIN_PASSWORD']=''
        os.environ['XPPN_ADMIN_USER']='different-name'
        self.assertEqual(cli.provision_env(),0)
        with store.connect() as c:
            after=c.execute('SELECT username,password_hash FROM admins').fetchone()
        self.assertEqual(tuple(before),tuple(after))

    def test_missing_password_blocks_first_install(self):
        os.environ['XPPN_ADMIN_PASSWORD']=''
        self.assertEqual(cli.provision_env(),2)
        with store.connect() as c:
            self.assertEqual(c.execute('SELECT count(*) FROM admins').fetchone()[0],0)

    def test_weak_password_rejected(self):
        os.environ['XPPN_ADMIN_PASSWORD']='short'
        self.assertEqual(cli.provision_env(),2)

    def test_installer_never_deletes_docker_volumes(self):
        s=(ROOT/'install.sh').read_text()
        self.assertNotIn('docker compose down -v',s)
        self.assertNotIn('docker volume rm',s)
        self.assertLess(s.index('build manager'),s.index('stop manager'))

    def test_web_update_builds_before_stop(self):
        s=(ROOT/'deploy/update-worker.sh').read_text()
        self.assertLess(s.index('build manager'),s.index('stop manager\nSTOPPED=1'))
        self.assertIn('DOCKER_CONFIG',s)

if __name__ == '__main__':
    unittest.main()
