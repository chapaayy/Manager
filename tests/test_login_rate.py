"""Regression test: valid logins may never exhaust the failure-only rate limit."""
import ast
import os
import tempfile
import types
import unittest
from pathlib import Path
from cryptography.fernet import Fernet
from fastapi import HTTPException

os.environ.setdefault('XPPN_DATA_KEY', Fernet.generate_key().decode())
from manager import store

FUNCTIONS = {'login_failure_key', 'check_login_failures', 'record_login_failure', 'clear_login_failures', 'login'}
src = Path(__file__).resolve().parents[1] / 'manager' / 'app.py'
module = ast.parse(src.read_text())
functions = [f for f in module.body if isinstance(f, ast.FunctionDef) and f.name in FUNCTIONS]
for f in functions:
    f.decorator_list = []
namespace = {'Login': object, 'Request': object, 'store': store, 'time': __import__('time'), 'HTTPException': HTTPException,
             'secrets': __import__('secrets'), 'ph': types.SimpleNamespace(verify=lambda encoded, entered: entered == 'pw'),
             
             'argon_exc': types.SimpleNamespace(VerifyMismatchError=ValueError, InvalidHashError=TypeError)}
exec(compile(ast.Module(body=functions, type_ignores=[]), str(src), 'exec'), namespace)

class LoginRateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.original_db = store.DB
        store.DB = str(Path(self.tmp.name) / 'test.db')
        store.init_db()
        with store.connect() as db:
            db.execute('INSERT INTO admins(password_hash,totp_secret) VALUES(?,?)', ('hash', 'secret'))
        self.request = types.SimpleNamespace(client=types.SimpleNamespace(host='172.18.0.3'), session={})
        self.good = types.SimpleNamespace(username='admin',password='pw')
        self.bad = types.SimpleNamespace(username='admin',password='bad')
        self.login = namespace['login']
        self.key = namespace['login_failure_key']('172.18.0.3')

    def tearDown(self):
        store.DB = self.original_db
        self.tmp.cleanup()

    def count(self):
        with store.connect() as db:
            return db.execute('SELECT COUNT(*) FROM attempts WHERE ip=?', (self.key,)).fetchone()[0]

    def test_repeated_valid_logins_never_lock_out(self):
        for _ in range(18):
            self.assertTrue(self.login(self.good, self.request)['ok'])
        self.assertEqual(self.count(), 0)

    def test_only_failures_count_and_success_clears(self):
        for _ in range(9):
            with self.assertRaises(HTTPException) as err:
                self.login(self.bad, self.request)
            self.assertEqual(err.exception.status_code, 401)
        self.assertEqual(self.count(), 9)
        self.login(self.good, self.request)
        self.assertEqual(self.count(), 0)

    def test_ten_failures_trigger_429_with_retry_after(self):
        for _ in range(10):
            with self.assertRaises(HTTPException) as err:
                self.login(self.bad, self.request)
            self.assertEqual(err.exception.status_code, 401)
        with self.assertRaises(HTTPException) as err:
            self.login(self.good, self.request)
        self.assertEqual(err.exception.status_code, 429)
        self.assertGreater(int(err.exception.headers['Retry-After']), 0)

    def test_old_version_counters_ignored(self):
        with store.connect() as db:
            for _ in range(20):
                db.execute("INSERT INTO attempts VALUES(?, strftime('%s','now'))", ('login:172.18.0.3',))
        self.assertTrue(self.login(self.good, self.request)['ok'])

if __name__=='__main__': unittest.main()
