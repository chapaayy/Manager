"""Regression tests: incorrect passwords never trigger a manager login lockout."""
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

src = Path(__file__).resolve().parents[1] / 'manager' / 'app.py'
module = ast.parse(src.read_text())
functions = [f for f in module.body if isinstance(f, ast.FunctionDef) and f.name == 'login']
assert len(functions) == 1
for f in functions:
    f.decorator_list = []
namespace = {
    'Login': object,
    'Request': object,
    'store': store,
    'HTTPException': HTTPException,
    'secrets': __import__('secrets'),
    'ph': types.SimpleNamespace(verify=lambda encoded, entered: entered == 'pw'),
    'argon_exc': types.SimpleNamespace(VerifyMismatchError=ValueError, InvalidHashError=TypeError),
}
exec(compile(ast.Module(body=functions, type_ignores=[]), str(src), 'exec'), namespace)

class LoginWithoutLockoutTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.original_db = store.DB
        store.DB = str(Path(self.tmp.name) / 'test.db')
        store.init_db()
        with store.connect() as db:
            db.execute('INSERT INTO admins(password_hash,totp_secret) VALUES(?,?)', ('hash', 'secret'))
        self.request = types.SimpleNamespace(client=types.SimpleNamespace(host='172.18.0.3'), session={})
        self.good = types.SimpleNamespace(username='admin', password='pw')
        self.bad = types.SimpleNamespace(username='admin', password='bad')
        self.login = namespace['login']

    def tearDown(self):
        store.DB = self.original_db
        self.tmp.cleanup()

    def test_many_incorrect_passwords_do_not_lock_out(self):
        for _ in range(35):
            with self.assertRaises(HTTPException) as error:
                self.login(self.bad, self.request)
            self.assertEqual(error.exception.status_code, 401)
        self.assertTrue(self.login(self.good, self.request)['ok'])

    def test_many_valid_logins_stay_successful(self):
        for _ in range(35):
            self.assertTrue(self.login(self.good, self.request)['ok'])

    def test_previous_failed_login_counters_do_not_block(self):
        with store.connect() as db:
            for prefix in ('login_fail:', 'login:'):
                for _ in range(50):
                    db.execute("INSERT INTO attempts VALUES(?, strftime('%s','now'))", (prefix + '172.18.0.3',))
        self.assertTrue(self.login(self.good, self.request)['ok'])

    def test_wrong_username_is_rejected_without_adding_attempts(self):
        bad_name = types.SimpleNamespace(username='wrong', password='pw')
        for _ in range(20):
            with self.assertRaises(HTTPException) as error:
                self.login(bad_name, self.request)
            self.assertEqual(error.exception.status_code, 401)
        with store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM attempts').fetchone()[0], 0)

if __name__ == '__main__':
    unittest.main()
