"""Single-install admin bootstrap and optional local credential reset.

provision-env consumes credentials from protected .env, stores an Argon2 hash,
and never prints the password. Re-running without a password preserves admin.
"""
import getpass
import os
import re
import sys
from argon2 import PasswordHasher
from .store import init_db, connect


def provision_env():
    name = os.getenv('XPPN_ADMIN_USER', 'admin').strip() or 'admin'
    password = os.getenv('XPPN_ADMIN_PASSWORD', '')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{3,40}', name):
        print('Invalid XPPN_ADMIN_USER (3-40 latin letters, digits, dot, underscore, hyphen).', file=sys.stderr)
        return 2
    if password and len(password) < 16:
        print('XPPN_ADMIN_PASSWORD must contain at least 16 characters.', file=sys.stderr)
        return 2
    init_db()
    with connect() as c:
        row = c.execute('SELECT id,username FROM admins LIMIT 1').fetchone()
        if not row and not password:
            print('First installation: set XPPN_ADMIN_PASSWORD in .env.', file=sys.stderr)
            return 2
        if password:
            encoded = PasswordHasher().hash(password)
            if row:
                c.execute('UPDATE admins SET username=?, password_hash=? WHERE id=?', (name, encoded, row['id']))
                print('Admin credentials updated from .env.')
            else:
                c.execute('INSERT INTO admins(username,password_hash,totp_secret) VALUES(?,?,?)', (name, encoded, ''))
                print('Admin credentials initialized from .env.')
        else:
            print('Existing admin preserved (no new password requested).')
    return 0


def interactive_password(action):
    init_db()
    with connect() as c:
        present = bool(c.execute('SELECT 1 FROM admins LIMIT 1').fetchone())
    if action == 'init' and present:
        print('Admin exists. Change login/password in web settings.')
        return 1
    if action == 'set-password' and not present:
        print('Run the installer first.')
        return 1
    name = input('Admin username [admin]: ').strip() or 'admin'
    if not re.fullmatch(r'[A-Za-z0-9_.-]{3,40}', name):
        print('Invalid username.')
        return 1
    pwd = getpass.getpass('New admin password (16+ characters): ')
    again = getpass.getpass('Repeat password: ')
    if len(pwd) < 16 or pwd != again:
        print('Password too short or mismatch')
        return 1
    with connect() as c:
        if present:
            c.execute('UPDATE admins SET username=?,password_hash=?', (name, PasswordHasher().hash(pwd)))
        else:
            c.execute('INSERT INTO admins(username,password_hash,totp_secret) VALUES(?,?,?)',
                      (name, PasswordHasher().hash(pwd), ''))
    print('Login configured.')
    return 0


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ('provision-env', 'init', 'set-password'):
        print('Usage: python -m manager.cli provision-env | init | set-password')
        return 2
    if sys.argv[1] == 'provision-env':
        return provision_env()
    return interactive_password(sys.argv[1])


if __name__ == '__main__':
    raise SystemExit(main())
