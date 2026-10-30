import getpass
import re
import sys
from argon2 import PasswordHasher
from .store import init_db, connect


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ('init', 'set-password'):
        print('Usage: python -m manager.cli init | set-password')
        return 2
    init_db()
    with connect() as c:
        present = bool(c.execute('SELECT 1 FROM admins LIMIT 1').fetchone())
    if sys.argv[1] == 'init' and present:
        print('Admin exists. Use set-password to change login credentials.')
        return 1
    if sys.argv[1] == 'set-password' and not present:
        print('Run init first.')
        return 1
    name = input('Admin username [admin]: ').strip() or 'admin'
    if not re.fullmatch(r'[A-Za-z0-9_.-]{3,40}', name):
        print('Invalid username (3-40 latin letters, digits, dot, underscore, hyphen).')
        return 1
    pwd = getpass.getpass('New admin password (16+ characters): ')
    again = getpass.getpass('Repeat password: ')
    if len(pwd) < 16 or pwd != again:
        print('Password too short or mismatch')
        return 1
    with connect() as c:
        if present:
            c.execute('UPDATE admins SET username=?,password_hash=?', (name,PasswordHasher().hash(pwd)))
        else:
            c.execute('INSERT INTO admins(username,password_hash,totp_secret) VALUES(?,?,?)', (name,PasswordHasher().hash(pwd),''))
    print('Login configured. 2FA is disabled for testing.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
