"""Optional Telegram health alerts and daily SQLite snapshots.

No user-supplied shell commands, no alert token stored in the database.
"""
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
from . import store


def send_alert(message: str) -> bool:
    token=os.getenv('XPPN_ALERT_BOT_TOKEN','')
    chat=os.getenv('XPPN_ALERT_CHAT_ID','')
    if not token or not chat:
        return False
    data=urllib.parse.urlencode({'chat_id':chat,'text':message[:950]}).encode()
    url='https://api.telegram.org/bot'+token+'/sendMessage'
    with urllib.request.urlopen(urllib.request.Request(url,data=data,method='POST'),timeout=8) as resp:
        result=json.loads(resp.read(2048))
    return result.get('ok') is True


def check_nodes_once():
    if not (os.getenv('XPPN_ALERT_BOT_TOKEN') and os.getenv('XPPN_ALERT_CHAT_ID')):
        return
    now=int(time.time())
    with store.connect() as c:
        nodes=c.execute('SELECT id,name,stage,last_seen,telemetry FROM nodes').fetchall()
    for n in nodes:
        if n['stage'] not in ('ready','failed','registration_failed'):
            continue
        status='ok'
        if n['stage']!='ready':status='failed'
        elif n['last_seen'] and now-n['last_seen']>120:status='offline'
        elif n['last_seen']:
            try:
                disk=json.loads(n['telemetry']).get('disk',{})
                if disk.get('total') and disk.get('free',0)/disk['total']<0.1:status='disk_low'
            except (TypeError,ValueError,ZeroDivisionError):pass
        with store.connect() as c:
            old=c.execute('SELECT status FROM alert_states WHERE node_id=?',(n['id'],)).fetchone()
        if old and old['status']==status:continue
        if not old and status=='ok':
            with store.connect() as c:c.execute('INSERT OR IGNORE INTO alert_states VALUES(?,?,?)',(n['id'],'ok',now))
            continue
        msg={'offline':'🔴 Недоступна нода','failed':'❌ Ошибка ноды',
             'disk_low':'⚠️ На ноде меньше 10% диска','ok':'🟢 Нода восстановилась'}[status]
        try:
            if send_alert(f'XPPN: {msg}: {n["name"]}'):
                with store.connect() as c:
                    c.execute('INSERT INTO alert_states(node_id,status,updated_at) VALUES(?,?,?) '
                              'ON CONFLICT(node_id) DO UPDATE SET status=excluded.status,updated_at=excluded.updated_at',
                              (n['id'],status,now))
        except Exception:
            # No bot token, URL or other secret logged.
            pass


def backup_sqlite_once(force=False):
    dest=Path('/data/backups')
    dest.mkdir(mode=0o700,parents=True,exist_ok=True)
    dest.chmod(0o700)
    today=time.strftime('%Y-%m-%d',time.gmtime())
    path=dest/('xppn-manager-'+(time.strftime('%Y-%m-%dT%H-%M-%SZ',time.gmtime()) if force else today)+'.sqlite3')
    if not path.exists():
        tmp=dest/('backup-'+today+'-'+str(os.getpid())+'-'+str(threading.get_ident())+'.tmp')
        with sqlite3.connect(store.DB,timeout=15) as source, sqlite3.connect(tmp) as copy:
            source.backup(copy)
        tmp.chmod(0o600)
        tmp.replace(path)
    for old in dest.glob('xppn-manager-*.sqlite3'):
        try:
            if old.is_file() and not old.is_symlink() and time.time()-old.stat().st_mtime>8*86400:
                old.unlink()
        except OSError:pass
    return path


def start_maintenance():
    def worker():
        last_backup=''
        while True:
            try:
                day=time.strftime('%Y-%m-%d',time.gmtime())
                if day!=last_backup:
                    backup_sqlite_once()
                    last_backup=day
                check_nodes_once()
                from .housekeeping import prune
                prune()
            except Exception:
                # Monitoring must not stop the API server on an optional task failure.
                pass
            time.sleep(65)
    threading.Thread(target=worker,name='xppn-maintenance',daemon=True).start()
