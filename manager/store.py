"""SQLite storage and short-lived encrypted job payloads."""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from cryptography.fernet import Fernet

DB = os.getenv('XPPN_DB', '/data/xppn.db')
KEY = os.environ.get('XPPN_DATA_KEY', '')
if not KEY:
    raise RuntimeError('XPPN_DATA_KEY must be configured')
FERNET = Fernet(KEY.encode())

@contextmanager
def connect():
    c = sqlite3.connect(DB, timeout=20, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA busy_timeout=20000')
    c.execute('PRAGMA foreign_keys=ON')
    try:
        yield c
    finally:
        c.close()

def init_db():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    with connect() as c:
        c.execute('PRAGMA journal_mode=WAL')
        c.executescript('''
        CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY, password_hash TEXT NOT NULL, totp_secret TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS nodes(
          id TEXT PRIMARY KEY, name TEXT NOT NULL, ip TEXT NOT NULL,
          token_hash TEXT NOT NULL, signing_key_enc TEXT NOT NULL DEFAULT '', ssh_fingerprint TEXT NOT NULL,
          stage TEXT NOT NULL DEFAULT 'installing', last_seen INTEGER NOT NULL DEFAULT 0,
          telemetry TEXT NOT NULL DEFAULT '{}', created_at INTEGER NOT NULL,
          error TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS jobs(
          id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id),
          command TEXT NOT NULL, encrypted_payload TEXT NOT NULL,
          status TEXT NOT NULL, output TEXT NOT NULL DEFAULT '',
          created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_jobs_pending ON jobs(node_id,status,created_at);
        CREATE TABLE IF NOT EXISTS attempts(ip TEXT NOT NULL, ts INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(ts INTEGER NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS install_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,node_id TEXT NOT NULL,ts INTEGER NOT NULL,message TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_install_logs ON install_logs(node_id,id);
        CREATE TABLE IF NOT EXISTS managed_configs(
            node_id TEXT NOT NULL REFERENCES nodes(id), name TEXT NOT NULL,
            content_enc TEXT NOT NULL DEFAULT '', remote_sha TEXT NOT NULL DEFAULT '',
            revision INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'unknown',
            last_job_id TEXT NOT NULL DEFAULT '', updated_at INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(node_id,name)
        );
        CREATE TABLE IF NOT EXISTS config_versions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,node_id TEXT NOT NULL, name TEXT NOT NULL,
            revision INTEGER NOT NULL, content_enc TEXT NOT NULL, created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_config_versions ON config_versions(node_id,name,revision);
        CREATE TABLE IF NOT EXISTS library_configs(
          id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL,
          content_enc TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1,
          created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS config_presets(
          id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
          created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS config_preset_items(
          preset_id TEXT NOT NULL REFERENCES config_presets(id) ON DELETE CASCADE,
          config_id TEXT NOT NULL REFERENCES library_configs(id) ON DELETE RESTRICT,
          kind TEXT NOT NULL, PRIMARY KEY(preset_id,kind)
        );
        CREATE INDEX IF NOT EXISTS idx_library_configs_kind ON library_configs(kind,name);
        CREATE TABLE IF NOT EXISTS alert_states(node_id TEXT PRIMARY KEY,status TEXT NOT NULL,updated_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS telemetry_history(
            id INTEGER PRIMARY KEY AUTOINCREMENT,node_id TEXT NOT NULL REFERENCES nodes(id),
            ts INTEGER NOT NULL,load1 REAL, cpu_percent REAL,mem_percent REAL,disk_percent REAL,
            net_rx INTEGER, net_tx INTEGER);
        CREATE INDEX IF NOT EXISTS idx_telemetry_history ON telemetry_history(node_id,ts);
        CREATE TABLE IF NOT EXISTS app_updates(id INTEGER PRIMARY KEY AUTOINCREMENT,status TEXT NOT NULL,
            requested_at INTEGER NOT NULL, finished_at INTEGER NOT NULL DEFAULT 0,detail TEXT NOT NULL DEFAULT '');
        ''')
        c.executescript('''
        CREATE TABLE IF NOT EXISTS projects(
          id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
          panel_url TEXT NOT NULL DEFAULT '', panel_ip TEXT NOT NULL DEFAULT '',
          secret_key_enc TEXT NOT NULL DEFAULT '', api_token_enc TEXT NOT NULL DEFAULT '',
          created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS deployment_profiles(
          id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
          name TEXT NOT NULL, mode TEXT NOT NULL, transport TEXT NOT NULL,
          settings TEXT NOT NULL DEFAULT '{}', revision INTEGER NOT NULL DEFAULT 1,
          created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
          UNIQUE(project_id,name)
        );
        ''')
        if 'username' not in [r['name'] for r in c.execute('PRAGMA table_info(admins)')]:
            c.execute("ALTER TABLE admins ADD COLUMN username TEXT NOT NULL DEFAULT 'admin'")
        c.execute('INSERT OR IGNORE INTO projects(id,name,created_at,updated_at) VALUES(?,?,?,?)',
                  ('default','Основной проект',int(time.time()),int(time.time())))
        # v1.3: project-level Remnawave registration defaults (no keys exposed via API).
        for col, declaration in [
            ('panel_config_profile_uuid', "TEXT NOT NULL DEFAULT ''"),
            ('panel_active_inbounds', "TEXT NOT NULL DEFAULT '[]'"),
            ('panel_country_code', "TEXT NOT NULL DEFAULT 'XX'")]:
            if col not in [r['name'] for r in c.execute('PRAGMA table_info(projects)')]:
                c.execute(f'ALTER TABLE projects ADD COLUMN {col} {declaration}')
        for col,declaration in [
            ('panel_auto_profile_uuid', "TEXT NOT NULL DEFAULT ''"),
            ('panel_auto_inbounds', "TEXT NOT NULL DEFAULT '[]'"),
            ('panel_auto_country', "TEXT NOT NULL DEFAULT 'XX'"),
            ('panel_register_started_at', "INTEGER NOT NULL DEFAULT 0")]:
            if col not in [r['name'] for r in c.execute('PRAGMA table_info(nodes)')]:
                c.execute(f'ALTER TABLE nodes ADD COLUMN {col} {declaration}')
        for col,declaration in [('project_id',"TEXT NOT NULL DEFAULT 'default'"),
                                ('profile_id',"TEXT NOT NULL DEFAULT ''"),
                                ('profile_snapshot',"TEXT NOT NULL DEFAULT '{}'"),('domain',"TEXT NOT NULL DEFAULT ''"),('panel_node_uuid',"TEXT NOT NULL DEFAULT ''"),('panel_registering',"INTEGER NOT NULL DEFAULT 0")]:
            if col not in [r['name'] for r in c.execute('PRAGMA table_info(nodes)')]:
                c.execute(f'ALTER TABLE nodes ADD COLUMN {col} {declaration}')
        for profile_id,name,mode,transport in [
            ('default-agent','Только агент','agent','none'),
            ('default-tls','TLS + Nginx fallback','full','tls-raw'),
            ('default-node','Remnawave Node','node','tls-raw'),
            ('default-reality','REALITY + Vision','node','reality-vision'),
            ('default-xhttp','XHTTP + TLS','node','xhttp-tls'),
            ('default-hysteria','Hysteria 2 + TLS / UDP','node','hysteria2'),
            ('default-bridge','RU → зарубежный мост','node','bridge'),
        ]:
            c.execute('INSERT OR IGNORE INTO deployment_profiles(id,project_id,name,mode,transport,settings,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',
                      (profile_id,'default',name,mode,transport,'{}',int(time.time()),int(time.time())))
        for col, declaration in [('preset',"TEXT NOT NULL DEFAULT 'agent'"), ('pending_install_enc',"TEXT NOT NULL DEFAULT ''"),('install_job_id',"TEXT NOT NULL DEFAULT ''")]:
            if col not in [r['name'] for r in c.execute('PRAGMA table_info(nodes)')]:
                c.execute(f'ALTER TABLE nodes ADD COLUMN {col} {declaration}')

def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()

def auth_node(node_id, token):
    if len(token) < 32 or len(token)>256: return False
    with connect() as c:
        row = c.execute('SELECT token_hash FROM nodes WHERE id=?', (node_id,)).fetchone()
    return bool(row and hmac.compare_digest(row['token_hash'], hash_token(token)))

def queue_job(node_id, job_id, cmd, payload):
    now = int(time.time())
    encrypted = FERNET.encrypt(json.dumps(payload).encode()).decode()
    with connect() as c:
        if not c.execute('SELECT id FROM nodes WHERE id=?',(node_id,)).fetchone():
            raise LookupError('Node not found')
        c.execute('INSERT INTO jobs(id,node_id,command,encrypted_payload,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)',
                  (job_id,node_id,cmd,encrypted,'queued',now,now))
        c.execute('INSERT INTO audit VALUES(?,?,?)',(now,'job', f'{node_id} {cmd} {job_id}'))

def take_job(node_id):
    now=int(time.time())
    with connect() as c:
        c.execute('BEGIN IMMEDIATE')
        # One job at a time. Timed-out leases intentionally require manual intervention.
        running=c.execute("SELECT id FROM jobs WHERE node_id=? AND status='running'",(node_id,)).fetchone()
        if running:
            c.execute('COMMIT'); return None
        row=c.execute("SELECT * FROM jobs WHERE node_id=? AND status='queued' ORDER BY created_at,id LIMIT 1",(node_id,)).fetchone()
        if not row:
            c.execute('COMMIT'); return None
        c.execute("UPDATE jobs SET status='running',updated_at=? WHERE id=?",(now,row['id']))
        c.execute('COMMIT')
    payload=json.loads(FERNET.decrypt(row['encrypted_payload']).decode())
    with connect() as c:
        n=c.execute('SELECT signing_key_enc FROM nodes WHERE id=?',(node_id,)).fetchone()
    if not n or not n['signing_key_enc']: raise RuntimeError('Missing node signing key')
    key=bytes.fromhex(FERNET.decrypt(n['signing_key_enc']).decode())
    signed={'job_id':row['id'],'command':row['command'],'payload':payload,'expires':now+1200}
    raw=json.dumps(signed,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    sig=hmac.new(key,raw,hashlib.sha256).hexdigest()
    return {'id':row['id'],'command':row['command'],'payload':payload,'signed':signed,'signature':sig}

def finish_job(node_id, job_id, status, output):
    with connect() as c:
        cur=c.execute("UPDATE jobs SET status=?,output=?, encrypted_payload='',updated_at=? WHERE id=? AND node_id=? AND status='running'",
                      (status,output[:130000],int(time.time()),job_id,node_id))
        return cur.rowcount==1


def log_install(node_id, message):
    # Only ever called with redacted, non-sensitive diagnostic text.
    msg=str(message).replace('\x00','')[:3200]
    if not msg:return
    with connect() as c:
        c.execute('INSERT INTO install_logs(node_id,ts,message) VALUES(?,?,?)',(node_id,int(time.time()),msg))
        # Bound retention per VPS; no unbounded DB growth.
        c.execute('DELETE FROM install_logs WHERE node_id=? AND id < (SELECT COALESCE(MAX(id)-1200,0) FROM install_logs WHERE node_id=?)',(node_id,node_id))

def logs_since(node_id, cursor):
    with connect() as c:
        return [dict(row) for row in c.execute('SELECT id,ts,message FROM install_logs WHERE node_id=? AND id>? ORDER BY id LIMIT 150',(node_id,cursor))]

def start_profile_if_ready(node_id):
    """Atomic transition; a reconnecting agent cannot enqueue profile twice."""
    now=int(time.time())
    with connect() as c:
        c.execute('BEGIN IMMEDIATE')
        node=c.execute('SELECT stage,preset,pending_install_enc FROM nodes WHERE id=?',(node_id,)).fetchone()
        if not node or node['stage']!='waiting':
            c.execute('COMMIT'); return None
        if node['preset']=='agent':
            c.execute("UPDATE nodes SET stage='ready' WHERE id=?",(node_id,))
            c.execute('COMMIT');return 'ready'
        if not node['pending_install_enc']:
            c.execute("UPDATE nodes SET stage='failed',error='Missing installation parameters' WHERE id=?",(node_id,))
            c.execute('COMMIT');return 'failed'
        body=json.loads(FERNET.decrypt(node['pending_install_enc']).decode())
        command='node.install' if node['preset']=='node' else 'legacy.install'
        job_id=secrets.token_hex(16)
        c.execute('INSERT INTO jobs(id,node_id,command,encrypted_payload,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)',
                 (job_id,node_id,command,node['pending_install_enc'],'queued',now,now))
        c.execute("UPDATE nodes SET stage='provisioning',pending_install_enc='',install_job_id=? WHERE id=?",(job_id,node_id))
        c.execute('COMMIT')
    log_install(node_id,'Настройка агента завершена. Запускается пресет: '+('Remnawave Node' if command=='node.install' else 'Полный стек Nginx + SSL + Remnawave'))
    return 'provisioning'

def recover_agent_if_healthy(node_id, telemetry):
    """Recover a failed *agent-only* bootstrap after the agent first checks in.

    This is intentionally not for node/full presets. Those may have partially
    applied host configuration and require explicit re-provisioning.
    """
    if not isinstance(telemetry, dict) or not isinstance(telemetry.get('hostname'), str) or not telemetry['hostname']:
        return False
    with connect() as c:
        cur = c.execute("UPDATE nodes SET stage='ready',error='' WHERE id=? AND stage='failed' AND preset='agent'", (node_id,))
    if cur.rowcount:
        log_install(node_id, 'Агент подключился после неполной установки; связь и телеметрия подтверждены. Управление доступно.')
        return True
    return False

def installation_job_result(node_id, job_id, success, output):
    with connect() as c:
        row=c.execute('SELECT stage,install_job_id FROM nodes WHERE id=?',(node_id,)).fetchone()
        if not row or row['install_job_id']!=job_id or row['stage']!='provisioning':return
        if success:
            c.execute("UPDATE nodes SET stage='verifying',error='' WHERE id=?",(node_id,))
        else:
            c.execute("UPDATE nodes SET stage='failed',error=? WHERE id=?",('Ошибка установки выбранного пресета. Смотри журнал задания.',node_id))
    log_install(node_id, 'Пресет установлен. Проверяем контейнеры…' if success else 'Установка пресета завершилась ошибкой. Проверь детали в журнале заданий.')

def verify_telemetry(node_id, telemetry):
    with connect() as c:
        r=c.execute('SELECT stage,preset FROM nodes WHERE id=?',(node_id,)).fetchone()
        if not r or r['stage']!='verifying':return
        names={str(item.get('Names','')).lstrip('/'):str(item.get('State',item.get('Status',''))).lower() for item in telemetry.get('containers',[]) if isinstance(item,dict)}
        ok= ('remnanode' in names and ('running' in names['remnanode'] or names['remnanode']=='up'))
        if r['preset']=='full':ok=ok and 'nginx' in names and ('running' in names['nginx'] or names['nginx']=='up')
        if not ok:return
        registration=c.execute('SELECT panel_auto_profile_uuid FROM nodes WHERE id=?',(node_id,)).fetchone()
        if registration and registration['panel_auto_profile_uuid']:
            c.execute("UPDATE nodes SET stage='registering',error='' WHERE id=?",(node_id,))
            stage='registering'
        else:
            c.execute("UPDATE nodes SET stage='ready',error='' WHERE id=?",(node_id,))
            stage='ready'
    log_install(node_id,'Контейнеры запущены. Регистрируем ноду в Remnawave…' if stage=='registering' else 'Проверка пройдена: необходимые контейнеры запущены. Управление доступно.')
