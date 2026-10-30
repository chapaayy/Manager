#!/usr/bin/env python3
"""Minimal host-side privileged RPC (Unix socket only). NEVER runs a user shell."""
import datetime
import hashlib
import hmac
import sqlite3
import uuid
import ipaddress
import json
import os
import re
import shutil
import socket
import socketserver
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path

SOCK='/run/xppn-agent/helper.sock'
ALLOWED={
    'nginx':Path('/opt/nginx/nginx.conf'),
    'nginx_compose':Path('/opt/nginx/docker-compose.yml'),
    'node_compose':Path('/opt/remnanode/docker-compose.yml'),
}
CONTAINERS={'remnanode','nginx'}
RUN_LOCK=threading.Lock()
CURRENT_JOB=threading.local()
CPU_SAMPLE=None

def report_progress(message):
    # Milestones only; never mirror raw installer stdout or passwords.
    jid=getattr(CURRENT_JOB,'id',None)
    if not jid:return
    path=Path('/run/xppn-agent')/('progress-'+jid+'.log')
    try:
        fd=os.open(str(path),os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o640)
        os.fchown(fd,0,15001)
        with os.fdopen(fd,'a',encoding='utf-8') as out:
            out.write(str(message).replace('\n',' ')[:450]+'\n')
    except OSError:pass


def run(cmd,timeout=45,check=True):
    # Absolute executable paths and no shell. Capped command output.
    p=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root'})
    result=(p.stdout+'\n'+p.stderr).strip()[-12000:]
    if check and p.returncode: raise RuntimeError(result[-2000:] or f'Command failed ({p.returncode})')
    return result

def assert_file(path, must_exist=True):
    if path.is_symlink(): raise ValueError('Symlink targets are forbidden')
    if must_exist and (not path.is_file()): raise FileNotFoundError(str(path))
    if not path.parent.is_dir() or path.parent.is_symlink(): raise ValueError('Invalid parent directory')
    if path.exists() and (not path.is_file() or path.stat().st_size>200000):raise ValueError('Invalid configuration file')
    return path

def textfile(path):
    return assert_file(path).read_text(encoding='utf-8')

def digest(content): return hashlib.sha256(content.encode()).hexdigest()

def backup(path,original):
    folder=Path('/var/backups/xppn')
    folder.mkdir(parents=True,exist_ok=True)
    os.chmod(folder,0o700)
    marker=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out=folder/f'{path.name}.{marker}.{hashlib.sha256(str(path).encode()).hexdigest()[:8]}.bak'
    out.write_text(original)
    os.chmod(out,0o600)
    return out

def put_file(path,content,orig):
    # Existing nginx.conf is bind-mounted by inode: overwrite in-place, not rename.
    assert_file(path)
    fd=os.open(str(path),os.O_WRONLY|os.O_TRUNC|os.O_NOFOLLOW)
    with os.fdopen(fd,'w',encoding='utf-8') as f:
        f.write(content);f.flush();os.fsync(f.fileno())

def validate_config(name):
    if name=='nginx':
        return run(['/usr/bin/docker','exec','nginx','nginx','-t'],timeout=25)
    p=str(ALLOWED[name])
    return run(['/usr/bin/docker','compose','-f',p,'config','-q'],timeout=25)

def save_config(p):
    name=p.get('name')
    if name not in ALLOWED:raise ValueError('Config name not allowed')
    content=p.get('content','')
    if not isinstance(content,str) or len(content)>100000 or '\x00' in content:raise ValueError('Invalid content')
    if not isinstance(p.get('sha256'),str) or not re.fullmatch('[a-f0-9]{64}',p['sha256']):raise ValueError('Expected digest required')
    path=assert_file(ALLOWED[name]);orig=textfile(path)
    if digest(orig)!=p['sha256']:raise ValueError('File changed since you opened it. Reload before saving.')
    if content==orig:return {'message':'No changes','sha256':digest(orig)}
    backup_path=backup(path,orig)
    put_file(path,content,orig)
    try:
        result=validate_config(name)
        if name=='nginx':
            run(['/usr/bin/docker','exec','nginx','nginx','-s','reload'],timeout=25)
        else:
            # Apply the validated Compose file, not merely write it. This may restart VPN.
            run(['/usr/bin/docker','compose','-f',str(path),'up','-d'],timeout=150)
    except Exception as e:
        put_file(path,orig,content)
        try:
            if name=='nginx':run(['/usr/bin/docker','exec','nginx','nginx','-s','reload'],timeout=25)
            else:run(['/usr/bin/docker','compose','-f',str(path),'up','-d'],timeout=150)
        except Exception:
            raise RuntimeError('New config failed; original restored on disk but service recovery needs manual verification')
        raise RuntimeError('New config failed; original restored and reapplied: '+str(e)[:650])
    return {'message':f'Saved, verified. Backup: {backup_path}', 'sha256':digest(content),'validation':result}


# Read-only log sources; no arbitrary filenames, systemd units, or shell interpolation.
LOG_SOURCES={
 'xray.access':Path('/var/log/remnanode/access.log'),
 'xray.error':Path('/var/log/remnanode/error.log'),
 'nginx.access':Path('/opt/nginx/logs/access.log'),
 'nginx.error':Path('/opt/nginx/logs/error.log'),
}
JOURNAL_UNITS={'journal.docker':'docker.service','journal.xppn-helper':'xppn-helper.service',
               'journal.xray':'remnanode.service'}

def read_logs(p):
    source=p.get('source')
    count=p.get('lines',100)
    if type(count) is not int or not 1<=count<=300:raise ValueError('Invalid lines')
    if source in ('docker.remnanode','docker.nginx'):
        container=source.split('.')[1]
        return run(['/usr/bin/docker','logs','--tail',str(count),'--timestamps',container],timeout=20,check=False)[-12000:]
    if source in JOURNAL_UNITS:
        binary=shutil.which('journalctl')
        if not binary:raise RuntimeError('journald not installed')
        return run([binary,'--no-pager','-u',JOURNAL_UNITS[source],'-n',str(count),'--output=short-iso'],timeout=20,check=False)[-12000:]
    if source in LOG_SOURCES:
        f=LOG_SOURCES[source]
        if not f.is_file() or f.is_symlink():return 'Log file not found or is not a regular file'
        # Only read the bounded tail, never the entire potentially large file.
        return run(['/usr/bin/tail','-n',str(count),'--',str(f)],timeout=20,check=False)[-12000:]
    raise ValueError('Log source not allowed')

LOG_PRESETS={'compact':('10M','3'),'standard':('50M','5'),'archive':('100M','10')}
def set_log_policy(p):
    preset=p.get('preset')
    if preset not in LOG_PRESETS:raise ValueError('Unknown log preset')
    maxsize,rotations=LOG_PRESETS[preset]
    path=Path('/etc/logrotate.d/xppn-managed')
    if path.is_symlink():raise ValueError('Refusing to change symlink')
    if path.exists() and (not path.is_file() or path.stat().st_size>5000):raise ValueError('Existing policy not recognized')
    # Restrict changes to logs we own; Docker's json-file rotation is defined by Compose.
    content=f"""/var/log/remnanode/access.log /var/log/remnanode/error.log /opt/nginx/logs/access.log /opt/nginx/logs/error.log {{
    daily
    maxsize {maxsize}
    rotate {rotations}
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}}
"""
    old=path.read_text() if path.exists() else None
    if old is not None:backup(path,old)
    fd,tmp=tempfile.mkstemp(prefix='.xppn-rotate-',dir='/etc/logrotate.d')
    try:
        with os.fdopen(fd,'w') as out:out.write(content)
        os.chmod(tmp,0o644)
        binary=shutil.which('logrotate')
        if not binary:raise RuntimeError('logrotate is not installed')
        run([binary,'--debug',tmp],timeout=15)
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    return {'preset':preset,'maxsize':maxsize,'rotate':int(rotations),
            'note':'Docker logs are controlled via Compose logging.max-size/max-file; this policy rotates Xray/Nginx log files.'}

def collect_status():
    res={'time':int(time.time()),'hostname':socket.gethostname(),'files':{},'containers':[], 'helper_version':'1.5.0','capabilities':['network.status','network.bbr','node.install','legacy.install','node.deploy','node.upgrade','ssl.renew','docker.action','docker.logs','logs.read','logs.policy','config.read','config.write']}
    try:
        import shutil
        du=shutil.disk_usage('/')
        res['disk']={'total':du.total,'free':du.free}
        with open('/proc/meminfo') as f:
            d={}
            for line in f:
                k,_,v=line.partition(':');d[k]=v.strip().split()[0]
            res['memory']={'total_kb':int(d.get('MemTotal',0)),'available_kb':int(d.get('MemAvailable',0))}
        res['loadavg']=list(os.getloadavg())
    except Exception:pass
    # CPU utilisation is calculated between successive helper heartbeat samples.
    global CPU_SAMPLE
    try:
        parts=[int(v) for v in Path('/proc/stat').read_text().splitlines()[0].split()[1:]]
        total=sum(parts);idle=parts[3]+parts[4]
        if CPU_SAMPLE and total>CPU_SAMPLE[0]:
            res['cpu_percent']=round(100*(1-(idle-CPU_SAMPLE[1])/(total-CPU_SAMPLE[0])),1)
        CPU_SAMPLE=(total,idle)
    except Exception:pass
    try:
        counters={'rx':0,'tx':0}
        for line in Path('/proc/net/dev').read_text().splitlines()[2:]:
            name,_,numbers=line.partition(':');name=name.strip()
            if name.startswith(('lo','veth','docker','br-')):continue
            values=numbers.split()
            counters['rx']+=int(values[0]);counters['tx']+=int(values[8])
        res['network_bytes']=counters
    except Exception:pass
    for key,path in ALLOWED.items(): res['files'][key]=path.exists() and not path.is_symlink()
    try:
        txt=run(['/usr/bin/docker','ps','-a','--format','{{json .}}'],timeout=15)
        res['containers']=[json.loads(s) for s in txt.splitlines() if s.strip().startswith('{')]
    except Exception as e:res['docker_error']=str(e)[:300]
    return res

def ensure_panel_firewall(panel_ip):
    try:
        panel=ipaddress.ip_address(panel_ip)
        if panel.version!=4 or not panel.is_global:raise ValueError()
    except ValueError:raise ValueError('Public IPv4 panel IP required')
    if not Path('/usr/sbin/iptables').exists() or not Path('/usr/sbin/ip6tables').exists():
        raise RuntimeError('iptables and ip6tables required to protect node port')
    # Apply firewall *before* starting the node; persist on reboots.
    Path('/etc/xppn-node-panel-ip').write_text('PANEL_IP='+str(panel)+'\n')
    os.chmod('/etc/xppn-node-panel-ip',0o600)
    run(['/usr/bin/systemctl','daemon-reload'],timeout=30)
    run(['/usr/bin/systemctl','enable','--now','xppn-node-firewall.service'],timeout=30)

def install_node(p):
    key=p.get('secret_key','')
    ver=p.get('version','')
    if not isinstance(key,str) or not re.fullmatch(r'[A-Za-z0-9+/=_-]{16,32768}',key):raise ValueError('Invalid SECRET_KEY format')
    if not isinstance(ver,str) or not re.fullmatch(r'\d+\.\d+\.\d+',ver):raise ValueError('Pinned version required')
    if Path('/opt/remnanode/docker-compose.yml').exists() or Path('/opt/remnanode/.env').exists():
        raise RuntimeError('Existing Remnawave installation detected; refusing to overwrite')
    report_progress('Проверяем правила firewall для TCP 2222…')
    ensure_panel_firewall(p.get('panel_ip',''))
    report_progress('Создаём Remnawave Compose и окружение…')
    folder=Path('/opt/remnanode');folder.mkdir(mode=0o700,parents=True,exist_ok=True)
    cf=folder/'docker-compose.yml'; ef=folder/'.env'
    if cf.exists() or ef.exists():raise RuntimeError('Existing Remnawave installation detected; refusing to overwrite')
    compose=f'''services:\n  remnanode:\n    image: remnawave/node:{ver}\n    container_name: remnanode\n    hostname: remnanode\n    network_mode: host\n    restart: unless-stopped\n    env_file:\n      - .env\n    logging:\n      driver: json-file\n      options:\n        max-size: "10m"\n        max-file: "5"\n'''
    try:
        ef.write_text('NODE_PORT=2222\nSECRET_KEY='+key+'\n')
        os.chmod(ef,0o600)
        cf.write_text(compose);os.chmod(cf,0o600)
        run(['/usr/bin/docker','compose','-f',str(cf),'config','-q'])
        report_progress('Загружаем образ и запускаем контейнер Remnawave…')
        run(['/usr/bin/docker','compose','-f',str(cf),'up','-d'],timeout=240)
    except Exception:
        # Keep configuration on disk to inspect/recover; never include secrets in errors.
        raise RuntimeError('Node provisioning failed; inspect /opt/remnanode locally')
    report_progress('Remnawave Node запущена. Ожидаем проверки состояния…')
    return 'Remnawave Node installed. IMPORTANT: restrict TCP 2222 to the panel IP before using this node.'

def deploy_node():
    f=assert_file(ALLOWED['node_compose'])
    run(['/usr/bin/docker','compose','-f',str(f),'config','-q'],timeout=35)
    run(['/usr/bin/docker','compose','-f',str(f),'pull','remnanode'],timeout=480)
    result=run(['/usr/bin/docker','compose','-f',str(f),'up','-d','--no-deps','remnanode'],timeout=240)
    time.sleep(3)
    run(['/usr/bin/docker','inspect','-f','{{.State.Running}}','remnanode'],timeout=20)
    return 'Deployment completed. Verify connection in Remnawave panel. '+result[-800:]

def upgrade_node(p):
    ver=p.get('version','')
    if not isinstance(ver,str) or not re.fullmatch(r'\d+\.\d+\.\d+',ver):raise ValueError('Pinned semantic version required')
    f=assert_file(ALLOWED['node_compose'])
    old=textfile(f)
    pattern=r'(?m)^(\s*image:\s*)(?:mirror\.gcr\.io/)?remnawave/node:[^\s#]+'
    found=list(re.finditer(pattern,old))
    if len(found)!=1:raise RuntimeError('Expected exactly one remnawave/node image in Compose. Edit manually.')
    new=re.sub(pattern,lambda m:m.group(1)+'remnawave/node:'+ver,old,count=1)
    if old==new:return 'Requested version is already configured.'
    dest=backup(f,old)
    put_file(f,new,old)
    try:
        run(['/usr/bin/docker','compose','-f',str(f),'config','-q'],timeout=30)
        run(['/usr/bin/docker','compose','-f',str(f),'pull','remnanode'],timeout=480)
        run(['/usr/bin/docker','compose','-f',str(f),'up','-d','--no-deps','remnanode'],timeout=240)
        result=run(['/usr/bin/docker','inspect','-f','{{.State.Running}}','remnanode'],timeout=25)
        if result.strip()!='true':raise RuntimeError('Container not running')
    except Exception:
        put_file(f,old,new)
        try:run(['/usr/bin/docker','compose','-f',str(f),'up','-d','--no-deps','remnanode'],timeout=240)
        except Exception:pass
        raise RuntimeError('Upgrade failed. Previous compose restored; check live node and connection manually.')
    return f'Remnawave Node {ver} running. Backup: {dest}. Check panel connectivity and traffic.'

def legacy_install(p):
    # Explicit advanced action. Requires a *clean* host; cannot overwrite an existing installation.
    if p.get('confirm_clean') is not True:raise ValueError('Clean-host confirmation required')
    domain=p.get('domain','')
    ver=p.get('version','')
    key=p.get('secret_key','')
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{2,250}',domain) or '..' in domain or domain.endswith('.'):
        raise ValueError('Invalid domain')
    if not re.fullmatch(r'\d+\.\d+\.\d+',ver):raise ValueError('Invalid version')
    if not isinstance(key,str) or not re.fullmatch(r'[A-Za-z0-9+/=_-]{16,32768}',key):raise ValueError('Invalid SECRET_KEY')
    if Path('/opt/nginx/docker-compose.yml').exists() or Path('/opt/remnanode/docker-compose.yml').exists():
        raise RuntimeError('Existing Nginx/Remnawave installation found: operation refused')
    report_progress('Устанавливаем ограничение порта 2222 для IP панели…')
    ensure_panel_firewall(p.get('panel_ip',''))
    report_progress('Готовим конфигурацию Nginx, SSL и Remnawave…')
    src=Path('/opt/xppn-agent/legacy/install.sh')
    if not src.is_file():raise FileNotFoundError('Legacy installer is missing')
    envfile=src.parent/'installer.env'
    profiles={'standard':('50M','5'),'compact':('10M','3'),'archive':('100M','10')}
    logs_preset=p.get('logs_preset','standard')
    if logs_preset not in profiles:raise ValueError('Unsupported logs preset')
    log_size,log_count=profiles[logs_preset]
    site_mode=p.get('site','static')
    if site_mode not in ('static','none'):raise ValueError('Unsupported site mode')
    source_site='/opt/xppn-agent/legacy/dist' if site_mode=='static' else '/opt/xppn-agent/legacy/site-none'
    values={'REMNANODE_LOGROTATE_SIZE':log_size,'REMNANODE_LOGROTATE_ROTATE':log_count,'DOMAINS':domain,'SECRET_KEY':key,'PANEL_AUTO_REGISTER_NODE':'0','AUTO_INSTALL_NODE':'1','REMNANODE_IMAGE':f'remnawave/node:{ver}', 'ACME_EMAIL':f'admin@{domain}', 'SITE_SOURCE_DIR':source_site}
    # Explicit format allowlist, no multiline injection.
    envfile.write_text(''.join(k+'='+v+'\n' for k,v in values.items()))
    os.chmod(envfile,0o600)
    try:
        report_progress('Запущен полный установщик. Выпуск SSL и Docker-образы могут занять несколько минут. Подробный журнал старого установщика остаётся на VPS во избежание утечки секретов.')
        run(['/usr/bin/bash',str(src),'install',domain],timeout=1200)
    except Exception:
        # Suppress stdout/stderr from the legacy shell in case its logs contain credentials.
        raise RuntimeError('Legacy installer failed; inspect /opt/nginx/logs/install.log locally (may contain secrets)')
    report_progress('Полная установка завершена, запущена проверка контейнеров…')
    return 'Full legacy installation completed. Verify DNS, SSL and firewall before opening traffic.'

def network_diagnostics():
    """Non-destructive host checks; read-only commands have hard-coded arguments."""
    import shutil
    result={'congestion_control':'unknown','available_congestion_controls':[], 'qdisc':'unknown',
            'fail2ban':'not installed','firewall':'unknown','ports':'check manually'}
    for key,path in [('congestion_control','/proc/sys/net/ipv4/tcp_congestion_control'),
                     ('qdisc','/proc/sys/net/core/default_qdisc')]:
        try: result[key]=Path(path).read_text().strip()
        except OSError:pass
    try:result['available_congestion_controls']=Path('/proc/sys/net/ipv4/tcp_available_congestion_control').read_text().strip().split()
    except OSError:pass
    if shutil.which('fail2ban-client'):
        try:result['fail2ban']=run([shutil.which('fail2ban-client'),'status'],timeout=12,check=False)[-2000:]
        except Exception:result['fail2ban']='error'
    if shutil.which('nft'):
        result['firewall']='nftables detected'
    elif shutil.which('iptables'):
        result['firewall']='iptables detected'
    return result

def set_tcp_congestion(p):
    """Deliberately narrow kernel setting. No arbitrary sysctl key or shell commands."""
    import shutil
    algorithm=p.get('algorithm')
    if algorithm not in ('cubic','bbr'):raise ValueError('Only cubic/bbr allowed')
    available=network_diagnostics()['available_congestion_controls']
    if algorithm not in available:raise RuntimeError(f'{algorithm} is not available on this kernel')
    path=Path('/etc/sysctl.d/98-xppn-tcp-congestion.conf')
    if path.exists() and (path.is_symlink() or path.stat().st_size>2048):
        raise RuntimeError('Unsafe existing sysctl override; refusing to replace')
    old=path.read_text() if path.is_file() else None
    if old is not None and any(line.strip() and not line.strip().startswith('#') and not line.strip().startswith('net.ipv4.tcp_congestion_control=') for line in old.splitlines()):
        raise RuntimeError('Existing file contains other settings. Refusing to overwrite')
    content=f'# Managed by XPPN Manager. Affects TCP only, not Hysteria/QUIC.\nnet.ipv4.tcp_congestion_control={algorithm}\n'
    path.parent.mkdir(exist_ok=True,parents=True)
    fd,tmp=tempfile.mkstemp(dir=str(path.parent),prefix='.xppn-sysctl-')
    try:
        with os.fdopen(fd,'w') as f:f.write(content)
        os.chmod(tmp,0o644)
        os.replace(tmp,path)
        result=run([shutil.which('sysctl') or '/usr/sbin/sysctl','-p',str(path)],timeout=15)
    except Exception:
        if old is None:path.unlink(missing_ok=True)
        else:path.write_text(old)
        raise
    return {'algorithm':algorithm,'message':result[-500:]}

def authorize_signed_job(obj):
    signed=obj.get('signed')
    sig=obj.get('signature')
    if not isinstance(signed,dict) or not isinstance(sig,str) or not re.fullmatch(r'[a-f0-9]{64}',sig):
        raise PermissionError('Signed instruction required')
    if set(signed)!={'job_id','command','payload','expires'}:
        raise PermissionError('Invalid signing envelope')
    if signed['command']!=obj.get('command') or signed['payload']!=(obj.get('payload') or {}):
        raise PermissionError('Envelope mismatch')
    try:
        jid=str(uuid.UUID(signed['job_id']))
        expires=int(signed['expires'])
    except (ValueError,KeyError,TypeError):raise PermissionError('Invalid job identifier or expiry')
    now=int(time.time())
    if not now<=expires<=now+1200:raise PermissionError('Expired or future instruction')
    signing_key=bytes.fromhex(Path('/opt/xppn-agent/helper.key').read_text().strip())
    raw=json.dumps(signed,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    digest=hmac.new(signing_key,raw,hashlib.sha256).hexdigest()
    if not hmac.compare_digest(digest,sig):raise PermissionError('Invalid manager signature')
    # Persist replay protection even across host helper/system restarts.
    replay=Path('/var/lib/xppn-helper')
    replay.mkdir(mode=0o700,parents=True,exist_ok=True)
    with sqlite3.connect(replay/'seen.sqlite',timeout=20) as db:
        db.execute('CREATE TABLE IF NOT EXISTS used(id TEXT PRIMARY KEY,expires INTEGER NOT NULL)')
        db.execute('DELETE FROM used WHERE expires<?',(now-86400,))
        try:db.execute('INSERT INTO used VALUES (?,?)',(jid,expires))
        except sqlite3.IntegrityError:raise PermissionError('Replay detected')
    return True

def execute(obj):
    cmd=obj.get('command');p=obj.get('payload') or {}
    if cmd=='status':return collect_status()
    authorize_signed_job(obj)
    CURRENT_JOB.id=obj['signed']['job_id']
    if cmd=='network.status':return network_diagnostics()
    if cmd=='logs.read':return read_logs(p)
    if cmd=='logs.policy':return set_log_policy(p)
    if cmd=='network.bbr':return set_tcp_congestion(p)
    if cmd=='docker.action':
        if p.get('container') not in CONTAINERS or p.get('action') not in {'start','stop','restart'}:raise ValueError('Action not allowed')
        return run(['/usr/bin/docker',p['action'],p['container']],timeout=80)
    if cmd=='docker.logs':
        if p.get('container') not in CONTAINERS:raise ValueError('Container not allowed')
        return run(['/usr/bin/docker','logs','--tail','80','--timestamps',p['container']],timeout=30,check=False)[-8000:]
    if cmd=='config.read':
        if p.get('name') not in ALLOWED:raise ValueError('Config not allowed')
        txt=textfile(ALLOWED[p['name']])
        # secrets live in .env, which cannot be read through RPC.
        return {'content':txt,'sha256':digest(txt),'name':p['name']}
    if cmd=='config.write': return save_config(p)
    if cmd=='node.deploy':return deploy_node()
    if cmd=='node.upgrade':return upgrade_node(p)
    if cmd=='node.install':return install_node(p)
    if cmd=='ssl.renew':
        script=Path('/opt/nginx/install.sh')
        if not script.is_file() or script.is_symlink():raise FileNotFoundError('Legacy SSL renewal script missing')
        return run(['/usr/bin/bash',str(script),'renew'],timeout=400)[-2000:]
    if cmd=='legacy.install':return legacy_install(p)
    raise ValueError('Unknown command')

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        # Linux peer credentials. Only the container agent UID 10001 may call.
        import struct
        raw=self.request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)
        pid,uid,gid=struct.unpack('3i',raw)
        if uid!=10001:return
        try:
            raw=self.rfile.readline(120001)
            if len(raw)>120000:raise ValueError('Request too large')
            request=json.loads(raw)
            if not isinstance(request,dict):raise ValueError('Invalid request')
            with RUN_LOCK: result=execute(request)
            out={'ok':True,'result':result}
        except Exception as e:
            # Never print full values/payload. For legacy, redact on error above.
            out={'ok':False,'error':str(e)[:1000]}
        self.wfile.write((json.dumps(out,ensure_ascii=False)+'\n').encode())

class Server(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):
    daemon_threads=True

if __name__=='__main__':
    if os.path.exists(SOCK):os.unlink(SOCK)
    with Server(SOCK,Handler) as srv:
        import grp
        os.chmod(SOCK,0o660)
        os.chown(SOCK,0,15001)
        srv.serve_forever()
