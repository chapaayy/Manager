"""Password used only in the bootstrap worker's memory. Verified SSH host fingerprint."""
import base64
import hashlib
import io
import os
import socket
import tarfile
import time
import uuid
from pathlib import Path
import paramiko
from . import store

ROOT=Path('/app')

def fingerprint(key):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')

def transport(ip, port=22):
    sock=socket.create_connection((ip,port),timeout=12)
    t=paramiko.Transport(sock, disabled_algorithms={'pubkeys': ['ssh-rsa']})
    t.banner_timeout=10
    t.auth_timeout=15
    t.start_client(timeout=12)
    return t

def probe(ip, port=22):
    t=transport(ip,port)
    try:
        return fingerprint(t.get_remote_server_key())
    finally:
        t.close()

def _archive():
    b=io.BytesIO()
    with tarfile.open(fileobj=b,mode='w:gz') as tf:
        for folder in ['agent','bootstrap','legacy']:
            for path in sorted((ROOT/folder).rglob('*')):
                if path.is_file() and not path.is_symlink():
                    tf.add(path,arcname=str(path.relative_to(ROOT)),recursive=False)
    return b.getvalue()

def _upload(t, remote, content, mode=0o600):
    sftp=paramiko.SFTPClient.from_transport(t)
    try:
        with sftp.file(remote,'wb') as f:
            f.write(content)
        sftp.chmod(remote,mode)
    finally:
        sftp.close()

def check_credentials(ip,port,password,expected_fp):
    """Do not create a database node for bad SSH credentials."""
    t=None
    try:
        t=transport(ip,port)
        if fingerprint(t.get_remote_server_key())!=expected_fp:
            raise RuntimeError('SSH host key is different. Verify fingerprint in VPS console.')
        try:
            t.auth_password('root',password,fallback=False)
        except paramiko.AuthenticationException:
            raise ValueError('SSH authentication failed: check root password, PermitRootLogin and PasswordAuthentication on this VPS.')
        if not t.is_authenticated():
            raise ValueError('SSH authentication failed: root password login denied.')
        ch=t.open_session(timeout=12)
        ch.exec_command('id -u')
        data=ch.recv(200).decode(errors='replace').strip()
        rc=ch.recv_exit_status()
        ch.close()
        if rc!=0 or data!='0':
            raise ValueError('SSH user must have UID 0 for first-time installation.')
        return True
    finally:
        if t:t.close()

def bootstrap(node_id, ip, port, password, expected_fp, token, helper_key, hub_url):
    t=None
    def info(msg):store.log_install(node_id,msg)
    def clean(chunk):
        # No secrets may enter the installation log, including environment dumps.
        text=chunk.decode(errors='replace')
        for secret in (password,token,helper_key):
            if secret: text=text.replace(secret,'[REDACTED]')
        import re
        text=re.sub(r'(?im)((?:SECRET_KEY|PANEL_API_TOKEN|XPPN_AGENT_TOKEN|XPPN_HELPER_KEY)\s*[=:]\s*)[^\s]+',r'\1[REDACTED]',text)
        return text
    try:
        info('Подключение к VPS по SSH…')
        t=transport(ip,port)
        actual=fingerprint(t.get_remote_server_key())
        if actual!=expected_fp:raise RuntimeError('SSH host key changed; installation cancelled.')
        try:t.auth_password('root',password,fallback=False)
        except paramiko.AuthenticationException:raise RuntimeError('SSH root authentication failed; check SSH password and root login settings.')
        if not t.is_authenticated():raise RuntimeError('SSH password authentication failed.')
        info('SSH авторизация успешна. Проверяем подготовку VPS…')
        archive=f'/root/.xppn-agent-{node_id}.tar.gz'
        secrets_file=f'/root/.xppn-agent-{node_id}.env'
        helper_key_file=f'/root/.xppn-helper-{node_id}.key'
        env=f'XPPN_HUB_URL={hub_url}\nXPPN_NODE_ID={node_id}\nXPPN_AGENT_TOKEN={token}\n'
        _upload(t,archive,_archive())
        _upload(t,secrets_file,env.encode())
        _upload(t,helper_key_file,(helper_key+'\n').encode())
        info('Архив XPPN Agent передан на сервер. Устанавливаем зависимости…')
        cmd=f'XPPN_PACKAGE={archive} XPPN_INPUT_ENV={secrets_file} XPPN_HELPER_KEY={helper_key_file} bash -s'
        channel=t.open_session(timeout=20)
        channel.settimeout(1200)
        channel.exec_command(cmd)
        channel.sendall((ROOT/'bootstrap'/'install.sh').read_bytes())
        channel.shutdown_write()
        recent='';logbuf='';last_flush=time.monotonic();deadline=time.monotonic()+1200
        while not channel.exit_status_ready() or channel.recv_ready() or channel.recv_stderr_ready():
            if time.monotonic()>deadline:
                channel.close()
                raise RuntimeError('Bootstrap timed out after 20 minutes. Last output: '+recent[-650:])
            for method in (channel.recv, channel.recv_stderr):
                ready = channel.recv_ready if method == channel.recv else channel.recv_stderr_ready
                if ready():
                    chunk=clean(method(16384))
                    recent=(recent+chunk)[-12000:]
                    # apt/dpkg prints progress with carriage returns: normalize and bound.
                    logbuf+=(chunk.replace('\r','\n'))
                    if len(logbuf)>16000:logbuf=logbuf[-16000:]
            if logbuf and (time.monotonic()-last_flush>0.8 or len(logbuf)>2800):
                info(logbuf[-2900:])
                logbuf='';last_flush=time.monotonic()
            time.sleep(.12)
        if logbuf:info(logbuf[-2900:])
        rc=channel.recv_exit_status()
        if rc:
            raise RuntimeError(f'Bootstrap exit code {rc}; last output: '+recent[-650:].replace('\r','\n'))
        info('Агент установлен. Ожидаем первого подключения к панели…')
        with store.connect() as c:
            c.execute("UPDATE nodes SET stage='waiting',error='' WHERE id=?",(node_id,))
            c.execute('INSERT INTO audit VALUES(?,?,?)',(int(time.time()),'bootstrap',f'{node_id} completed'))
    except Exception as e:
        safe=str(e)
        for secret in (password,token,helper_key):
            if secret:safe=safe.replace(secret,'[REDACTED]')
        info('ОШИБКА: '+safe[-700:])
        with store.connect() as c:
            c.execute("UPDATE nodes SET stage='failed',error=?,pending_install_enc='' WHERE id=?",(safe[-500:],node_id))
    finally:
        if t:
            try:
                if t.is_authenticated():
                    ch=t.open_session(timeout=5)
                    ch.exec_command(f'rm -f -- /root/.xppn-agent-{node_id}.tar.gz /root/.xppn-agent-{node_id}.env /root/.xppn-helper-{node_id}.key')
                    ch.recv_exit_status();ch.close()
            except Exception:pass
            t.close()
