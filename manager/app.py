"""XPPN Manager: SSH enrollment + strictly typed remote jobs."""
import hashlib
import ipaddress
import json
import os
import re
import secrets
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

from argon2 import PasswordHasher, exceptions as argon_exc
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import store, sshbootstrap, projects, remna_api

APP_SECRET=os.environ.get('XPPN_SESSION_SECRET','')
if len(APP_SECRET)<32: raise RuntimeError('Set XPPN_SESSION_SECRET (32+ characters)')
HUB_URL=os.getenv('XPPN_PUBLIC_URL','')
if HUB_URL and (urlparse(HUB_URL).scheme!='https' or not urlparse(HUB_URL).hostname):
    raise RuntimeError('XPPN_PUBLIC_URL must be an HTTPS URL')
store.init_db()
app=FastAPI(title='XPPN Manager', docs_url=None, redoc_url=None, openapi_url=None)

@app.on_event('startup')
def maintenance_startup():
    from .maintenance import start_maintenance
    start_maintenance()

app.add_middleware(SessionMiddleware, secret_key=APP_SECRET, same_site='strict', https_only=os.getenv('XPPN_SECURE_COOKIES','true')=='true', max_age=2592000)
allowed=[s.strip() for s in os.getenv('XPPN_ALLOWED_HOSTS','localhost,127.0.0.1').split(',') if s.strip()]
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed)
executor=ThreadPoolExecutor(max_workers=2)
ph=PasswordHasher()

class Login(BaseModel):
    username: str=Field(min_length=1,max_length=80)
    password: str=Field(min_length=1,max_length=1024)
class Probe(BaseModel):
    ip: str
    port: int=Field(default=22,ge=1,le=65535)
class ReadOnlyPreflight(Probe):
    password: str=Field(min_length=1,max_length=1024)
    fingerprint: str=Field(pattern=r'^SHA256:[A-Za-z0-9+/]{43}$')

class Enroll(Probe):
    project_id: str="default"
    profile_id: str=""
    preset: str=Field(default="agent",pattern=r"^(agent|node|full)$")
    version: str=Field(default="3.4.2",pattern=r"^\d+\.\d+\.\d+$")
    panel_ip: str=""
    secret_key: str=""
    domain: str=""
    confirm_panel_dns_as_egress: bool=False
    country_code: str=Field(default='XX',pattern=r'^[A-Z]{2}$')
    confirm_clean: bool=False
    logs_preset: str=Field(default='standard',pattern=r'^(standard|compact|archive)$')
    name: str=Field(min_length=1,max_length=48)
    password: str=Field(min_length=1,max_length=1024)
    fingerprint: str=Field(pattern=r'^SHA256:[A-Za-z0-9+/]{43}$')
class ProjectBody(BaseModel):
    name: str=Field(min_length=1,max_length=80)
    panel_url: str=''
    panel_ip: str=''
    secret_key: str=''
    api_token: str=''
    clear_secret_key: bool=False
    clear_api_token: bool=False

class PanelDefaultsBody(BaseModel):
    config_profile_uuid: str=Field(min_length=36,max_length=36)
    active_inbounds: list[str]=Field(min_length=1,max_length=30)
    country_code: str=Field(default='XX',pattern=r'^[A-Z]{2}$')

class RegisterPanelNode(BaseModel):
    config_profile_uuid: str=Field(min_length=16,max_length=64)
    active_inbounds: list[str]=Field(min_length=1,max_length=30)
    country_code: str=Field(pattern=r'^[A-Z]{2}$')

class ProfileBody(BaseModel):
    name: str=Field(min_length=1,max_length=80)
    mode: str
    transport: str
    settings: dict=Field(default_factory=dict)

class JobBody(BaseModel):
    command: str
    payload: dict=Field(default_factory=dict)
class AgentResult(BaseModel):
    job_id: str
    success: bool
    output: str=Field(default='',max_length=130000)
class Progress(BaseModel):
    job_id: str
    message: str=Field(min_length=1,max_length=500)
class Heartbeat(BaseModel):
    telemetry: dict=Field(default_factory=dict)

ALL_COMMANDS={'logs.read','logs.policy','status','docker.action','docker.logs','config.read','config.write','node.deploy','node.upgrade','node.install','ssl.renew','legacy.install','network.status','network.bbr','project.node.install','project.stack.install'}
CONFIGS={'nginx','nginx_compose','node_compose'}
ALLOWED_CONTAINERS={'nginx','remnanode'}

@app.middleware('http')
async def security_headers(request, call_next):
    if request.url.path.startswith('/api/') and request.method not in ('GET','HEAD') and not request.url.path.startswith('/api/agent/'):
        origin=request.headers.get('origin')
        if origin and origin != (HUB_URL if HUB_URL else f'{request.url.scheme}://{request.headers.get("host","")}'):
            return FileResponse(str(Path(__file__).parent/'static/forbidden.txt'),status_code=403)
    resp=await call_next(request)
    resp.headers['X-Content-Type-Options']='nosniff'
    resp.headers['Referrer-Policy']='no-referrer'
    resp.headers['X-Frame-Options']='DENY'
    resp.headers['Content-Security-Policy']="default-src 'self'; connect-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    resp.headers['Cache-Control']='no-store'
    return resp

def admin(request:Request):
    if not request.session.get('authenticated'):
        raise HTTPException(401,'Authentication required')
    return True

def write_access(request:Request, ok=Depends(admin)):
    token=request.headers.get('X-CSRF-Token','')
    if not token or not secrets.compare_digest(token,request.session.get('csrf','')):
        raise HTTPException(403,'CSRF validation failed')
    return True

def agent_auth(request:Request, node_id:str):
    bearer=request.headers.get('Authorization','')
    if not bearer.startswith('Bearer ') or not store.auth_node(node_id,bearer[7:]):
        raise HTTPException(401,'Agent authentication failed')
    return True

def verify_ip(ip:str):
    try: addr=ipaddress.ip_address(ip)
    except ValueError: raise HTTPException(400,'Specify a numeric IPv4/IPv6 address')
    if not addr.is_global and os.getenv('XPPN_ALLOW_PRIVATE_SSH')!='true':
        raise HTTPException(400,'Only publicly routable IPs allowed by default')
    return str(addr)

def attempts(ip,limit=6):
    now=int(time.time())
    with store.connect() as c:
        c.execute('DELETE FROM attempts WHERE ts<?',(now-900,))
        count=c.execute('SELECT count(*) AS n FROM attempts WHERE ip=?',(ip,)).fetchone()['n']
        if count>=limit: raise HTTPException(429,'Too many attempts')
        c.execute('INSERT INTO attempts VALUES(?,?)',(ip,now))

@app.get('/')
def index(): return FileResponse(str(Path(__file__).parent/'static/index.html'))
app.mount('/assets',StaticFiles(directory=str(Path(__file__).parent/'static')),name='assets')

@app.get('/api/me')
def me(request:Request):
    return {'authenticated':bool(request.session.get('authenticated')),'csrf':request.session.get('csrf') if request.session.get('authenticated') else None,'hub_configured':bool(HUB_URL),'user':request.session.get('user') if request.session.get('authenticated') else None}

@app.post('/api/login')
def login(data:Login, request:Request):
    with store.connect() as c:
        row=c.execute('SELECT * FROM admins LIMIT 1').fetchone()
    if not row: raise HTTPException(503,'Initialize an admin account from the server console')
    good=False
    try: good=ph.verify(row['password_hash'],data.password)
    except (argon_exc.VerifyMismatchError,argon_exc.InvalidHashError): pass
    if not good or not secrets.compare_digest(row['username'],data.username):
        raise HTTPException(401,'Неверный логин или пароль')
    request.session.clear()
    request.session['authenticated']=True
    request.session['user']=row['username']
    request.session['csrf']=secrets.token_urlsafe(32)
    return {'ok':True,'csrf':request.session['csrf']}

@app.post('/api/logout')
def logout(request:Request, _=Depends(write_access)):
    request.session.clear()
    return {'ok':True}

@app.post('/api/projects/{pid}/panel/sync')
def panel_sync(pid:str,_=Depends(write_access)):
    """Validate API credentials + fetch panel key without sending it to browser."""
    try:
        profiles=remna_api.get_profiles(pid)
        key=remna_api.get_node_public_key(pid)
    except remna_api.PanelError as e:raise HTTPException(502,str(e))
    with store.connect() as c:
        c.execute('UPDATE projects SET secret_key_enc=?,updated_at=? WHERE id=?',
                  (projects._encrypt_secret(key, max_length=32768),int(time.time()),pid))
        c.execute('INSERT INTO audit VALUES(?,?,?)',(int(time.time()),'panel.sync',pid))
    return {'ok':True,'has_node_key':True,'profiles':profiles}

@app.put('/api/projects/{pid}/panel/defaults')
def panel_defaults(pid:str,body:PanelDefaultsBody,_=Depends(write_access)):
    try:
        all_profiles=remna_api.get_profiles(pid)
        remna_api.validate_selection(all_profiles,body.config_profile_uuid,body.active_inbounds)
    except remna_api.PanelError as e:raise HTTPException(422,str(e))
    with store.connect() as c:
        if not c.execute('SELECT 1 FROM projects WHERE id=?',(pid,)).fetchone():
            raise HTTPException(404,'Проект не найден')
        c.execute('UPDATE projects SET panel_config_profile_uuid=?,panel_active_inbounds=?,panel_country_code=?,updated_at=? WHERE id=?',
                  (body.config_profile_uuid,json.dumps(body.active_inbounds),body.country_code,int(time.time()),pid))
        c.execute('INSERT INTO audit VALUES(?,?,?)',(int(time.time()),'panel.defaults',pid))
    return {'ok':True}

@app.get('/api/projects/{pid}/panel/profiles')
def remote_config_profiles(pid:str,_=Depends(admin)):
    try:return remna_api.get_profiles(pid)
    except remna_api.PanelError as e:raise HTTPException(502,str(e))

@app.post('/api/nodes/{node_id}/panel/register')
def register_remote_node(node_id:str,body:RegisterPanelNode,_=Depends(write_access)):
    with store.connect() as c:
        row=c.execute('SELECT id,name,ip,stage,project_id,domain,panel_node_uuid FROM nodes WHERE id=?',(node_id,)).fetchone()
    if not row:raise HTTPException(404,'Нода не найдена')
    if row['stage'] not in ('ready','registration_failed'):raise HTTPException(409,'Регистрация доступна после успешной установки VPS')
    with store.connect() as c:
        telemetry_row=c.execute('SELECT telemetry,last_seen FROM nodes WHERE id=?',(node_id,)).fetchone()
    if not telemetry_row or int(time.time())-telemetry_row['last_seen']>120 or not component_inventory(json.loads(telemetry_row['telemetry']))['remnanode']['running']:
        raise HTTPException(409,'Remnawave Node не обнаружена или не запущена на VPS')

    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        claimed=c.execute("UPDATE nodes SET panel_registering=1 WHERE id=? AND panel_registering=0 AND panel_node_uuid='' AND stage IN ('ready','registration_failed')",(node_id,))
        if claimed.rowcount!=1:
            c.execute('ROLLBACK')
            raise HTTPException(409,'Нода уже зарегистрирована или регистрация выполняется')
        c.execute('COMMIT')
    addr=row['domain'] or row['ip']
    try:
        panel_uuid=remna_api.register_node(row['project_id'],row['name'][:30],addr,body.country_code,
                                           body.config_profile_uuid,body.active_inbounds)
    except remna_api.PanelError as e:
        with store.connect() as c:
            c.execute('UPDATE nodes SET panel_registering=0 WHERE id=?',(node_id,))
        raise HTTPException(502,str(e))
    except Exception:
        with store.connect() as c:
            c.execute('UPDATE nodes SET panel_registering=0 WHERE id=?',(node_id,))
        raise HTTPException(502,'Неожиданная ошибка API. Проверь состояние панели перед повтором')
    with store.connect() as c:
        c.execute("UPDATE nodes SET panel_node_uuid=?,panel_registering=0,stage='ready',error='' WHERE id=?",(panel_uuid,node_id))
        c.execute('INSERT INTO audit VALUES(?,?,?)',(int(time.time()),'panel.node.register',node_id))
    return {'ok':True,'panel_node_uuid':panel_uuid}

def auto_register_after_install(node_id):
    """One attempt only; interrupted/ambiguous remote writes require manual reconciliation."""
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        claimed=c.execute("UPDATE nodes SET panel_registering=1,panel_register_started_at=? WHERE id=? AND stage='registering' AND panel_registering=0 AND panel_node_uuid=''",(int(time.time()),node_id))
        if claimed.rowcount!=1:
            c.execute('COMMIT');return
        r=c.execute('SELECT * FROM nodes WHERE id=?',(node_id,)).fetchone()
        c.execute('COMMIT')
    try:
        uuid_value=remna_api.register_node(r['project_id'],r['name'][:30],r['domain'] or r['ip'],r['panel_auto_country'],
                                            r['panel_auto_profile_uuid'],json.loads(r['panel_auto_inbounds']))
    except remna_api.PanelError as e:
        # Includes duplicate / unclear response: do not retry automatically.
        with store.connect() as c:
            c.execute("UPDATE nodes SET stage='registration_failed',panel_registering=0,error=? WHERE id=? AND stage='registering'",(str(e)[:350],node_id))
        store.log_install(node_id,'Регистрация в Remnawave не завершена: '+str(e)[:350]+'. Проверь панель перед повтором.')
        return
    except Exception:
        with store.connect() as c:
            c.execute("UPDATE nodes SET stage='registration_failed',panel_registering=0,error=? WHERE id=? AND stage='registering'",('Неизвестная ошибка API; проверь панель перед повтором',node_id))
        store.log_install(node_id,'Регистрация прервана. Проверь, не появилась ли нода в панели, прежде чем повторять.')
        return
    with store.connect() as c:
        c.execute("UPDATE nodes SET panel_node_uuid=?,panel_registering=0,stage='ready',error='' WHERE id=? AND stage='registering'",(uuid_value,node_id))
        c.execute('INSERT INTO audit VALUES(?,?,?)',(int(time.time()),'panel.auto-register',node_id))
    store.log_install(node_id,'Нода зарегистрирована в панели Remnawave. UUID: '+uuid_value+'; установка завершена.')

@app.get('/api/transports')
def transports(_=Depends(admin)):
    return [{'id':k,**v} for k,v in projects.TRANSPORTS.items()]

@app.get('/api/projects')
def list_projects(_=Depends(admin)):
    with store.connect() as c:
        rows=c.execute('SELECT * FROM projects ORDER BY created_at,id').fetchall()
    return [projects.project_view(r) for r in rows]

@app.post('/api/projects')
def create_project(body:ProjectBody,_=Depends(write_access)):
    try:pid=projects.create_project(body.model_dump())
    except ValueError as e:raise HTTPException(422,str(e))
    except store.sqlite3.IntegrityError:raise HTTPException(409,'Название проекта уже используется')
    return {'id':pid}

@app.patch('/api/projects/{pid}')
def update_project(pid:str,body:ProjectBody,_=Depends(write_access)):
    try:projects.update_project(pid,body.model_dump())
    except LookupError:raise HTTPException(404,'Проект не найден')
    except ValueError as e:raise HTTPException(422,str(e))
    except store.sqlite3.IntegrityError:raise HTTPException(409,'Название проекта уже используется')
    return {'ok':True}

@app.get('/api/projects/{pid}/profiles')
def profiles_for_project(pid:str,_=Depends(admin)):
    with store.connect() as c:
        if not c.execute('SELECT id FROM projects WHERE id=?',(pid,)).fetchone():raise HTTPException(404,'Проект не найден')
        rows=c.execute('SELECT * FROM deployment_profiles WHERE project_id=? ORDER BY created_at,name',(pid,)).fetchall()
    return [projects.profile_view(r) for r in rows]

@app.post('/api/projects/{pid}/profiles')
def create_profile(pid:str,body:ProfileBody,_=Depends(write_access)):
    try:fid=projects.add_profile(pid,body.model_dump())
    except LookupError:raise HTTPException(404,'Проект не найден')
    except ValueError as e:raise HTTPException(422,str(e))
    except store.sqlite3.IntegrityError:raise HTTPException(409,'Название шаблона уже используется')
    return {'id':fid}

@app.put('/api/profiles/{fid}')
def edit_profile(fid:str,body:ProfileBody,_=Depends(write_access)):
    try:projects.update_profile(fid,body.model_dump())
    except LookupError:raise HTTPException(404,'Шаблон не найден')
    except ValueError as e:raise HTTPException(422,str(e))
    except store.sqlite3.IntegrityError:raise HTTPException(409,'Название шаблона уже используется')
    return {'ok':True}

@app.get('/api/profiles/{fid}/preview')
def preview_profile(fid:str,domain:str='',_=Depends(admin)):
    with store.connect() as c:
        row=c.execute('SELECT * FROM deployment_profiles WHERE id=?',(fid,)).fetchone()
    if not row:raise HTTPException(404,'Шаблон не найден')
    try:return projects.profile_preview(projects.profile_view(row),domain.strip().lower())
    except ValueError as e:raise HTTPException(422,str(e))

def component_inventory(telemetry):
    """Observed host state. Unknown is distinct from missing/offline."""
    if not isinstance(telemetry,dict): telemetry={}
    files=telemetry.get('files') or {}
    containers=telemetry.get('containers') or []
    if not isinstance(files,dict):files={}
    if not isinstance(containers,list):containers=[]
    by_name={}
    for row in containers:
        if not isinstance(row,dict):continue
        # Docker ps JSON has Names (often comma-separated), State, Status, Image.
        for name in str(row.get('Names','')).split(','):
            n=name.strip().lstrip('/')
            if n in ('nginx','remnanode'):
                by_name[n]={'present':True,'running':str(row.get('State','')).lower()=='running' or str(row.get('Status','')).lower().startswith('up '),'image':str(row.get('Image',''))[:180], 'status':str(row.get('Status',''))[:120]}
    result={}
    for component, config in [('nginx','nginx_compose'),('remnanode','node_compose')]:
        entry=by_name.get(component,{})
        result[component]={'installed':bool(entry or files.get(config)),'running':entry.get('running',False),'compose':files.get(config) is True,'container':bool(entry),'image':entry.get('image',''),'status':entry.get('status','')}
    result['agent']={'installed':bool(telemetry.get('hostname')),'running':bool(telemetry.get('hostname'))}
    result['configs']={k:bool(files.get(k)) for k in ('nginx','nginx_compose','node_compose')}
    result['docker']={'available':isinstance(containers,list) and 'docker_error' not in telemetry,'containers':len(containers)}
    return result


def require_component_command(command,payload,node):
    """Server-side authorization by *actual* components, not a client-provided preset."""
    if not isinstance(node.get('telemetry'),str) or not node.get('last_seen') or int(time.time())-node['last_seen']>120:
        raise HTTPException(409,'Агент не отвечает или состояние устарело. Дождись обновления телеметрии.')
    try: tele=json.loads(node['telemetry'])
    except (TypeError,ValueError):raise HTTPException(409,'Телеметрия недоступна')
    inv=component_inventory(tele)
    features=tele.get('capabilities')
    if command in ('network.status','network.bbr') and (not isinstance(features,list) or command not in features):
        raise HTTPException(409,'Установлен старый XPPN Agent. Обнови агент на VPS перед использованием этой функции.')
    if command in ('docker.action','docker.logs'):
        if not inv[payload['container']]['container']:
            raise HTTPException(409,'Контейнер не установлен. Сначала установи компонент.')
    if command in ('config.read','config.write') and not inv['configs'][payload['name']]:
        raise HTTPException(409,'Этот конфиг отсутствует на VPS')
    if command in ('node.upgrade','node.deploy') and not inv['remnanode']['compose']:
        raise HTTPException(409,'Remnawave Node не установлена')
    if command=='ssl.renew' and not inv['nginx']['installed']:
        raise HTTPException(409,'Сначала установи Nginx и SSL')
    if command in ('node.install','project.node.install') and inv['remnanode']['installed']:
        raise HTTPException(409,'Нода уже установлена. Используй обновление или управление компонентами.')
    if command in ('legacy.install','project.stack.install') and (inv['remnanode']['installed'] or inv['nginx']['installed']):
        raise HTTPException(409,'На VPS уже есть Remnawave/Nginx. Полный старый установщик запрещён; установка поверх может повредить конфиги. Используй существующие компоненты либо отдельный чистый VPS.')
    return inv


class CredentialChange(BaseModel):
    current_password: str = Field(min_length=1,max_length=1024)
    username: str = Field(pattern=r'^[A-Za-z0-9_.-]{3,40}$')
    new_password: str = Field(min_length=1,max_length=1024)

@app.get('/api/settings/status')
def settings_status(request:Request,_=Depends(admin)):
    folder=Path('/data/backups')
    items=sorted(folder.glob('xppn-manager-*.sqlite3'),reverse=True) if folder.is_dir() else []
    return {'username':request.session.get('user','admin'),
            'telegram_configured':bool(os.getenv('XPPN_ALERT_BOT_TOKEN') and os.getenv('XPPN_ALERT_CHAT_ID')),
            'updates_enabled':os.getenv('XPPN_UPDATE_ENABLED','false')=='true',
            'backup_count':len(items),'latest_backup':items[0].name if items else None,
            'session_days':30,'history_days':30}

@app.post('/api/settings/backup')
def backup_now(_=Depends(write_access)):
    from .maintenance import backup_sqlite_once
    try:
        path=backup_sqlite_once(force=True)
    except (OSError,RuntimeError) as e:
        raise HTTPException(500,'Backup failed; check manager disk and service logs') from e
    with store.connect() as c:c.execute('INSERT INTO audit VALUES(?,?,?)',(int(time.time()),'manager.backup',path.name))
    return {'backup':path.name,'status':'success'}

@app.post('/api/settings/credentials')
def change_credentials(body:CredentialChange,request:Request,_=Depends(write_access)):
    with store.connect() as c:
        row=c.execute('SELECT id,password_hash FROM admins LIMIT 1').fetchone()
    if not row:raise HTTPException(503,'Admin not initialized')
    try:ph.verify(row['password_hash'],body.current_password)
    except (argon_exc.VerifyMismatchError,argon_exc.VerificationError,argon_exc.InvalidHashError):
        raise HTTPException(403,'Current password incorrect')
    with store.connect() as c:
        c.execute('UPDATE admins SET username=?,password_hash=? WHERE id=?',(body.username,ph.hash(body.new_password),row['id']))
        c.execute('INSERT INTO audit VALUES(?,?,?)',(int(time.time()),'manager.credentials.changed',body.username))
    request.session['user']=body.username
    return {'ok':True,'username':body.username}

@app.get('/api/updates/status')
def update_status(_=Depends(admin)):
    enabled=os.getenv('XPPN_UPDATE_ENABLED','false')=='true'
    report=Path('/data/update-status.json')
    result={'enabled':enabled,'status':'not_configured' if not enabled else 'idle','detail':''}
    if report.is_file():
        try:
            item=json.loads(report.read_text()[:4096])
            result.update({'status':str(item.get('status','unknown'))[:40],
                           'detail':str(item.get('detail',''))[:450],
                           'commit':str(item.get('commit',''))[:40]})
        except Exception:result['detail']='Update status is unreadable'
    return result

@app.post('/api/updates/request')
def update_request(_=Depends(write_access)):
    if os.getenv('XPPN_UPDATE_ENABLED','false')!='true':
        raise HTTPException(503,'Install and enable the host updater first')
    filename=Path('/data/update-request.json')
    if filename.exists():raise HTTPException(409,'Update already pending')
    rid=str(uuid.uuid4())
    payload={'id':rid,'requested_at':int(time.time())}
    path=Path('/data/update-request.'+rid+'.tmp')
    try:
        with path.open('x') as f:f.write(json.dumps(payload))
        os.replace(path,filename)
    finally:path.unlink(missing_ok=True)
    with store.connect() as c:
        c.execute('INSERT INTO audit VALUES(?,?,?)',(int(time.time()),'manager.update.request',rid))
    return {'id':rid,'status':'queued'}

@app.get('/api/nodes')
def nodes(_=Depends(admin)):
    with store.connect() as c:
        rows=c.execute('SELECT id,name,ip,preset,stage,last_seen,telemetry,created_at,error,project_id,profile_id,profile_snapshot,domain,panel_node_uuid FROM nodes ORDER BY created_at DESC').fetchall()
    now=int(time.time())
    return [{**dict(r),'online':bool(now-r['last_seen']<65),'telemetry':json.loads(r['telemetry']),'components':component_inventory(json.loads(r['telemetry'])) if now-r['last_seen']<120 else {},'profile_snapshot':json.loads(r['profile_snapshot'])} for r in rows]

class BatchPolicy(BaseModel):
    node_ids: list[str] = Field(min_length=1, max_length=60)
    preset: str = Field(pattern=r'^(compact|standard|archive)$')

@app.post('/api/nodes/batch/log-policy')
def batch_log_policy(body: BatchPolicy, _=Depends(write_access)):
    # Keep bulk changes constrained to a single, typed, low-impact operation.
    # A failed/offline node remains unchanged; user gets per-node details.
    if len(body.node_ids)!=len(set(body.node_ids)):
        raise HTTPException(422,'Duplicate node IDs')
    now=int(time.time())
    results=[]
    for node_id in body.node_ids:
        with store.connect() as c:
            row=c.execute('SELECT name,stage,last_seen,telemetry FROM nodes WHERE id=?',(node_id,)).fetchone()
            if not row:
                results.append({'node_id':node_id,'status':'skipped','reason':'Not found'});continue
            if row['stage']!='ready' or now-row['last_seen']>90:
                results.append({'node_id':node_id,'name':row['name'],'status':'skipped','reason':'Offline / not ready'});continue
            try:cap=json.loads(row['telemetry']).get('capabilities',[])
            except (ValueError,TypeError):cap=[]
            if 'logs.policy' not in cap:
                results.append({'node_id':node_id,'name':row['name'],'status':'skipped','reason':'Upgrade the agent'});continue
            active=c.execute("SELECT count(*) FROM jobs WHERE node_id=? AND status IN ('queued','running')",(node_id,)).fetchone()[0]
            if active>=15:
                results.append({'node_id':node_id,'name':row['name'],'status':'skipped','reason':'Queue full'});continue
        jid=str(uuid.uuid4())
        store.queue_job(node_id,jid,'logs.policy',{'preset':body.preset})
        results.append({'node_id':node_id,'name':row['name'],'status':'queued','id':jid})
    return {'results':results}

@app.get('/api/nodes/{node_id}/metrics')
def metrics(node_id:str,hours:int=24,_=Depends(admin)):
    if hours not in (24,168,720):raise HTTPException(422,'Select 24, 168 or 720 hours')
    with store.connect() as c:
        if not c.execute('SELECT 1 FROM nodes WHERE id=?',(node_id,)).fetchone():raise HTTPException(404,'Node not found')
        rows=c.execute('SELECT ts,load1,cpu_percent,mem_percent,disk_percent,net_rx,net_tx FROM telemetry_history WHERE node_id=? AND ts>=? ORDER BY ts',
                       (node_id,int(time.time())-hours*3600)).fetchall()
    step=max(1,len(rows)//280)
    return [dict(r) for r in rows[::step]][-300:]

@app.get('/api/nodes/{node_id}/jobs')
def jobs(node_id:str,_=Depends(admin)):
    with store.connect() as c:
        rows=c.execute('SELECT id,command,status,output,created_at,updated_at FROM jobs WHERE node_id=? ORDER BY created_at DESC LIMIT 30',(node_id,)).fetchall()
    return [dict(r) for r in rows]


# The manager is the canonical editor. Import remote configs only on explicit request,
# then keep encrypted revisions locally. Remote SHA guards against out-of-band edits.
CONFIG_PATTERN = re.compile(r'^[a-f0-9]{64}$')

class DraftConfig(BaseModel):
    content: str = Field(max_length=100000)
    revision: int = Field(ge=0)


def _config_node(node_id):
    with store.connect() as c:
        node=c.execute('SELECT stage,last_seen,telemetry FROM nodes WHERE id=?',(node_id,)).fetchone()
    if not node:raise HTTPException(404,'Node not found')
    return dict(node)


def _config_record(node_id,name):
    if name not in CONFIGS:raise HTTPException(422,'Unknown config')
    with store.connect() as c:
        row=c.execute('SELECT * FROM managed_configs WHERE node_id=? AND name=?',(node_id,name)).fetchone()
    if not row:return None
    d=dict(row)
    encrypted=d.pop('content_enc')
    d['content']=store.FERNET.decrypt(encrypted.encode()).decode() if encrypted else ''
    return d

@app.get('/api/nodes/{node_id}/configs')
def stored_configs(node_id:str,_=Depends(admin)):
    _config_node(node_id)
    with store.connect() as c:
        return [{k:r[k] for k in ('name','revision','remote_sha','status','last_job_id','updated_at')}
                for r in c.execute('SELECT * FROM managed_configs WHERE node_id=? ORDER BY name',(node_id,))]

@app.get('/api/nodes/{node_id}/configs/{name}')
def stored_config(node_id:str,name:str,_=Depends(admin)):
    _config_node(node_id)
    row=_config_record(node_id,name)
    if not row:raise HTTPException(404,'Import config from node once first')
    return row

@app.post('/api/nodes/{node_id}/configs/{name}/import')
def import_config(node_id:str,name:str,_=Depends(write_access)):
    if name not in CONFIGS:raise HTTPException(422,'Unknown config')
    node=_config_node(node_id)
    if node['stage']!='ready' or time.time()-node['last_seen']>90:raise HTTPException(409,'Node is offline')
    inv=component_inventory(json.loads(node['telemetry']))
    if not inv['configs'].get(name):raise HTTPException(409,'Config is absent on node')
    with store.connect() as c:
        rec=c.execute('SELECT revision,status FROM managed_configs WHERE node_id=? AND name=?',(node_id,name)).fetchone()
        if rec and rec['status'] in ('draft','applying'):
            raise HTTPException(409,'First apply or resolve the stored draft')
        jid=str(uuid.uuid4())
        store.queue_job(node_id,jid,'config.read',{'name':name})
        c.execute('INSERT INTO managed_configs(node_id,name,status,last_job_id,updated_at) VALUES(?,?,?,?,?) '
                  'ON CONFLICT(node_id,name) DO UPDATE SET status=excluded.status,last_job_id=excluded.last_job_id,updated_at=excluded.updated_at',
                  (node_id,name,'importing',jid,int(time.time())))
    return {'id':jid,'status':'importing'}

@app.put('/api/nodes/{node_id}/configs/{name}')
def save_draft(node_id:str,name:str,body:DraftConfig,_=Depends(write_access)):
    if name not in CONFIGS or '\x00' in body.content:raise HTTPException(422,'Invalid config')
    now=int(time.time())
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute('SELECT revision,remote_sha,status FROM managed_configs WHERE node_id=? AND name=?',(node_id,name)).fetchone()
        if not row or not row['remote_sha']:
            c.execute('ROLLBACK');raise HTTPException(409,'Import this config from the node first')
        if row['revision']!=body.revision or row['status'] in ('importing','applying'):
            c.execute('ROLLBACK');raise HTTPException(409,'Revision changed or config is currently applying')
        rev=row['revision']+1
        token=store.FERNET.encrypt(body.content.encode()).decode()
        c.execute('UPDATE managed_configs SET content_enc=?,revision=?,status=?,updated_at=? WHERE node_id=? AND name=?',
                  (token,rev,'draft',now,node_id,name))
        c.execute('INSERT INTO config_versions(node_id,name,revision,content_enc,created_at) VALUES(?,?,?,?,?)',
                  (node_id,name,rev,token,now))
        c.execute('COMMIT')
    return {'revision':rev,'status':'draft'}

@app.get('/api/nodes/{node_id}/configs/{name}/history')
def config_history(node_id:str,name:str,_=Depends(admin)):
    if name not in CONFIGS:raise HTTPException(422,'Unknown config')
    _config_node(node_id)
    with store.connect() as c:
        return [dict(r) for r in c.execute('SELECT id,revision,created_at FROM config_versions WHERE node_id=? AND name=? ORDER BY id DESC LIMIT 30',(node_id,name))]

@app.post('/api/nodes/{node_id}/configs/{name}/restore/{revision}')
def config_restore(node_id:str,name:str,revision:int,_=Depends(write_access)):
    if name not in CONFIGS:raise HTTPException(422,'Unknown config')
    with store.connect() as c:
        ver=c.execute('SELECT content_enc FROM config_versions WHERE node_id=? AND name=? AND revision=? ORDER BY id DESC LIMIT 1',(node_id,name,revision)).fetchone()
        old=c.execute('SELECT revision,status FROM managed_configs WHERE node_id=? AND name=?',(node_id,name)).fetchone()
    if not ver or not old:raise HTTPException(404,'Revision unavailable')
    return save_draft(node_id,name,DraftConfig(content=store.FERNET.decrypt(ver['content_enc']).decode(),revision=old['revision']),True)

@app.post('/api/nodes/{node_id}/configs/{name}/apply')
def apply_draft(node_id:str,name:str,_=Depends(write_access)):
    node=_config_node(node_id)
    if node['stage']!='ready' or time.time()-node['last_seen']>90:raise HTTPException(409,'Node is offline')
    row=_config_record(node_id,name)
    if not row or not row['remote_sha'] or row['status'] in ('applying','importing'):
        raise HTTPException(409,'Nothing to apply or a job is already in progress')
    if not CONFIG_PATTERN.fullmatch(row['remote_sha']):raise HTTPException(409,'Invalid saved remote digest')
    with store.connect() as c:
        queued=c.execute("SELECT count(*) AS n FROM jobs WHERE node_id=? AND status IN ('running','queued')",(node_id,)).fetchone()['n']
    if queued>=15:raise HTTPException(429,'Job queue full')
    jid=str(uuid.uuid4())
    store.queue_job(node_id,jid,'config.write',{'name':name,'content':row['content'],'sha256':row['remote_sha']})
    with store.connect() as c:
        c.execute("UPDATE managed_configs SET status='applying',last_job_id=?,updated_at=? WHERE node_id=? AND name=?",(jid,int(time.time()),node_id,name))
    return {'id':jid,'status':'applying'}


def reconcile_config_job(node_id,job_id,success,output):
    with store.connect() as c:
        rec=c.execute('SELECT * FROM managed_configs WHERE node_id=? AND last_job_id=?',(node_id,job_id)).fetchone()
        if not rec:return
        name=rec['name']
        if not success:
            c.execute('UPDATE managed_configs SET status=?,updated_at=? WHERE node_id=? AND name=?',
                     ('error',int(time.time()),node_id,name));return
        try:parsed=json.loads(output)
        except (ValueError,TypeError):parsed={}
        if rec['status']=='importing':
            content=parsed.get('content'); sha=parsed.get('sha256')
            if not isinstance(content,str) or not isinstance(sha,str) or not CONFIG_PATTERN.fullmatch(sha) or hashlib.sha256(content.encode()).hexdigest()!=sha:
                c.execute("UPDATE managed_configs SET status='error' WHERE node_id=? AND name=?",(node_id,name));return
            enc=store.FERNET.encrypt(content.encode()).decode()
            rev=rec['revision']+1
            c.execute('UPDATE managed_configs SET content_enc=?,remote_sha=?,revision=?,status=?,updated_at=? WHERE node_id=? AND name=?',
                      (enc,sha,rev,'synced',int(time.time()),node_id,name))
            c.execute('INSERT INTO config_versions(node_id,name,revision,content_enc,created_at) VALUES(?,?,?,?,?)',
                      (node_id,name,rev,enc,int(time.time())))
        elif rec['status']=='applying':
            sha=parsed.get('sha256')
            content=store.FERNET.decrypt(rec['content_enc'].encode()).decode()
            if sha!=hashlib.sha256(content.encode()).hexdigest():
                c.execute("UPDATE managed_configs SET status='error' WHERE node_id=? AND name=?",(node_id,name));return
            c.execute('UPDATE managed_configs SET remote_sha=?,status=?,updated_at=? WHERE node_id=? AND name=?',
                      (sha,'synced',int(time.time()),node_id,name))

@app.get('/api/presets')
def presets(_=Depends(admin)):
    return [
      {'id':'agent','title':'Только управление','details':'Docker, системный агент, диагностика, управление существующим стеком. Ничего не переустанавливается.'},
      {'id':'node','title':'Remnawave Node','details':'Docker + XPPN Agent + Remnawave Node. SSH и защиту порта 2222 настраиваем автоматически.'},
      {'id':'full','title':'Полный XPPN','details':'Docker + агент + Remnawave Node + Nginx + SSL + Fail2Ban. Только чистый VPS; используется адаптированный сентябрьский установщик.'}
    ]

@app.get('/api/nodes/{node_id}/install-events')
def install_events(node_id:str,request:Request,after:int=0,_=Depends(admin)):
    if after<0:raise HTTPException(400,'Invalid event cursor')
    with store.connect() as c:
        if not c.execute('SELECT id FROM nodes WHERE id=?',(node_id,)).fetchone():raise HTTPException(404,'Node not found')
    return {'events':store.logs_since(node_id,after)}

@app.get('/api/nodes/{node_id}/install-stream')
def stream_install(node_id:str,request:Request,after:int=0,_=Depends(admin)):
    with store.connect() as c:
        if not c.execute('SELECT id FROM nodes WHERE id=?',(node_id,)).fetchone():raise HTTPException(404,'Node not found')
    def produce():
        cursor=max(0,after)
        for i in range(250):
            events=store.logs_since(node_id,cursor)
            for event in events:
                cursor=event['id']
                yield 'event: log\ndata: '+json.dumps(event,ensure_ascii=False)+'\n\n'
            with store.connect() as c:
                row=c.execute('SELECT stage,error FROM nodes WHERE id=?',(node_id,)).fetchone()
            if not row:return
            yield 'event: state\ndata: '+json.dumps({'stage':row['stage'],'error':row['error']},ensure_ascii=False)+'\n\n'
            time.sleep(1)
    return StreamingResponse(produce(),media_type='text/event-stream',headers={'Cache-Control':'no-store','X-Accel-Buffering':'no'})

@app.delete('/api/nodes/{node_id}')
def remove_failed_node(node_id:str,_=Depends(write_access)):
    with store.connect() as c:
        row=c.execute('SELECT stage,last_seen FROM nodes WHERE id=?',(node_id,)).fetchone()
        if not row:raise HTTPException(404,'Not found')
        if row['stage']!='failed' or int(time.time())-row['last_seen']<90:
            raise HTTPException(409,'Only offline failed installations may be removed')
        c.execute('DELETE FROM jobs WHERE node_id=?',(node_id,))
        c.execute('DELETE FROM install_logs WHERE node_id=?',(node_id,))
        c.execute('DELETE FROM nodes WHERE id=?',(node_id,))
    return {'ok':True,'warning':'Removing the card does not uninstall files from the remote VPS.'}

@app.post('/api/ssh/probe')
def ssh_probe(data:Probe, request:Request,_=Depends(write_access)):
    ip=verify_ip(data.ip)
    attempts('ssh:'+request.client.host,20)
    # SSH fingerprints alone are not authentication; user must verify out-of-band.
    from concurrent.futures import TimeoutError as FuturesTimeout
    f=executor.submit(sshbootstrap.probe,ip,data.port)
    try: return {'fingerprint':f.result(timeout=20),'warning':'Verify this fingerprint using the VPS provider console before confirming.'}
    except FuturesTimeout: raise HTTPException(504,'SSH connection timeout')
    except Exception: raise HTTPException(502,'Cannot reach SSH host')

@app.post('/api/ssh/preflight')
def ssh_preflight(data:ReadOnlyPreflight,request:Request,_=Depends(write_access)):
    ip=verify_ip(data.ip)
    attempts('preflight:'+request.client.host,15)
    from concurrent.futures import TimeoutError as FuturesTimeout
    future=executor.submit(sshbootstrap.read_only_preflight,ip,data.port,data.password,data.fingerprint)
    try:return future.result(timeout=35)
    except FuturesTimeout:raise HTTPException(504,'VPS не отвечает на проверку в отведённое время')
    except (ValueError,RuntimeError) as e:raise HTTPException(409,str(e))
    except Exception:raise HTTPException(502,'Не удалось выполнить проверку VPS; проверь SSH-доступ')

@app.post('/api/ssh/enroll')
def ssh_enroll(data:Enroll,request:Request,_=Depends(write_access)):
    if not HUB_URL:raise HTTPException(422,'XPPN_PUBLIC_URL (HTTPS) must be configured')
    ip=verify_ip(data.ip)
    attempts('enroll:'+request.client.host,10)
    project_id=data.project_id
    with store.connect() as c:
        project=c.execute('SELECT * FROM projects WHERE id=?',(project_id,)).fetchone()
        prof=c.execute('SELECT * FROM deployment_profiles WHERE id=? AND project_id=?',(data.profile_id,project_id)).fetchone() if data.profile_id else None
    if not project:raise HTTPException(422,'Сначала создай проект и настрой параметры Remnawave')
    if data.profile_id and not prof:raise HTTPException(422,'Этот шаблон не принадлежит выбранному проекту')
    snapshot=projects.profile_view(prof) if prof else {}
    preset=snapshot['mode'] if prof else data.preset
    settings=snapshot.get('settings',{})
    if prof and snapshot['transport'] not in ('none','tls-raw'):
        # SSH bootstrap does not configure remote Xray/Remnawave inbounds!
        # This only provisions node runtime; the inbound is created in panel separately.
        if preset=='full':raise HTTPException(422,'Full deploy only supports TLS + RAW')
    creds=projects.project_secret(project_id)
    panel_ip=creds['panel_ip'] if prof else (creds['panel_ip'] or data.panel_ip)
    secret_key=creds['secret_key'] or data.secret_key
    auto_profile='';auto_inbounds=[]
    if preset in {'node','full'}:
        # Validate selection against LIVE panel before changing anything on VPS.
        auto_profile=settings.get('panel_config_profile_uuid') or project['panel_config_profile_uuid']
        try:auto_inbounds=settings.get('panel_active_inbounds') or json.loads(project['panel_active_inbounds'])
        except (TypeError,ValueError):auto_inbounds=[]
        if not auto_profile or not auto_inbounds:
            raise HTTPException(422,'Сначала подключи Remnawave API и выбери профиль/inbound-ы в настройках проекта')
        try:
            remote_profiles=remna_api.get_profiles(project_id)
            remna_api.validate_selection(remote_profiles,auto_profile,auto_inbounds)
            selected_panel=next(p for p in remote_profiles if p['uuid']==auto_profile)
            selected_inbounds=[i for i in selected_panel['inbounds'] if i['uuid'] in auto_inbounds]
            types={i.get('protocol','').lower() for i in selected_inbounds if i.get('protocol')}
            if snapshot.get('transport')=='hysteria2' and types and not types <= {'hysteria','hysteria2'}:
                raise HTTPException(422,'Hysteria 2 шаблон привязан к inbound другого протокола; выбери правильный inbound в шаблоне')
            if not secret_key:
                secret_key=remna_api.get_node_public_key(project_id)
                with store.connect() as c:
                    c.execute('UPDATE projects SET secret_key_enc=? WHERE id=?',(projects._encrypt_secret(secret_key, max_length=32768),project_id))
        except remna_api.PanelError as e:
            raise HTTPException(502,str(e))
        # DNS for panel inbound is NOT necessarily the same as outbound source.
        if not panel_ip and data.confirm_panel_dns_as_egress:
            try:panel_ip=remna_api.panel_dns_ipv4(project['panel_url'])
            except remna_api.PanelError as e:raise HTTPException(422,str(e))
        if not panel_ip:raise HTTPException(422,'Укажи исходящий IPv4 панели для firewall или подтверди использование IPv4 её домена')
    payload={}
    if preset in {'node','full'}:
        payload={'panel_ip':panel_ip,'secret_key':secret_key,'version':data.version}
        if preset=='full':
            if not data.confirm_clean:raise HTTPException(422,'Confirm that this is a clean VPS')
            payload.update({'domain':data.domain.strip().lower(),'confirm_clean':True,'logs_preset':settings.get('logs',data.logs_preset),'site':settings.get('site','static')})
        # Shared validation, no write on bad inputs.
        validate_job('node.install' if preset=='node' else 'legacy.install',payload)
    # Credentials verified BEFORE persisting a server record.
    try:
        sshbootstrap.check_credentials(ip,data.port,data.password,data.fingerprint)
    except ValueError as e:
        raise HTTPException(401,str(e))
    except RuntimeError as e:
        raise HTTPException(409,str(e))
    except Exception:
        raise HTTPException(502,'SSH connection failed; check network and port')
    with store.connect() as c:
        if c.execute("SELECT id FROM nodes WHERE ip=? AND stage!='failed'",(ip,)).fetchone():
            raise HTTPException(409,'Host already registered')
    node_id=str(uuid.uuid4())
    agent_token=secrets.token_urlsafe(48)
    helper_key=secrets.token_hex(32)
    encrypted=store.FERNET.encrypt(json.dumps(payload).encode()).decode() if payload else ''
    with store.connect() as c:
        c.execute('INSERT INTO nodes(id,name,ip,token_hash,signing_key_enc,ssh_fingerprint,stage,preset,pending_install_enc,created_at,project_id,profile_id,profile_snapshot,domain) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                  (node_id,data.name,ip,store.hash_token(agent_token),store.FERNET.encrypt(helper_key.encode()).decode(),data.fingerprint,'installing',preset,encrypted,int(time.time()),project_id,data.profile_id,json.dumps(snapshot,ensure_ascii=False),data.domain.strip().lower()))
        if auto_profile:
            c.execute('UPDATE nodes SET panel_auto_profile_uuid=?,panel_auto_inbounds=?,panel_auto_country=? WHERE id=?',
                      (auto_profile,json.dumps(auto_inbounds),data.country_code or project['panel_country_code'],node_id))
        c.execute('INSERT INTO audit VALUES(?,?,?)',(int(time.time()),'enroll',f'{node_id} {ip} preset={preset}'))
    store.log_install(node_id,'Проект '+project_id+', шаблон '+(snapshot.get('name') or preset)+'. SSH-пароль проверен, начинаем установку.')
    if snapshot.get('transport') not in (None,'none','tls-raw'):
        store.log_install(node_id,'Важно: выбранный Xray транспорт не развёртывается агентом автоматически. После установки открой Xray-профиль в Remnawave.')
    executor.submit(sshbootstrap.bootstrap,node_id,ip,data.port,data.password,data.fingerprint,agent_token,helper_key,HUB_URL)
    return {'id':node_id,'state':'installing'}

def validate_job(cmd,p):
    if cmd not in ALL_COMMANDS: raise HTTPException(422,'Unsupported command')
    if cmd=='logs.read':
        if p.get('source') not in {'docker.remnanode','docker.nginx','journal.docker','journal.xppn-helper','journal.xray','xray.access','xray.error','nginx.access','nginx.error'} or not isinstance(p.get('lines',100),int) or not 1<=p.get('lines',100)<=300 or set(p)-{'source','lines'}:raise HTTPException(422,'Unsupported logs request')
    elif cmd=='logs.policy':
        if p.get('preset') not in {'compact','standard','archive'} or set(p)!={'preset'}:raise HTTPException(422,'Invalid logs policy')
    elif cmd=='docker.action':
        if p.get('container') not in ALLOWED_CONTAINERS or p.get('action') not in {'restart','start','stop'}:
            raise HTTPException(422,'Invalid container or action')
    elif cmd=='docker.logs':
        if p.get('container') not in ALLOWED_CONTAINERS: raise HTTPException(422,'Invalid container')
    elif cmd in {'config.read','config.write'}:
        if p.get('name') not in CONFIGS: raise HTTPException(422,'Unsupported config')
        if cmd=='config.write':
            if not isinstance(p.get('content'),str) or len(p['content'])>100000 or '\x00' in p['content'] or not re.fullmatch('[0-9a-f]{64}',str(p.get('sha256',''))):
                raise HTTPException(422,'Invalid content or expected digest')
    elif cmd=='network.bbr':
        if p.get('algorithm') not in ('cubic','bbr') or len(p)!=1:raise HTTPException(422,'Allowed congestion controls: cubic or bbr')
    elif cmd=='project.node.install':
        if not re.fullmatch(r'\d+\.\d+\.\d+',str(p.get('version',''))) or len(p)!=1:raise HTTPException(422,'Pinned version required')
    elif cmd=='project.stack.install':
        if set(p)!={'version','domain','confirm_clean','profile_id'} or not re.fullmatch(r'\d+\.\d+\.\d+',str(p.get('version',''))):
            raise HTTPException(422,'Укажи закреплённую версию Remnawave')
        if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{2,250}',str(p.get('domain',''))) or '..' in p['domain'] or p['domain'].endswith('.'):
            raise HTTPException(422,'Нужен действительный домен VPS')
        if p.get('confirm_clean') is not True:
            raise HTTPException(422,'Необходимо подтвердить чистую установку стека на VPS без существующих Nginx/Remnawave')
        if not isinstance(p.get('profile_id'),str) or len(p['profile_id'])>80 or not p['profile_id']:
            raise HTTPException(422,'Выбери проверенный TLS-пресет проекта')
    elif cmd=='node.upgrade':
        if not re.fullmatch(r'\d+\.\d+\.\d+', str(p.get('version',''))):
            raise HTTPException(422,'Pinned semantic version required')
    elif cmd=='node.install':
        try:
            if not ipaddress.ip_address(p.get('panel_ip','')).is_global or ':' in p['panel_ip']:
                raise ValueError()
        except (ValueError,KeyError):raise HTTPException(422,'Public IPv4 address of the panel is required')
        if not isinstance(p.get('secret_key'),str) or not re.fullmatch(r'[A-Za-z0-9+/=_-]{16,32768}',p['secret_key']) or not re.fullmatch(r'\d+\.\d+\.\d+',str(p.get('version',''))):
            raise HTTPException(422,'Valid SECRET_KEY and pinned version are required')
    elif cmd=='legacy.install':
        try:
            if not ipaddress.ip_address(p.get('panel_ip','')).is_global or ':' in p['panel_ip']:
                raise ValueError()
        except (ValueError,KeyError): raise HTTPException(422,'Public IPv4 address of the panel is required')
        if p.get('logs_preset','standard') not in ('standard','compact','archive') or p.get('site','static') not in ('static','none'):
            raise HTTPException(422,'Invalid logs preset')
        if not p.get('confirm_clean') or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{2,250}',str(p.get('domain',''))):
            raise HTTPException(422,'A valid DNS domain and clean-host confirmation are required')
        if not isinstance(p.get('secret_key'),str) or not re.fullmatch(r'[A-Za-z0-9+/=_-]{16,32768}',p['secret_key']) or not re.fullmatch(r'\d+\.\d+\.\d+',str(p.get('version',''))):
            raise HTTPException(422,'SECRET_KEY and pinned version are required')
    elif p: raise HTTPException(422,'Unexpected parameters')
    return p

@app.post('/api/nodes/{node_id}/jobs')
def queue(node_id:str,body:JobBody,_=Depends(write_access)):
    validate_job(body.command,body.payload)
    with store.connect() as c:
        state=c.execute('SELECT stage,last_seen,telemetry,panel_node_uuid FROM nodes WHERE id=?',(node_id,)).fetchone()
        if not state:raise HTTPException(404,'Node not found')
        if state['stage']!='ready':raise HTTPException(409,'Actions unlock only after successful installation and verification')
        queued=c.execute("SELECT count(*) AS n FROM jobs WHERE node_id=? AND status in ('queued','running')",(node_id,)).fetchone()['n']
        if queued>=15:raise HTTPException(429,'Queue full')
    jid=str(uuid.uuid4())
    cmd=body.command;payload=body.payload
    postinstall_defaults=None
    if cmd in ('project.node.install','project.stack.install'):
        with store.connect() as c:
            pr=c.execute('SELECT p.panel_config_profile_uuid,p.panel_active_inbounds,p.panel_country_code FROM nodes n JOIN projects p ON p.id=n.project_id WHERE n.id=?',(node_id,)).fetchone()
        if not pr or not pr['panel_config_profile_uuid']:
            raise HTTPException(422,'Сначала сохрани Config Profile и inbound-ы в VPN-проекте')
        inbounds=json.loads(pr['panel_active_inbounds'])
        if not inbounds:
            raise HTTPException(422,'В проекте не выбраны активные inbound-ы')
        # Validate using project id; never rely on cached inbound choices.
        with store.connect() as c:
            pid=c.execute('SELECT project_id FROM nodes WHERE id=?',(node_id,)).fetchone()['project_id']
        try:remna_api.validate_selection(remna_api.get_profiles(pid),pr['panel_config_profile_uuid'],inbounds)
        except remna_api.PanelError as e:raise HTTPException(422,str(e))
        postinstall_defaults=(pr['panel_config_profile_uuid'],json.dumps(inbounds),pr['panel_country_code'])
    if cmd=='project.node.install':
        with store.connect() as c:
            row=c.execute('SELECT project_id FROM nodes WHERE id=?',(node_id,)).fetchone()
        if not row:raise HTTPException(404,'Node not found')
        creds=projects.project_secret(row['project_id'])
        payload={**creds,'version':body.payload['version']}
        validate_job('node.install',payload)
        cmd='node.install'
    if cmd=='project.stack.install':
        with store.connect() as c:
            row=c.execute('SELECT project_id, panel_node_uuid FROM nodes WHERE id=?',(node_id,)).fetchone()
        with store.connect() as c:
            profrow=c.execute('SELECT * FROM deployment_profiles WHERE id=? AND project_id=?',
                (body.payload['profile_id'],row['project_id'])).fetchone()
        if not profrow or profrow['mode']!='full' or profrow['transport']!='tls-raw':
            raise HTTPException(422,'Для полного стека нужен TLS + Nginx fallback пресет этого проекта')
        settings=json.loads(profrow['settings'])
        selected_uuid=settings.get('panel_config_profile_uuid') or postinstall_defaults[0]
        selected_ins=settings.get('panel_active_inbounds') or json.loads(postinstall_defaults[1])
        if not selected_uuid or not selected_ins:
            raise HTTPException(422,'Для TLS нужны Config Profile и inbound-ы')
        try:
            remote_profiles=remna_api.get_profiles(row['project_id'])
            remna_api.validate_selection(remote_profiles,selected_uuid,selected_ins)
            chosen=next(p for p in remote_profiles if p['uuid']==selected_uuid)
            active=[i for i in chosen['inbounds'] if i['uuid'] in selected_ins]
            if any(i.get('security') and i['security'].lower()!='tls' for i in active):
                raise HTTPException(422,'В TLS-шаблоне есть inbound без TLS; выбери соответствующий inbound')
            if any(i.get('network') and i['network'].lower() not in ('tcp','raw') for i in active):
                raise HTTPException(422,'TLS + Nginx fallback рассчитан на RAW/TCP inbound')
        except remna_api.PanelError as e:raise HTTPException(422,str(e))
        postinstall_defaults=(selected_uuid,json.dumps(selected_ins),postinstall_defaults[2])
        # Templates describe the desired Xray profile, never rewrite an existing panel configuration.
        creds=projects.project_secret(row['project_id'])
        payload={'panel_ip':creds['panel_ip'],'secret_key':creds['secret_key'],
                 'version':body.payload['version'],'domain':body.payload['domain'],
                 'confirm_clean':True,'logs_preset':'standard','site':'static'}
        validate_job('legacy.install',payload)
        cmd='legacy.install'
    require_component_command(cmd,payload,dict(state))
    # One provisioning action at a time for a host; jobs are already serialized by agent.
    try:store.queue_job(node_id,jid,cmd,payload)
    except LookupError:raise HTTPException(404,'Node not found')
    if postinstall_defaults:
        with store.connect() as c:
            c.execute('UPDATE nodes SET panel_auto_profile_uuid=?,panel_auto_inbounds=?,panel_auto_country=? WHERE id=?',
                      (*postinstall_defaults,node_id))
            if body.command=='project.stack.install':
                c.execute('UPDATE nodes SET domain=?,profile_id=?,profile_snapshot=? WHERE id=?',
                    (body.payload['domain'],profrow['id'],json.dumps(projects.profile_view(profrow),ensure_ascii=False),node_id))
        store.log_install(node_id,'Добавление компонентов запущено. После подтверждения запуска будет выполнена проверка и регистрация через API Remnawave.')
    return {'id':jid,'status':'queued'}

@app.get('/api/agent/{node_id}/next')
def next_job(node_id:str,request:Request,_=Depends(agent_auth)):
    with store.connect() as c:
        c.execute("UPDATE nodes SET last_seen=? WHERE id=?",(int(time.time()),node_id))
    store.start_profile_if_ready(node_id)
    return {'job':store.take_job(node_id)}

@app.post('/api/agent/{node_id}/heartbeat')
def heartbeat(node_id:str,data:Heartbeat,request:Request,_=Depends(agent_auth)):
    txt=json.dumps(data.telemetry)
    if len(txt)>16000: raise HTTPException(413,'Telemetry too large')
    with store.connect() as c:
        c.execute("UPDATE nodes SET last_seen=?,telemetry=? WHERE id=?",(int(time.time()),txt,node_id))
    store.start_profile_if_ready(node_id)
    store.recover_agent_if_healthy(node_id,data.telemetry)
    store.verify_telemetry(node_id,data.telemetry)
    # Bounded historical metrics, never store arbitrary agent log data here.
    try:
        t=data.telemetry; mem=t.get('memory',{}); disk=t.get('disk',{}); net=t.get('network_bytes',{})
        now=int(time.time())
        def finite(v):
            import math
            n=float(v)
            return round(n,2) if math.isfinite(n) else None
        with store.connect() as c:
            last=c.execute('SELECT ts FROM telemetry_history WHERE node_id=? ORDER BY ts DESC LIMIT 1',(node_id,)).fetchone()
            if not last or now-last['ts']>=60:
                mt=float(mem.get('total_kb') or 0);dt=float(disk.get('total') or 0)
                cpu=t.get('cpu_percent')
                c.execute('INSERT INTO telemetry_history(node_id,ts,load1,cpu_percent,mem_percent,disk_percent,net_rx,net_tx) VALUES(?,?,?,?,?,?,?,?)',
                    (node_id,now,finite((t.get('loadavg') or [0])[0]),finite(cpu) if cpu is not None else None,
                     finite(100*(1-float(mem.get('available_kb',0))/mt)) if mt else None,
                     finite(100*(1-float(disk.get('free',0))/dt)) if dt else None,
                     int(net.get('rx',0)),int(net.get('tx',0))))
    except (ValueError,TypeError,KeyError,IndexError):pass
    if int(time.time()) % 3600 < 20:
        from .housekeeping import prune
        prune()
    # Atomic claim in worker prevents duplicated registration on repeated heartbeats.
    with store.connect() as c:
        pending=c.execute("SELECT stage,panel_registering,panel_register_started_at FROM nodes WHERE id=?",(node_id,)).fetchone()
        if pending and pending['stage']=='registering' and pending['panel_registering'] and int(time.time())-pending['panel_register_started_at']>240:
            c.execute("UPDATE nodes SET stage='registration_failed',panel_registering=0,error=? WHERE id=?",('Регистрация прервана или завершилась без подтверждения. Проверь Remnawave перед повтором.',node_id))
            store.log_install(node_id,'Регистрация не подтвердилась вовремя. Не повторяем API-запрос автоматически; проверь панель.')
            pending=None
    if pending and pending['stage']=='registering' and not pending['panel_registering']:
        executor.submit(auto_register_after_install,node_id)
    return {'ok':True}

@app.post('/api/agent/{node_id}/progress')
def installation_progress(node_id:str,data:Progress,request:Request,_=Depends(agent_auth)):
    with store.connect() as c:
        active=c.execute("SELECT id,command FROM jobs WHERE node_id=? AND id=? AND status='running'",(node_id,data.job_id)).fetchone()
        node=c.execute('SELECT stage,install_job_id FROM nodes WHERE id=?',(node_id,)).fetchone()
    initial=node and node['install_job_id']==data.job_id and node['stage']=='provisioning'
    postinstall=node and node['stage']=='ready' and active and active['command'] in ('node.install','legacy.install')
    if not active or not (initial or postinstall):
        raise HTTPException(409,'Not an active provisioning job')
    store.log_install(node_id,data.message)
    return {'ok':True}

@app.post('/api/agent/{node_id}/result')
def result(node_id:str,data:AgentResult,request:Request,_=Depends(agent_auth)):
    try: uuid.UUID(data.job_id)
    except ValueError: raise HTTPException(400,'Invalid job ID')
    # Imported remote configuration may contain certificates or tokens. Never retain
    # its plaintext in the unencrypted jobs table or the user-visible job history.
    with store.connect() as c:
        pending=c.execute("SELECT command FROM jobs WHERE node_id=? AND id=? AND status='running'",(node_id,data.job_id)).fetchone()
    if not pending:raise HTTPException(409,'Not a running job')
    job_output='[configuration snapshot stored encrypted]' if pending['command']=='config.read' and data.success else data.output
    if pending['command']=='config.read' and not data.success:job_output='Configuration import failed on agent (details hidden)'
    if not store.finish_job(node_id,data.job_id,'success' if data.success else 'error',job_output):
        raise HTTPException(409,'Not a running job')
    store.installation_job_result(node_id,data.job_id,data.success,data.output)
    reconcile_config_job(node_id,data.job_id,data.success,data.output)
    # Stage-driven auto-registration after an agent-only VPS is extended with a Node.
    # The original first-time bootstrap flow is handled separately by store.installation_job_result.
    with store.connect() as c:
        job=c.execute('SELECT command FROM jobs WHERE id=? AND node_id=?',(data.job_id,node_id)).fetchone()
        node=c.execute('SELECT stage,panel_node_uuid,panel_auto_profile_uuid FROM nodes WHERE id=?',(node_id,)).fetchone()
        if job and node and node['stage']=='ready' and job['command'] in ('node.install','legacy.install'):
            if data.success and not node['panel_node_uuid']:
                new_preset='full' if job['command']=='legacy.install' else 'node'
                c.execute("UPDATE nodes SET stage='verifying',preset=?,error='' WHERE id=?",(new_preset,node_id))
                store.log_install(node_id,'Компонент установлен. Проверяем его работу по телеметрии; затем регистрируем в Remnawave.')
            elif not data.success:
                store.log_install(node_id,'Доустановка не выполнена. Агент остаётся доступным; смотри ошибку в истории заданий.')
    return {'ok':True}

@app.post('/api/nodes/{node_id}/panel/retry')
def retry_panel_registration(node_id: str, _=Depends(write_access)):
    """Explicit manual retry after operator checked ambiguous outcomes in Remnawave."""
    with store.connect() as c:
        c.execute('BEGIN IMMEDIATE')
        row=c.execute('SELECT panel_auto_profile_uuid,stage,panel_node_uuid,panel_registering FROM nodes WHERE id=?',(node_id,)).fetchone()
        if not row:
            c.execute('ROLLBACK');raise HTTPException(404,'Сервер не найден')
        if row['stage']!='registration_failed' or row['panel_node_uuid'] or row['panel_registering'] or not row['panel_auto_profile_uuid']:
            c.execute('ROLLBACK');raise HTTPException(409,'Повторить можно только неуспешную регистрацию ноды с настроенным проектом')
        c.execute("UPDATE nodes SET stage='registering',error='' WHERE id=?",(node_id,))
        c.execute('COMMIT')
    store.log_install(node_id,'Оператор запросил повторную регистрацию. Работающую ноду на VPS не переустанавливаем.')
    executor.submit(auto_register_after_install,node_id)
    return {'ok':True}


# Independent reusable configuration library and multi-file presets.
from . import config_library
config_library.register(app,admin,write_access)
