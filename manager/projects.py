"""Multi-project profile & credential store. Remnawave remains Xray config authority."""
import ipaddress
import json
import re
import secrets
import time
import uuid
from urllib.parse import urlparse
from . import store

TRANSPORTS = {
    'none': {'title':'Только агент', 'udp':False, 'mode':'agent'},
    'tls-raw': {'title':'VLESS / RAW / TLS / Nginx fallback','udp':False},
    'reality-vision': {'title':'VLESS / RAW / REALITY / Vision','udp':False},
    'xhttp-tls': {'title':'VLESS / XHTTP / TLS','udp':False},
    'xhttp-reality': {'title':'VLESS / XHTTP / REALITY','udp':False},
    'hysteria2': {'title':'Hysteria 2 / QUIC / TLS','udp':True},
    'grpc-tls': {'title':'VLESS / gRPC / TLS (legacy)','udp':False},
    'ws-tls': {'title':'VLESS / WS / TLS (legacy)','udp':False},
    'bridge': {'title':'RU → зарубежный мост (раздельная настройка)','udp':False},
}
MODES=('agent','node','full')
SITE_MODES=('none','static','custom')

def project_view(r):
    d=dict(r)
    return {k:d[k] for k in ('id','name','panel_url','panel_ip','created_at','updated_at')} | {
        'has_secret_key':bool(d['secret_key_enc']), 'has_api_token':bool(d['api_token_enc']),
        'panel_config_profile_uuid':d['panel_config_profile_uuid'],
        'panel_active_inbounds':json.loads(d['panel_active_inbounds']),
        'panel_country_code':d['panel_country_code']}

def _project_values(data, old=None):
    name=str(data.get('name', old['name'] if old else '')).strip()
    if not 1<=len(name)<=80 or any(ord(ch)<32 for ch in name):raise ValueError('Название проекта: 1–80 символов')
    url=str(data.get('panel_url',old['panel_url'] if old else '')).strip().rstrip('/')
    if url:
        u=urlparse(url)
        if u.scheme!='https' or not u.hostname or u.username or u.password or u.fragment or u.query or not u.hostname.count('.'):
            raise ValueError('Укажи HTTPS URL панели (без логина и параметров)')
    ip=str(data.get('panel_ip',old['panel_ip'] if old else '')).strip()
    if ip:
        try:addr=ipaddress.ip_address(ip)
        except ValueError:raise ValueError('Нужен публичный IPv4 панели')
        if addr.version!=4 or not addr.is_global:raise ValueError('Нужен публичный IPv4 панели')
    return name,url,ip

def _encrypt_secret(v, max_length=2048):
    # API tokens remain capped at 2048, but Remnawave Node SECRET_KEY is a
    # base64-encoded JSON bundle of mTLS certs and may be much longer.
    if not isinstance(v,str) or not 16<=len(v)<=max_length or any(ord(ch)<32 for ch in v):
        raise ValueError(f'Секрет: 16–{max_length} символов, без переноса строк')
    return store.FERNET.encrypt(v.encode()).decode()

def create_project(data):
    name,url,ip=_project_values(data)
    pid=str(uuid.uuid4());now=int(time.time())
    sk=_encrypt_secret(data['secret_key'], max_length=32768) if data.get('secret_key') else ''
    tok=_encrypt_secret(data['api_token']) if data.get('api_token') else ''
    with store.connect() as c:
        c.execute('INSERT INTO projects(id,name,panel_url,panel_ip,secret_key_enc,api_token_enc,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',(pid,name,url,ip,sk,tok,now,now))
        for label,mode,transport in [
            ('Только управление','agent','none'),('TLS + Nginx','full','tls-raw'),
            ('Remnawave Node','node','tls-raw'),('REALITY + Vision','node','reality-vision'),
            ('XHTTP + TLS','node','xhttp-tls'),('Hysteria 2 + TLS','node','hysteria2'),
            ('RU Bridge','node','bridge')]:
            profile_id=str(uuid.uuid4())
            c.execute('INSERT INTO deployment_profiles(id,project_id,name,mode,transport,settings,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',
                      (profile_id,pid,label,mode,transport,'{}',now,now))
        c.execute('INSERT INTO audit VALUES(?,?,?)',(now,'project.create',pid))
    return pid

def update_project(pid,data):
    with store.connect() as c:
        old=c.execute('SELECT * FROM projects WHERE id=?',(pid,)).fetchone()
        if not old:raise LookupError('Проект не найден')
        name,url,ip=_project_values(data,old)
        sk='' if data.get('clear_secret_key') is True else (_encrypt_secret(data['secret_key'], max_length=32768) if data.get('secret_key') else old['secret_key_enc'])
        tok='' if data.get('clear_api_token') is True else (_encrypt_secret(data['api_token']) if data.get('api_token') else old['api_token_enc'])
        # A new panel URL invalidates old node key and panel profile defaults.
        if url!=old['panel_url']:
            sk=_encrypt_secret(data['secret_key'], max_length=32768) if data.get('secret_key') else ''
        now=int(time.time())
        c.execute('UPDATE projects SET name=?,panel_url=?,panel_ip=?,secret_key_enc=?,api_token_enc=?,updated_at=? WHERE id=?',
                  (name,url,ip,sk,tok,now,pid))
        if url!=old['panel_url']:
            c.execute("UPDATE projects SET panel_config_profile_uuid='',panel_active_inbounds='[]' WHERE id=?",(pid,))
        c.execute('INSERT INTO audit VALUES(?,?,?)',(now,'project.update',pid))

def project_secret(pid):
    with store.connect() as c:
        p=c.execute('SELECT * FROM projects WHERE id=?',(pid,)).fetchone()
    if not p:raise LookupError('Проект не найден')
    return {'panel_ip':p['panel_ip'], 'secret_key':store.FERNET.decrypt(p['secret_key_enc']).decode() if p['secret_key_enc'] else ''}

def validate_profile(data):
    name=str(data.get('name','')).strip()
    mode=data.get('mode')
    t=data.get('transport')
    if not 1<=len(name)<=80 or mode not in MODES or t not in TRANSPORTS:
        raise ValueError('Неверное название, режим или транспорт')
    if mode=='agent' and t!='none':raise ValueError('Агент без прокси должен использовать transport=none')
    if mode!='agent' and t=='none':raise ValueError('Ноде нужен выбранный транспорт')
    if mode=='full' and t!='tls-raw':
        raise ValueError('Полная установка с Nginx пока поддерживает только проверенный TLS + RAW профиль')
    settings=data.get('settings') or {}
    if not isinstance(settings,dict) or set(settings)-{'port','site','bbr','fail2ban','logs','xhttp_path','udp_idle_timeout','panel_config_profile_uuid','panel_active_inbounds'}:
        raise ValueError('Неподдерживаемые настройки шаблона')
    if type(settings.get('port',443)) is not int or not 1<=settings.get('port',443)<=65535:
        raise ValueError('Неверный порт')
    if mode=='full' and settings.get('port',443)!=443:
        raise ValueError('Полная TLS+Nginx установка поддерживает только TCP 443')
    if settings.get('site','static') not in SITE_MODES or settings.get('logs','standard') not in ('standard','compact','archive'):
        raise ValueError('Неверный сайт/логи')
    if mode=='full' and settings.get('site','static')=='custom':
        raise ValueError('Загрузка собственного сайта через веб пока недоступна; используй статический шаблон')
    if any(type(settings.get(k,False)) is not bool for k in ('bbr','fail2ban')):
        raise ValueError('Сетевые модули должны быть true/false')
    if type(settings.get('udp_idle_timeout',60)) is not int or not 10<=settings.get('udp_idle_timeout',60)<=600:
        raise ValueError('Неверный UDP timeout')
    path=settings.get('xhttp_path','/xhttp')
    if not isinstance(path,str) or not re.fullmatch(r'/[A-Za-z0-9/_-]{1,90}',path):raise ValueError('Неверный XHTTP path')
    override=settings.get('panel_config_profile_uuid','')
    selected=settings.get('panel_active_inbounds',[])
    if override or selected:
        if not isinstance(override,str) or not re.fullmatch(r'[0-9a-fA-F-]{36}',override):
            raise ValueError('Некорректный UUID профиля Remnawave')
        if not isinstance(selected,list) or not 1<=len(selected)<=30 or len(set(selected))!=len(selected) or not all(isinstance(i,str) and re.fullmatch(r'[0-9a-fA-F-]{36}',i) for i in selected):
            raise ValueError('Некорректные UUID inbound-ов шаблона')
        if mode=='agent':raise ValueError('Управляющий агент не использует inbound-ы')
    return name,mode,t,settings

def add_profile(pid,data):
    name,mode,t,settings=validate_profile(data)
    now=int(time.time());fid=str(uuid.uuid4())
    with store.connect() as c:
        if not c.execute('SELECT id FROM projects WHERE id=?',(pid,)).fetchone():raise LookupError('Проект не найден')
        c.execute('INSERT INTO deployment_profiles(id,project_id,name,mode,transport,settings,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',
                  (fid,pid,name,mode,t,json.dumps(settings),now,now))
    return fid

def update_profile(fid,data):
    name,mode,t,settings=validate_profile(data)
    with store.connect() as c:
        row=c.execute('SELECT * FROM deployment_profiles WHERE id=?',(fid,)).fetchone()
        if not row:raise LookupError('Шаблон не найден')
        c.execute('UPDATE deployment_profiles SET name=?,mode=?,transport=?,settings=?,revision=revision+1,updated_at=? WHERE id=?',
                  (name,mode,t,json.dumps(settings),int(time.time()),fid))

def profile_view(r):
    d=dict(r);d['settings']=json.loads(d['settings']);return d

def profile_preview(profile,domain):
    """Safe skeleton only. NOT a validated Remnawave panel profile or deployable Xray config."""
    t=profile['transport'];cfg=profile['settings']
    port=cfg.get('port',443)
    if t=='none':return {'description':'Только агент','inbound':None,'applies_automatically':True,'warnings':[]}
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{2,250}', domain) or '..' in domain or domain.endswith('.'):
        raise ValueError('Укажи домен ноды для предварительного просмотра')
    base={'tag':'XPPN_'+t.upper().replace('-','_'), 'listen':'0.0.0.0','port':port}
    warnings=['Это предварительный шаблон. Применять через Remnawave и проверять совместимость ядра/клиентов; автоматически в панель не записывается.']
    if t=='hysteria2':
        base.update({'protocol':'hysteria', 'settings':{'version':2,'users':[]},
                     'streamSettings':{'network':'hysteria','security':'tls',
                     'tlsSettings':{'alpn':['h3'],'certificates':[{'certificateFile':'/PATH/TO/fullchain.pem','keyFile':'/PATH/TO/privkey.pem'}]},
                     'hysteriaSettings':{'version':2,'udpIdleTimeout':cfg.get('udp_idle_timeout',60)}}})
        warnings.append('Порт UDP. Пользователей/пароли задаёт панель. UDP/443 может конфликтовать с HTTP/3 сайта.')
    elif t=='bridge':
        return {'description':'Нужны два согласованных Xray-конфига для входного RU и выходного зарубежного VPS.',
                'inbound':None,'applies_automatically':False,'warnings':warnings+['Генерация моста требует адрес/профиль зарубежного outbound; текущую маршрутизацию не переписываем.']}
    else:
        security='reality' if 'reality' in t else 'tls'
        network='xhttp' if 'xhttp' in t else ('grpc' if 'grpc' in t else ('ws' if 'ws' in t else 'raw'))
        stream={'network':network,'security':security}
        if security=='tls':
            stream['tlsSettings']={'alpn':['http/1.1'],'certificates':[{'certificateFile':'/PATH/TO/fullchain.pem','keyFile':'/PATH/TO/privkey.pem'}]}
        else:
            stream['realitySettings']={'dest':'127.0.0.1:8443','serverNames':[domain], 'privateKey':'REPLACE_WITH_REALITY_PRIVATE_KEY','shortIds':['REPLACE_SHORT_ID']}
        if network=='xhttp':stream['xhttpSettings']={'path':cfg.get('xhttp_path','/xhttp')}
        if network=='grpc':stream['grpcSettings']={'serviceName':'xppn'}
        if network=='ws':stream['wsSettings']={'path':'/ws'}
        settings={'clients':[],'decryption':'none'}
        if t=='tls-raw':settings['fallbacks']=[{'dest':'127.0.0.1:8080'}]
        base.update({'protocol':'vless','settings':settings,'streamSettings':stream})
        if t=='reality-vision':warnings.append('Для Vision пользовательский flow задаёт Remnawave: xtls-rprx-vision.')
    return {'description':TRANSPORTS[t]['title'],'inbound':base,'applies_automatically':False,'warnings':warnings}
