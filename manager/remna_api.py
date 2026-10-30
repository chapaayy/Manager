"""Explicit, allowlisted Remnawave API calls using TLS validation and pinned public DNS.

Never sends API credentials to agent nodes. Refuses redirects and nonpublic destinations.
"""
import http.client
import ipaddress
import json
import re
import socket
import ssl
from urllib.parse import urlsplit
from . import store

class PanelError(Exception):
    pass

def credentials(pid):
    with store.connect() as c:
        r=c.execute('SELECT panel_url,api_token_enc FROM projects WHERE id=?',(pid,)).fetchone()
    if not r:raise PanelError('Проект не найден')
    if not r['panel_url'] or not r['api_token_enc']:raise PanelError('Укажи HTTPS URL панели и API-токен в проекте')
    return r['panel_url'],store.FERNET.decrypt(r['api_token_enc']).decode()

def _target(url):
    u=urlsplit(url)
    if u.scheme!='https' or not u.hostname or u.username or u.password or u.port not in (None,443) or u.query or u.fragment or u.path not in ('','/'):
        raise PanelError('Панель должна иметь публичный HTTPS-адрес без путей и параметров')
    # Fixed IP selected once. Do not resolve again after validation (DNS rebinding).
    try:addresses=socket.getaddrinfo(u.hostname,443,type=socket.SOCK_STREAM)
    except OSError:raise PanelError('Не удалось разрешить DNS панели')
    resolved=[entry[4][0] for entry in addresses]
    if not resolved or any(not ipaddress.ip_address(ip).is_global for ip in resolved):
        raise PanelError('Панель должна разрешаться только в публичные IP; внутренние адреса запрещены')
    return u.hostname,resolved[0]

class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self,hostname,ip):
        super().__init__(hostname,443,context=ssl.create_default_context(),timeout=12)
        self.pinned_ip=ip
    def connect(self):
        raw=socket.create_connection((self.pinned_ip,443),timeout=self.timeout)
        try:self.sock=self._context.wrap_socket(raw,server_hostname=self.host)
        except Exception:
            raw.close();raise

def request(pid,method,path,body=None):
    allowed=(method,path) in [('GET','/api/config-profiles'),('GET','/api/keygen'),('GET','/api/nodes'),('POST','/api/nodes')]
    allowed=allowed or (method=='GET' and re.fullmatch(r'/api/config-profiles/[0-9a-fA-F-]{36}/inbounds',path) is not None)
    if not allowed:
        raise PanelError('Эта API-операция не разрешена')
    url,token=credentials(pid)
    host,pinned=_target(url)
    conn=PinnedHTTPS(host,pinned)
    try:
        headers={'Authorization':'Bearer '+token,'Accept':'application/json'}
        encoded=None
        if body is not None:
            encoded=json.dumps(body,separators=(',',':')).encode()
            headers['Content-Type']='application/json'
            if len(encoded)>4000:raise PanelError('Слишком большой запрос')
        conn.request(method,path,body=encoded,headers=headers)
        resp=conn.getresponse()
        if resp.status<200 or resp.status>=300:
            # Error body may contain sensitive details, never return it to browser/logs.
            raise PanelError('Панель вернула HTTP '+str(resp.status))
        raw=resp.read(300001)
        if len(raw)>300000:raise PanelError('Слишком большой ответ панели')
        return json.loads(raw)
    except (OSError,ssl.SSLError,http.client.HTTPException,ValueError,json.JSONDecodeError) as e:
        raise PanelError('Не удалось выполнить защищённый API-запрос к Remnawave: '+type(e).__name__)
    finally:
        conn.close()

def get_node_public_key(pid):
    """Fetch the panel-issued node authentication public key. Never return its value to a browser."""
    payload=request(pid,'GET','/api/keygen')
    response=payload.get('response') if isinstance(payload,dict) else None
    if not isinstance(response,dict):
        raise PanelError('API /api/keygen: ответ не содержит ожидаемый объект response')
    value=response.get('secretKey') or response.get('pubKey')
    if not isinstance(value,str):
        raise PanelError('API /api/keygen: в response нет строкового secretKey или pubKey')
    if not 16<=len(value)<=32768:
        raise PanelError('API /api/keygen: длина ключа ноды вне поддерживаемых границ (16–32768)')
    if not re.fullmatch(r'[A-Za-z0-9+/=_-]+',value):
        raise PanelError('API /api/keygen: неподдерживаемая кодировка ключа; ожидается base64 без пробелов')
    return value

def validate_selection(profiles,profile_uuid,inbounds):
    if not isinstance(inbounds,list) or not 1<=len(inbounds)<=30 or len(set(inbounds))!=len(inbounds):
        raise PanelError('Выбери 1–30 различных inbound-ов')
    chosen=next((p for p in profiles if p['uuid']==profile_uuid),None)
    if not chosen:raise PanelError('Профиль больше не существует в панели')
    permitted={i['uuid'] for i in chosen['inbounds']}
    if not set(inbounds).issubset(permitted):raise PanelError('Некоторые inbound-ы не принадлежат выбранному профилю')
    return True

def get_profiles(pid):
    obj=request(pid,'GET','/api/config-profiles')
    rows=obj.get('response',{}).get('configProfiles',[])
    if not isinstance(rows,list):raise PanelError('Неверный формат ответа config-profiles')
    # Only public metadata and IDs, never raw inbounds or potential secrets.
    out=[]
    for row in rows[:200]:
        if not isinstance(row,dict):continue
        ins=[]
        # Current API variants can omit inbounds from config-profiles list.
        raw_ins=row.get('inbounds')
        if (not isinstance(raw_ins,list) or (raw_ins and not isinstance(raw_ins[0],dict))) and isinstance(row.get('uuid'),str):
            details=request(pid,'GET',f"/api/config-profiles/{row['uuid']}/inbounds")
            response=details.get('response',{})
            raw_ins=response.get('inbounds',[]) if isinstance(response,dict) else []
        for i in raw_ins or []:
            if isinstance(i,dict) and isinstance(i.get('uuid'),str):
                ins.append({'uuid':i['uuid'],'tag':str(i.get('tag',''))[:100],
                            'protocol':str(i.get('inboundType') or i.get('inbound_type') or i.get('protocol') or '')[:32],
                            'network':str(i.get('network') or '')[:32],
                            'security':str(i.get('security') or '')[:32]})
        out.append({'uuid':row.get('uuid'),'name':str(row.get('name',''))[:100],'inbounds':ins})
    return out

def register_node(pid, name, address, country, profile_uuid, inbounds):
    if not 3<=len(name)<=30 or any(ord(ch)<32 for ch in name):raise PanelError('Имя ноды в Remnawave: 3–30 символов')
    if not re.fullmatch(r'[A-Z]{2}',country):raise PanelError('Укажи код страны из двух заглавных букв')
    if not 1<=len(inbounds)<=30 or len(set(inbounds))!=len(inbounds):raise PanelError('Выбери inbound-ы без повторов')
    profiles=get_profiles(pid)
    validate_selection(profiles,profile_uuid,inbounds)
    nodes=request(pid,'GET','/api/nodes')
    existing=nodes.get('response',[])
    if not isinstance(existing,list):raise PanelError('Неверный формат списка нод')
    if any(isinstance(row,dict) and (row.get('address')==address or row.get('name')==name) for row in existing):
        raise PanelError('Нода с таким адресом или именем уже есть в панели; автоматическое изменение запрещено')
    payload={'name':name,'address':address,'port':2222,'countryCode':country,
             'isTrafficTrackingActive':False,'consumptionMultiplier':1,
             'configProfile':{'activeConfigProfileUuid':profile_uuid,'activeInbounds':inbounds}}
    r=request(pid,'POST','/api/nodes',payload)
    try:uuid=r['response']['uuid']
    except (TypeError,KeyError):raise PanelError('Панель не вернула UUID созданной ноды. Проверь её вручную')
    if not isinstance(uuid,str) or not uuid:raise PanelError('UUID ноды в ответе неверен')
    return uuid


def panel_dns_ipv4(panel_url):
    """Only after explicit UI confirmation that panel DNS A is its *outbound* IP."""
    host,_=_target(panel_url)
    try:infos=socket.getaddrinfo(host,443,family=socket.AF_INET,type=socket.SOCK_STREAM)
    except OSError:raise PanelError('У панели нет доступной A-записи')
    ips=sorted({i[4][0] for i in infos if ipaddress.ip_address(i[4][0]).is_global})
    if len(ips)!=1:raise PanelError('Панель должна иметь ровно один публичный IPv4 A-record; укажи исходящий IP вручную')
    return ips[0]
