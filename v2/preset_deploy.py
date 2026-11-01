"""Render two scoped install presets from the encrypted Manager library.

Bridge bootstrap has no outbound destination until a real exit is configured.
Only Nginx text may differ from the shipped baseline; Compose is constrained
to the known safe service/mount sets to prevent arbitrary root VPS changes.
"""
from __future__ import annotations
import json
import re
from pathlib import Path
import yaml

from . import storage
from .template_engine import Endpoint, TemplateError, validate_rendered

ROOT=Path(__file__).resolve().parent/"data"
TYPES=("xray","nginx","nginx_compose","node_compose")
TOKEN=re.compile(r"\{\{([a-z0-9_.]+)\}\}")


def default_preset_id():
    with storage.connect() as db:
        row=db.execute(
            """SELECT p.id FROM presets p
               JOIN preset_items i ON p.id=i.preset_id
               WHERE p.name=? AND p.mode='direct' AND i.kind='xray'
               LIMIT 1""",("XPPN · Direct VLESS TLS RAW",)).fetchone()
    if not row:
        raise ValueError("Пресет обычного сервера не найден. Проверь библиотеку.")
    return row["id"]


def _safe_compose(text: str, baseline: str) -> bool:
    """Allow harmless Compose revision changes without risking VPS root access."""
    try:
        proposed=yaml.safe_load(text)
        expected=yaml.safe_load(baseline)
        if not isinstance(proposed,dict) or set(proposed)!={"services"}:
            return False
        services=proposed["services"]
        if not isinstance(services,dict) or set(services)!=set(expected["services"]):
            return False
        for service_name, ref in expected["services"].items():
            actual=services[service_name]
            if not isinstance(actual,dict):
                return False
            allowed=set(ref)|{"ulimits"}
            if set(actual)-allowed:
                return False
            # Container identity, image, mounts, network and env stay immutable.
            mandatory=set(ref)-{"logging","restart"}
            if any(actual.get(k)!=ref[k] for k in mandatory):
                return False
            if actual.get("restart",ref.get("restart")) not in ("unless-stopped","always"):
                return False
            logging=actual.get("logging",ref.get("logging",{}))
            if not isinstance(logging,dict) or set(logging)-{"options","driver"}:
                return False
            if logging.get("driver","json-file")!="json-file":
                return False
            options=logging.get("options",{})
            if not isinstance(options,dict) or set(options)-{"max-size","max-file"}:
                return False
            size=str(options.get("max-size","10m"))
            limit=str(options.get("max-file","3"))
            if not re.fullmatch(r"(?:[1-9]|[1-4][0-9]|50)m",size):
                return False
            if not limit.isdigit() or not 1<=int(limit)<=8:
                return False
            if "ulimits" in actual:
                limit_spec=actual["ulimits"]
                if not isinstance(limit_spec,dict) or set(limit_spec)!={"nofile"}:
                    return False
                nofile=limit_spec["nofile"]
                if isinstance(nofile,dict):
                    if set(nofile)!={"soft","hard"}:
                        return False
                    values=list(nofile.values())
                else:
                    values=[nofile]
                if any(not isinstance(v,int) or not 1024<=v<=1048576 for v in values):
                    return False
        return True
    except yaml.YAMLError:
        return False


def load_preset(preset_id: str) -> dict:
    with storage.connect() as db:
        p=db.execute("SELECT * FROM presets WHERE id=?",(preset_id,)).fetchone()
        if not p:
            raise ValueError("Выбранный пресет не найден")
        if p["mode"]!="direct":
            raise ValueError("Этот пресет не предназначен для установки обычной ноды")
        rows=db.execute("""SELECT i.kind,c.content_enc,c.revision
             FROM preset_items i JOIN library_configs c ON c.id=i.config_id
             WHERE i.preset_id=?""",(preset_id,)).fetchall()
    files={r["kind"]:storage.decrypt(r["content_enc"]) for r in rows}
    if set(files)!=set(TYPES):
        raise ValueError("Установочный пресет должен содержать Xray, Nginx и оба Docker Compose")
    for kind,filename in (("nginx_compose","nginx-compose.yml"),
                          ("node_compose","remnanode-compose.yml")):
        baseline=(ROOT/filename).read_text("utf-8")
        if not _safe_compose(files[kind],baseline):
            raise ValueError("Docker Compose содержит небезопасные изменения портов, "
                             "контейнеров, образов, путей или прав. Установка заблокирована.")
    config=json.loads(files["xray"])
    if not isinstance(config,dict):
        raise ValueError("Xray-шаблон должен быть JSON-объектом")
    return {"id":p["id"],"name":p["name"],"mode":p["mode"],"files":files,
            "revisions":{r["kind"]:r["revision"] for r in rows}}


def _replace(value,source:Endpoint):
    values={"source.code":source.code,"source.domain":source.domain}
    if isinstance(value,str):
        def sub(m):
            if m.group(1) not in values:
                raise TemplateError("Неразрешённая переменная Xray: "+m.group(1))
            return values[m.group(1)]
        return TOKEN.sub(sub,value)
    if isinstance(value,list):
        return [_replace(v,source) for v in value]
    if isinstance(value,dict):
        return {k:_replace(v,source) for k,v in value.items()}
    return value


def _assert_inbound(inbound:dict,source:Endpoint,port:int):
    expected_certs=[{
        "keyFile":"/opt/nginx/certs/"+source.domain+"_privkey.key",
        "certificateFile":"/opt/nginx/certs/"+source.domain+"_fullchain.pem"}]
    expected=inbound.get("streamSettings",{})
    tls=expected.get("tlsSettings",{})
    if (inbound.get("port")!=port or inbound.get("protocol")!="vless"
        or inbound.get("listen")!="0.0.0.0"
        or expected.get("network")!="raw" or expected.get("security")!="tls"
        or tls.get("certificates")!=expected_certs
        or inbound.get("settings",{}).get("fallbacks")!=[{"dest":"127.0.0.1:8080"}]):
        raise ValueError("Xray пресет изменил разрешённые TLS-пути, fallback или порт. "
                         "Установка остановлена до явной проверки.")


def xray_for_install(preset:dict,source:Endpoint)->dict:
    if preset["mode"]!="direct":
        raise ValueError("Мостовая топология отключена")
    raw=json.loads(preset["files"]["xray"])
    result=_replace(raw,source)
    ins=result.get("inbounds",[])
    if len(ins)!=1 or ins[0].get("tag")!=source.code+"_VLESS_TLS_IN":
        raise ValueError("Direct Xray: требуется один inbound с тегом CODE_VLESS_TLS_IN")
    _assert_inbound(ins[0],source,443)
    if {i.get("tag") for i in result.get("outbounds",[])}!={"DIRECT","BLOCKED"}:
        raise ValueError("Direct Xray: посторонние исходящие маршруты запрещены")
    validate_rendered(result)
    return result


def render_snapshot(preset_id:str,source:Endpoint,role:str)->dict:
    preset=load_preset(preset_id)
    mode=preset["mode"]
    if mode!="direct" or role!="regular":
        raise ValueError("Для установки поддерживается только обычная нода")
    xray=xray_for_install(preset,source)
    nginx=_replace(preset["files"]["nginx"],source)
    if "{{" in nginx or "\x00" in nginx or len(nginx.encode())>45000:
        raise ValueError("В Nginx остались шаблонные переменные или размер файла превышен")
    return {"preset_id":preset["id"],"preset_name":preset["name"],"mode":mode,
            "revisions":preset["revisions"],"xray":xray,
            "nginx":nginx,
            "nginx_compose":preset["files"]["nginx_compose"],
            "node_compose":preset["files"]["node_compose"],
            "inbound_tags":[i["tag"] for i in xray["inbounds"]],
            "note":"Обычный VLESS TLS сервер с прямым выходом."}
