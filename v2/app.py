"""XPPN Manager 2.0 review server — one panel, node inventory and safe bridge plans.

This is an intentionally isolated *preview* app. It never SSHes into a VPS,
modifies Remnawave profiles or publishes an Xray config. Do not expose to the
public internet until the future deployment adapter is tested.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import sqlite3
import time
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from pydantic import BaseModel, Field

from . import agent_bootstrap, agent_transport, bundled, library, node_cert_sync, node_lifecycle, node_removal, remnawave, service, storage, vps_install, web_updates
from .template_engine import Endpoint, TemplateError, safe_preview, variables_map

STATIC = Path(__file__).resolve().parent / "static"
app = FastAPI(title="XPPN 2.0 — isolated preview", docs_url=None,
              redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

COOKIE = "xppn_v2_session"
SESSION_MAX = 12 * 3600
_failed_login: dict[str, list[float]] = {}


def _secret() -> str:
    key = os.environ.get("XPPN_V2_SESSION_SECRET", "")
    if len(key) < 32:
        raise RuntimeError("Set XPPN_V2_SESSION_SECRET (at least 32 random characters)")
    return key


def _username() -> str:
    name = os.environ.get("XPPN_V2_ADMIN_USER", "admin")
    if not 3 <= len(name) <= 40 or not all(c.isalnum() or c in "_.-" for c in name):
        raise RuntimeError("XPPN_V2_ADMIN_USER must be 3–40 safe characters")
    return name


def _password_hash() -> str:
    stored = os.environ.get("XPPN_V2_ADMIN_PASSWORD_HASH", "")
    if stored:
        parts = stored.replace("$", ":").split(":")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            raise RuntimeError("Invalid XPPN_V2_ADMIN_PASSWORD_HASH")
        try:
            rounds = int(parts[1])
            if not 300_000 <= rounds <= 2_000_000:
                raise ValueError()
            salt = bytes.fromhex(parts[2])
            digest = bytes.fromhex(parts[3])
            if len(salt) != 16 or len(digest) != 32:
                raise ValueError()
        except ValueError:
            raise RuntimeError("Invalid XPPN_V2_ADMIN_PASSWORD_HASH") from None
        return stored
    # Backward compatibility ONLY for old v2 preview environments.
    value = os.environ.get("XPPN_V2_ADMIN_PASSWORD", "")
    if len(value) < 12:
        raise RuntimeError("Configure XPPN_V2_ADMIN_PASSWORD_HASH before starting")
    return ""


def _password_ok(password: str) -> bool:
    value = _password_hash()
    if value:
        _, iterations, salt, digest = value.replace("$", ":").split(":")
        computed = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(computed, bytes.fromhex(digest))
    return hmac.compare_digest(hashlib.sha256(password.encode()).digest(),
                               hashlib.sha256(os.environ["XPPN_V2_ADMIN_PASSWORD"].encode()).digest())


def signer():
    return URLSafeTimedSerializer(_secret(), salt="xppn-v2-auth-cookie")


@app.on_event("startup")
def startup():
    _secret()
    _username()
    _password_hash()
    storage.init_db()
    agent_transport.initialize()
    node_lifecycle.disable_pending_vps_cleanup()
    bundled.seed_defaults()
    storage.mark_interrupted_jobs()
    storage.remove_one_time_test_rus10()
    node_cert_sync.start_background()


@app.middleware("http")
async def protective_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
        "script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    )
    return response


def _session(request: Request) -> str:
    cookie = request.cookies.get(COOKIE)
    if not cookie:
        raise HTTPException(401, "Требуется авторизация")
    try:
        data = signer().loads(cookie, max_age=SESSION_MAX)
    except (BadSignature, SignatureExpired):
        raise HTTPException(401, "Сессия закончилась. Войди повторно") from None
    if not isinstance(data, dict) or data.get("version") != 2 or not isinstance(data.get("sid"), str):
        raise HTTPException(401, "Недействительная сессия")
    return data["sid"]


def _csrf(sid: str) -> str:
    return hmac.new(_secret().encode(), ("csrf:" + sid).encode(), hashlib.sha256).hexdigest()


def read_access(request: Request):
    return _session(request)


def write_access(request: Request):
    sid = _session(request)
    token = request.headers.get("X-CSRF-Token", "")
    if not hmac.compare_digest(token, _csrf(sid)):
        raise HTTPException(403, "Защита формы: обнови страницу")
    return sid


def _fail(exc: Exception):
    if isinstance(exc, sqlite3.IntegrityError):
        raise HTTPException(409,"Такая запись уже существует или связана с другой. Обнови страницу и проверь карточки.") from None
    if isinstance(exc, (ValueError, TemplateError)):
        raise HTTPException(422, str(exc)) from None
    if isinstance(exc, LookupError):
        raise HTTPException(404, str(exc)) from None
    raise exc


class Login(BaseModel):
    username: str = Field(default="admin", min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=512)


class PanelData(BaseModel):
    url: str
    token: str = Field(default="", max_length=2048)
    caddy_api_key: str = Field(default="", max_length=2048)
    outbound_ip: str = ""


class PanelProfile(BaseModel):
    uuid: str
    inbounds: list[str] = Field(min_length=1, max_length=30)


class NodeData(BaseModel):
    code: str
    name: str = Field(min_length=1, max_length=80)
    country: str
    domain: str
    role: str = Field(pattern=r"^(regular|entry|exit)$")


class VpsProbeData(BaseModel):
    ip: str = Field(min_length=7,max_length=45)
    port: int = Field(default=22,ge=1,le=65535)
    password: str = Field(min_length=1,max_length=512)
    domain: str = Field(min_length=4,max_length=253)


class VpsResumeData(BaseModel):
    password: str = Field(min_length=1, max_length=512)
    confirm_existing: bool = False


class VpsForgetData(BaseModel):
    confirm_local_only: bool = False


class VpsInstallData(VpsProbeData):
    code: str = Field(min_length=2,max_length=20)
    name: str = Field(min_length=3,max_length=80)
    country: str = Field(pattern=r"^[A-Za-z]{2}$")
    role: str = Field(pattern=r"^(regular|exit|entry)$")
    preset_id: str | None = Field(default=None,max_length=64)
    fingerprint: str
    confirm_clean: bool = False
    panel_ip: str = ""
    existing_node_id: str | None = Field(default=None,max_length=64)


class BridgeData(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    entry_id: str


class SnapshotData(BaseModel):
    config: dict
    revision: int = Field(ge=0)
    confirm_read_only: bool = False


class ExitPlanData(BaseModel):
    exit_id: str
    # Omitted UUID is generated and securely staged by the manager.
    outgoing_uuid: str | None = None
    inbound_port: int | None = Field(default=None, ge=8444, le=8999)
    config_template_id: str | None = None


@app.get("/")
def home():
    return FileResponse(STATIC / "index.html", media_type="text/html")


@app.get("/api/health")
def health():
    return {"ok": True, "product": "XPPN Manager 2.1 Preview", "deployment": False}


@app.post("/api/auth/login")
def login(body: Login, request: Request, response: Response):
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    failures = [t for t in _failed_login.get(ip, []) if now - t < 900]
    if len(failures) >= 6:
        raise HTTPException(429, "Слишком много попыток. Повтори позже")
    valid_user = hmac.compare_digest(body.username.encode(), _username().encode())
    valid_password = _password_ok(body.password)
    correct = valid_user and valid_password
    if not correct:
        failures.append(now)
        _failed_login[ip] = failures
        raise HTTPException(401, "Неверный пароль")
    _failed_login.pop(ip, None)
    sid = secrets.token_urlsafe(32)
    response.set_cookie(
        COOKIE, signer().dumps({"version": 2, "sid": sid}),
        max_age=SESSION_MAX, httponly=True, samesite="strict",
        secure=os.environ.get("XPPN_V2_COOKIE_SECURE", "1") != "0",
        path="/",
    )
    return {"ok": True, "csrf": _csrf(sid)}


@app.get("/api/auth/session")
def session(sid=Depends(read_access)):
    return {"ok": True, "csrf": _csrf(sid)}


@app.post("/api/auth/logout")
def logout(response: Response, _=Depends(write_access)):
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.get("/api/system/update")
def update_status(_=Depends(read_access)):
    return web_updates.status()


@app.post("/api/system/update/check")
def update_check(_=Depends(write_access)):
    try:
        return web_updates.check_available()
    except ValueError as e:
        raise HTTPException(503, str(e)) from None


@app.post("/api/system/update")
def trigger_update(_=Depends(write_access)):
    try:
        return web_updates.request_update()
    except ValueError as e:
        raise HTTPException(409, str(e)) from None


@app.get("/api/dashboard")
def dashboard(_=Depends(read_access)):
    return {
        "panel": storage.get_panel(),
        "nodes": storage.list_nodes(),
        "bridges": storage.list_bridges(),
        "phase": "preview-only",
    }


@app.put("/api/panel")
def update_panel(body: PanelData, _=Depends(write_access)):
    url = remnawave.validate_url(body.url.strip())
    outbound = body.outbound_ip.strip()
    if outbound:
        try:
            ip = ipaddress.ip_address(outbound)
            if ip.version != 4 or not ip.is_global:
                raise ValueError("Исходящий IP панели должен быть публичным IPv4")
        except ValueError as e:
            raise HTTPException(422, str(e) if "публичным" in str(e) else "Некорректный исходящий IPv4") from None
    if body.token and len(body.token) < 16:
        raise HTTPException(422, "API-токен слишком короткий")
    try:
        return storage.set_panel(url=url, outbound_ip=outbound,
                                 token=body.token.strip() if body.token.strip() else None,
                                 caddy_api_key=body.caddy_api_key.strip() if body.caddy_api_key.strip() else None)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None


@app.post("/api/panel/check")
def check_panel(_=Depends(write_access)):
    try:
        return remnawave.panel_status()
    except remnawave.PanelError as e:
        raise HTTPException(502, str(e)) from None


@app.put("/api/panel/profile")
def update_panel_profile(body: PanelProfile, _=Depends(write_access)):
    try:
        remnawave.validate_profile_selection(body.uuid, body.inbounds)
        return storage.set_panel_profile(body.uuid, body.inbounds)
    except remnawave.PanelError as e:
        raise HTTPException(422, str(e)) from None


class VpsPreviewData(BaseModel):
    preset_id: str | None = Field(default=None,max_length=64)
    role: str = Field(default="regular",pattern=r"^(regular|exit|entry)$")
    code: str = Field(min_length=2,max_length=20)
    domain: str = Field(min_length=4,max_length=253)
    country: str = Field(pattern=r"^[A-Za-z]{2}$")


@app.post("/api/vps/preview")
def vps_preview(body: VpsPreviewData, _=Depends(write_access)):
    try:
        endpoint=Endpoint(body.code.upper().strip(),body.domain.lower().strip(),
                          body.country.upper().strip())
        from . import preset_deploy
        selected=body.preset_id or preset_deploy.default_preset_id()
        return vps_install.preview_plan(endpoint,selected,body.role)
    except (TemplateError,ValueError) as e:
        raise HTTPException(422,str(e)) from None


@app.post("/api/vps/probe")
def probe_vps(body: VpsProbeData, request: Request, _=Depends(write_access)):
    try:
        return vps_install.preflight(body.ip,body.port,body.password,
                                     body.domain.strip().lower())
    except ValueError as e:
        raise HTTPException(422,str(e)) from None
    except Exception:
        raise HTTPException(502,"SSH не отвечает или доступ root не подтверждён") from None


@app.post("/api/vps/install")
def install_vps(body: VpsInstallData, request: Request, _=Depends(write_access)):
    if not body.confirm_clean:
        raise HTTPException(422,"Подтверди установку только на чистый VPS")
    if not storage.get_panel().get("has_token"):
        raise HTTPException(422,"Сначала подключи Remnawave API в настройках")
    try:
        return vps_install.start_install(
            code=body.code.upper().strip(),country=body.country.upper(),
            name=body.name.strip(),domain=body.domain.strip().lower(),
            role=body.role,ip=body.ip,port=body.port,password=body.password,
            fingerprint_value=body.fingerprint,panel_ip=body.panel_ip,
            existing_node_id=body.existing_node_id,preset_id=body.preset_id)
    except (ValueError,TemplateError,remnawave.PanelError) as e:
        raise HTTPException(422,str(e)) from None
    except LookupError:
        raise HTTPException(404,"Сохранённая нода больше не существует") from None
    except sqlite3.IntegrityError:
        raise HTTPException(409,"Нода или этот VPS уже добавлены. Открой существующую карточку.") from None
    except Exception:
        raise HTTPException(502,"Не удалось подтвердить VPS и начать установку") from None


@app.get("/api/vps/jobs/{node_id}")
def vps_job_status(node_id: str, _=Depends(read_access)):
    try:
        result=storage.get_install_job(node_id)
    except LookupError:
        raise HTTPException(404,"Установка не найдена") from None
    return result


@app.post("/api/vps/jobs/{node_id}/resume")
def resume_vps(node_id: str, body: VpsResumeData, _=Depends(write_access)):
    try:
        return vps_install.start_resume(node_id, body.password, body.confirm_existing)
    except (ValueError, TemplateError, remnawave.PanelError, LookupError) as e:
        _fail(e)
    except Exception:
        raise HTTPException(502, "Не удалось подключиться к сохранённому VPS по SSH") from None


@app.post("/api/vps/jobs/{node_id}/forget")
def forget_failed_vps(node_id: str, body: VpsForgetData, _=Depends(write_access)):
    if not body.confirm_local_only:
        raise HTTPException(422, "Подтверди удаление только записи без изменений на VPS")
    try:
        return storage.delete_failed_install(node_id)
    except (ValueError, LookupError, sqlite3.IntegrityError) as e:
        _fail(e)



@app.get("/api/node-certificates")
def node_certificates(_=Depends(read_access)):
    return node_cert_sync.status()


class NodeTLSMigrationData(BaseModel):
    code: str = Field(min_length=2,max_length=32)
    certificate_job_id: str = Field(min_length=30,max_length=45)
    compose_job_id: str = Field(min_length=30,max_length=45)


@app.post("/api/node-certificates/{node_id}/migrate")
def migrate_node_certificate(node_id: str,body: NodeTLSMigrationData,
                             _=Depends(write_access)):
    # Only the Manager-created, exclusively attached Remnawave profile is
    # eligible. No SSH, Panel filesystem, other Nodes, or shared profiles.
    try:
        return node_cert_sync.migrate_to_local_paths(
            node_id,body.code,body.certificate_job_id,body.compose_job_id)
    except (node_cert_sync.CertificateSyncError,agent_transport.AgentError,LookupError) as exc:
        raise HTTPException(422,str(exc)) from None


@app.post("/api/node-certificates/{node_id}/sync")
def sync_node_certificate(node_id: str, _=Depends(write_access)):
    try:
        return node_cert_sync.sync(node_id)
    except (node_cert_sync.CertificateSyncError,agent_transport.AgentError,LookupError) as e:
        raise HTTPException(422,str(e)) from None


class AgentHeartbeatData(BaseModel):
    version: str = Field(default="",max_length=40)
    metrics: dict = Field(default_factory=dict)


class AgentTaskData(BaseModel):
    action: str = Field(min_length=4,max_length=35)
    payload: dict = Field(default_factory=dict)
    confirmed: bool = False


class AgentBootstrapData(BaseModel):
    password: str = Field(min_length=1,max_length=512)
    confirm_ssh_migration: bool = False


class AgentRevokeData(BaseModel):
    confirmed: bool = False


def agent_required(request: Request):
    node_id=request.headers.get("X-Node-Id","")
    if not agent_transport.authenticate(node_id,request.headers.get("Authorization","")):
        raise HTTPException(401,"Агент не авторизован")
    return node_id


@app.post("/api/agent/v1/heartbeat")
def agent_heartbeat(body: AgentHeartbeatData, node_id=Depends(agent_required)):
    try:
        return agent_transport.heartbeat(node_id,body.model_dump())
    except agent_transport.AgentError as e:
        raise HTTPException(422,str(e)) from None


@app.get("/api/agent/v1/pull")
def agent_pull(node_id=Depends(agent_required)):
    return agent_transport.poll(node_id)


@app.post("/api/agent/v1/report")
def agent_report(body: dict, node_id=Depends(agent_required)):
    try:
        if len(json.dumps(body))>155000:
            raise HTTPException(413,"Результат агента слишком большой")
        return agent_transport.report(node_id,body)
    except agent_transport.AgentError as e:
        raise HTTPException(422,str(e)) from None


@app.get("/api/agents")
def agents_status(_=Depends(read_access)):
    return {"agents":agent_transport.nodes_status()}


@app.post("/api/agents/{node_id}/bootstrap")
def bootstrap_agent(node_id: str,body: AgentBootstrapData,_=Depends(write_access)):
    try:
        return agent_bootstrap.install_existing(node_id,body.password,body.confirm_ssh_migration)
    except (LookupError,ValueError) as e:
        raise HTTPException(422,str(e)) from None
    except Exception:
        raise HTTPException(502,"Не удалось установить агент по первоначальному SSH") from None


@app.post("/api/agents/{node_id}/repair-helper")
def repair_agent_helper(node_id: str, body: AgentBootstrapData, _=Depends(write_access)):
    """One-time recovery for the first agent install's broken sudo sandbox."""
    try:
        return agent_bootstrap.repair_existing(
            node_id,body.password,body.confirm_ssh_migration)
    except (LookupError,agent_bootstrap.AgentBootstrapError,ValueError) as e:
        raise HTTPException(422,str(e)) from None
    except Exception:
        raise HTTPException(502,
            "Не удалось исправить служебные права агента на VPS") from None


@app.post("/api/agents/{node_id}/tasks")
def agent_enqueue(node_id: str, body: AgentTaskData, _=Depends(write_access)):
    if body.action in ("docker.restart","service.restart","config.apply") and not body.confirmed:
        raise HTTPException(422,"Подтверди изменение VPS")
    try:
        return agent_transport.enqueue(node_id,body.action,body.payload)
    except (agent_transport.AgentError,LookupError) as e:
        raise HTTPException(422,str(e)) from None


@app.get("/api/agents/{node_id}/tasks/{job_id}")
def agent_job(node_id: str,job_id: str,_=Depends(read_access)):
    try:
        return agent_transport.job_status(node_id,job_id)
    except LookupError:
        raise HTTPException(404,"Задание не найдено") from None


@app.post("/api/agents/{node_id}/revoke")
def agent_revoke(node_id: str,body: AgentRevokeData,_=Depends(write_access)):
    if not body.confirmed:
        raise HTTPException(422,"Подтверди отключение агента")
    return agent_transport.revoke(node_id)


@app.post("/api/nodes")
def create_node(body: NodeData, _=Depends(write_access)):
    try:
        endpoint = Endpoint(body.code.upper().strip(), body.domain.lower().strip(),
                            body.country.upper().strip())
        return storage.create_node(
            code=endpoint.code, name=body.name.strip(), domain=endpoint.domain,
            country=endpoint.country, role=body.role)
    except (ValueError, sqlite3.IntegrityError) as e:
        _fail(e)


class NodeRemovalConfirm(BaseModel):
    code: str = Field(min_length=2, max_length=32)
    remove_remote: bool = True
    delete_profile: bool = True
    shared_confirmation: str = Field(default="", max_length=100)
    expected_shared_ids: list[str] = Field(default_factory=list, max_length=1000)


@app.get("/api/nodes/{node_id}/removal-preview")
def node_removal_preview(node_id: str, _=Depends(read_access)):
    try:
        return node_removal.preview(node_id)
    except (node_lifecycle.LifecycleError, LookupError) as e:
        raise HTTPException(422, str(e)) from None


@app.post("/api/nodes/{node_id}/remove")
def node_removal_execute(node_id: str, body: NodeRemovalConfirm,
                        _=Depends(write_access)):
    try:
        return node_removal.remove(
            node_id, body.code, delete_remote=body.remove_remote,
            delete_profile=body.delete_profile,
            shared_confirmation=body.shared_confirmation,
            expected_shared_ids=body.expected_shared_ids)
    except (node_removal.RemovalError, node_lifecycle.LifecycleError, LookupError) as e:
        raise HTTPException(422, str(e)) from None


class NodeArchiveData(BaseModel):
    archived: bool


class NodeLifecycleConfirm(BaseModel):
    code: str = Field(min_length=2,max_length=32)
    delete_profile: bool = True


class NodeAbandonConfirm(BaseModel):
    code: str = Field(min_length=2,max_length=32)
    acknowledge_unverified: bool = False


@app.get("/api/nodes/{node_id}/lifecycle")
def lifecycle_preview(node_id: str, _=Depends(read_access)):
    try:
        return node_lifecycle.preview(node_id)
    except LookupError as e:
        raise HTTPException(404,str(e)) from None


@app.put("/api/nodes/{node_id}/archive")
def lifecycle_archive(node_id: str,body: NodeArchiveData,_=Depends(write_access)):
    try:
        return node_lifecycle.archive(node_id,body.archived)
    except (node_lifecycle.LifecycleError,LookupError) as e:
        raise HTTPException(422,str(e)) from None


@app.post("/api/nodes/{node_id}/detach-dependencies")
def lifecycle_detach(node_id: str,body: NodeLifecycleConfirm,_=Depends(write_access)):
    try:
        return node_lifecycle.detach_dependencies(node_id,body.code)
    except (node_lifecycle.LifecycleError,LookupError) as e:
        raise HTTPException(422,str(e)) from None


@app.post("/api/nodes/{node_id}/forget")
def lifecycle_forget(node_id: str,body: NodeLifecycleConfirm,_=Depends(write_access)):
    try:
        return node_lifecycle.forget(node_id,body.code)
    except (node_lifecycle.LifecycleError,LookupError) as e:
        raise HTTPException(422,str(e)) from None


@app.post("/api/nodes/{node_id}/abandon")
def lifecycle_abandon(node_id: str,body: NodeAbandonConfirm,_=Depends(write_access)):
    try:
        return node_lifecycle.abandon_interrupted(
            node_id,body.code,body.acknowledge_unverified)
    except (node_lifecycle.LifecycleError,LookupError) as e:
        raise HTTPException(422,str(e)) from None


@app.post("/api/nodes/{node_id}/delete-remnawave")
def lifecycle_remnawave(node_id: str,body: NodeLifecycleConfirm,_=Depends(write_access)):
    try:
        return node_lifecycle.delete_remnawave(node_id,body.code,body.delete_profile)
    except (node_lifecycle.LifecycleError,LookupError) as e:
        raise HTTPException(422,str(e)) from None


@app.post("/api/nodes/{node_id}/full/start")
def lifecycle_start(node_id: str, body: NodeLifecycleConfirm, _=Depends(write_access)):
    raise HTTPException(410, "Очистка VPS отключена. Используй удаление через Remnawave API.")


@app.post("/api/nodes/{node_id}/full/advance")
def lifecycle_advance(node_id: str, body: NodeLifecycleConfirm, _=Depends(write_access)):
    raise HTTPException(410, "Очистка VPS отключена. Используй удаление через Remnawave API.")


@app.delete("/api/nodes/{node_id}")
def delete_node_draft(node_id: str, _=Depends(write_access)):
    try:
        return storage.delete_unused_draft(node_id)
    except (ValueError, LookupError) as e:
        _fail(e)
    except sqlite3.IntegrityError:
        raise HTTPException(409,"Черновик используется другой записью. Удаление отменено.") from None


@app.post("/api/bridges")
def create_bridge(body: BridgeData, _=Depends(write_access)):
    try:
        return storage.create_bridge(body.entry_id, body.name.strip())
    except (ValueError, LookupError, sqlite3.IntegrityError) as e:
        _fail(e)


@app.get("/api/bridges/{bridge_id}")
def bridge_detail(bridge_id: str, _=Depends(read_access)):
    try:
        result = storage.get_bridge(bridge_id)
        snapshot = storage.get_snapshot(bridge_id)
        result["has_snapshot"] = snapshot is not None
        result["snapshot_preview"] = safe_preview(snapshot) if snapshot else None
        return result
    except LookupError as e:
        _fail(e)


@app.post("/api/bridges/{bridge_id}/import")
def import_existing(bridge_id: str, body: SnapshotData, _=Depends(write_access)):
    if not body.confirm_read_only:
        raise HTTPException(422, "Подтверди импорт копии действующего конфига")
    if len(json.dumps(body.config, ensure_ascii=False).encode()) > 250_000:
        raise HTTPException(413, "Конфиг слишком большой")
    try:
        return storage.save_snapshot(bridge_id, body.config, expected_revision=body.revision)
    except (TemplateError, LookupError, ValueError) as e:
        _fail(e)


@app.post("/api/bridges/{bridge_id}/plans")
def preview_exit(bridge_id: str, body: ExitPlanData, _=Depends(write_access)):
    try:
        outgoing_id = body.outgoing_uuid or str(uuid.uuid4())
        return service.prepare_bridge_exit(
            bridge_id, body.exit_id, outgoing_id, body.inbound_port, body.config_template_id)
    except (TemplateError, LookupError, ValueError, sqlite3.IntegrityError) as e:
        _fail(e)


@app.get("/api/plans/{plan_id}")
def get_plan(plan_id: str, _=Depends(read_access)):
    try:
        return service.plan_public(plan_id)
    except LookupError as e:
        _fail(e)


@app.post("/api/plans/{plan_id}/approve")
def approve(plan_id: str, _=Depends(write_access)):
    try:
        return storage.approve_plan(plan_id)
    except (LookupError, ValueError) as e:
        _fail(e)


@app.get("/api/template/default")
def default_bridge_template(_=Depends(read_access)):
    path = Path(__file__).resolve().parent / "data" / "xray_bridge_template.json"
    return {"name":"XPPN · Bridge VLESS TLS RAW","kind":"xray",
            "content":path.read_text(encoding="utf-8")}


@app.get("/api/template/variables")
def template_variables(_=Depends(read_access)):
    return {
        "note": "Variables are structured and typed; never blindly replace arbitrary JSON strings.",
        "variables": [
            {"key": "source.code", "description": "Код входной ноды"},
            {"key": "source.domain", "description": "TLS-путь и сертификат входной ноды"},
            {"key": "exit.code", "description": "Код первого выходного сервера"},
            {"key": "exit.domain", "description": "Адрес и TLS SNI выхода"},
            {"key": "bridge.user_id", "description": "Межсерверный UUID — секрет"},
            {"key": "additional.inbound_port", "description": "Новый порт выделяется автоматически, не заполняется текстовой заменой"},
        ]
    }



class ConfigFileData(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    kind: str
    content: str = Field(min_length=1, max_length=250000)
    revision: int | None = None


class PresetData(BaseModel):
    mode: str = Field(default="custom",pattern=r"^(custom|direct|bridge)$")
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=600)
    config_ids: list[str] = Field(min_length=1, max_length=4)


@app.get("/api/configs")
def configs(_=Depends(read_access)):
    return library.list_files()


@app.post("/api/configs")
def new_config(body: ConfigFileData, _=Depends(write_access)):
    try:
        return library.save_file(name=body.name, kind=body.kind, content=body.content)
    except (ValueError, sqlite3.IntegrityError) as e:
        _fail(e)


@app.get("/api/configs/{config_id}")
def config_detail(config_id: str, _=Depends(read_access)):
    try:
        return library.get_file(config_id)
    except LookupError as e:
        _fail(e)


@app.put("/api/configs/{config_id}")
def edit_config(config_id: str, body: ConfigFileData, _=Depends(write_access)):
    try:
        return library.save_file(
            name=body.name, kind=body.kind, content=body.content,
            file_id=config_id, revision=body.revision)
    except (ValueError, LookupError) as e:
        _fail(e)


@app.delete("/api/configs/{config_id}")
def delete_config(config_id: str, _=Depends(write_access)):
    try:
        return library.delete_file(config_id)
    except (ValueError, LookupError) as e:
        _fail(e)


@app.get("/api/presets")
def presets(_=Depends(read_access)):
    return library.list_presets()


@app.post("/api/presets")
def new_preset(body: PresetData, _=Depends(write_access)):
    try:
        return library.save_preset(
            name=body.name, description=body.description, config_ids=body.config_ids,mode=body.mode)
    except (ValueError, LookupError, sqlite3.IntegrityError) as e:
        _fail(e)


@app.put("/api/presets/{preset_id}")
def edit_preset(preset_id: str, body: PresetData, _=Depends(write_access)):
    try:
        return library.save_preset(
            name=body.name, description=body.description,
            config_ids=body.config_ids, preset_id=preset_id,mode=body.mode)
    except (ValueError, LookupError) as e:
        _fail(e)


@app.delete("/api/presets/{preset_id}")
def delete_preset(preset_id: str, _=Depends(write_access)):
    try:
        return library.delete_preset(preset_id)
    except (LookupError,) as e:
        _fail(e)
