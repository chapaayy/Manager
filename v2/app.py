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

from . import library, remnawave, service, storage
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
    if isinstance(exc, (ValueError, TemplateError, sqlite3.IntegrityError)):
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
            name=body.name, description=body.description, config_ids=body.config_ids)
    except (ValueError, LookupError, sqlite3.IntegrityError) as e:
        _fail(e)


@app.put("/api/presets/{preset_id}")
def edit_preset(preset_id: str, body: PresetData, _=Depends(write_access)):
    try:
        return library.save_preset(
            name=body.name, description=body.description,
            config_ids=body.config_ids, preset_id=preset_id)
    except (ValueError, LookupError) as e:
        _fail(e)


@app.delete("/api/presets/{preset_id}")
def delete_preset(preset_id: str, _=Depends(write_access)):
    try:
        return library.delete_preset(preset_id)
    except (LookupError,) as e:
        _fail(e)
