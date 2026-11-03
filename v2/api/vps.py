import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .. import preset_deploy, remnawave, storage
from ..nodes import install as node_install
from ..core.auth import read_access, write_access
from ..core.errors import api_failure
from ..xray import Endpoint, TemplateError
from .node_access import node_password

router = APIRouter()


class VpsProbeData(BaseModel):
    ip: str = Field(min_length=7, max_length=45)
    port: int = Field(default=22, ge=1, le=65535)
    password: str = Field(min_length=1, max_length=512)
    domain: str = Field(min_length=4, max_length=253)


class VpsResumeData(BaseModel):
    password: str = Field(default="", max_length=512)
    confirm_existing: bool = False


class VpsForgetData(BaseModel):
    confirm_local_only: bool = False


class VpsInstallData(VpsProbeData):
    code: str = Field(min_length=2, max_length=20)
    name: str = Field(min_length=3, max_length=80)
    country: str = Field(pattern=r"^[A-Za-z]{2}$")
    role: str = Field(default="regular", pattern=r"^regular$")
    preset_id: str | None = Field(default=None, max_length=64)
    fingerprint: str
    confirm_clean: bool = False
    panel_ip: str = ""
    existing_node_id: str | None = Field(default=None, max_length=64)


class VpsPreviewData(BaseModel):
    preset_id: str | None = Field(default=None, max_length=64)
    role: str = Field(default="regular", pattern=r"^regular$")
    code: str = Field(min_length=2, max_length=20)
    domain: str = Field(min_length=4, max_length=253)
    country: str = Field(pattern=r"^[A-Za-z]{2}$")


@router.post("/api/vps/preview")
def vps_preview(body: VpsPreviewData, _=Depends(write_access)):
    try:
        endpoint = Endpoint(
            body.code.upper().strip(),
            body.domain.lower().strip(),
            body.country.upper().strip(),
        )
        selected = body.preset_id or preset_deploy.default_preset_id()
        return node_install.preview_plan(endpoint, selected, body.role)
    except (TemplateError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from None


@router.post("/api/vps/probe")
def probe_vps(body: VpsProbeData, request: Request, _=Depends(write_access)):
    try:
        return node_install.preflight(
            body.ip, body.port, body.password, body.domain.strip().lower()
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    except Exception:
        raise HTTPException(502, "SSH не отвечает или доступ root не подтверждён") from None


@router.post("/api/vps/install")
def install_vps(body: VpsInstallData, request: Request, _=Depends(write_access)):
    if not body.confirm_clean:
        raise HTTPException(422, "Подтверди установку только на чистый VPS")
    if not storage.get_panel().get("has_token"):
        raise HTTPException(422, "Сначала подключи Remnawave API в настройках")
    try:
        return node_install.start_install(
            code=body.code.upper().strip(),
            country=body.country.upper(),
            name=body.name.strip(),
            domain=body.domain.strip().lower(),
            role=body.role,
            ip=body.ip,
            port=body.port,
            password=body.password,
            fingerprint_value=body.fingerprint,
            panel_ip=body.panel_ip,
            existing_node_id=body.existing_node_id,
            preset_id=body.preset_id,
        )
    except (ValueError, TemplateError, remnawave.PanelError) as exc:
        raise HTTPException(422, str(exc)) from None
    except LookupError:
        raise HTTPException(404, "Сохранённая нода больше не существует") from None
    except sqlite3.IntegrityError:
        raise HTTPException(
            409, "Нода или этот VPS уже добавлены. Открой существующую карточку."
        ) from None
    except Exception:
        raise HTTPException(
            502, "Не удалось подтвердить VPS и начать установку"
        ) from None


@router.get("/api/vps/jobs/{node_id}")
def vps_job_status(node_id: str, _=Depends(read_access)):
    try:
        return storage.get_install_job(node_id)
    except LookupError:
        raise HTTPException(404, "Установка не найдена") from None


@router.post("/api/vps/jobs/{node_id}/resume")
def resume_vps(node_id: str, body: VpsResumeData, _=Depends(write_access)):
    try:
        return node_install.start_resume(
            node_id, node_password(node_id, body.password), body.confirm_existing
        )
    except (ValueError, TemplateError, remnawave.PanelError, LookupError) as exc:
        api_failure(exc)
    except Exception:
        raise HTTPException(
            502, "Не удалось подключиться к сохранённому VPS по SSH"
        ) from None


@router.post("/api/vps/jobs/{node_id}/forget")
def forget_failed_vps(node_id: str, body: VpsForgetData, _=Depends(write_access)):
    if not body.confirm_local_only:
        raise HTTPException(
            422, "Подтверди удаление только записи без изменений на VPS"
        )
    try:
        return storage.delete_failed_install(node_id)
    except (ValueError, LookupError, sqlite3.IntegrityError) as exc:
        api_failure(exc)
