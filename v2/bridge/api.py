from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..core.auth import read_access, write_access

router = APIRouter()


class BridgeData(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    entry_id: str


class SnapshotData(BaseModel):
    config: dict
    revision: int = Field(ge=0)
    confirm_read_only: bool = False


class ExitPlanData(BaseModel):
    exit_id: str
    outgoing_uuid: str | None = None
    inbound_port: int | None = Field(default=None, ge=8444, le=8999)
    config_template_id: str | None = None


_DISABLED = (
    "Система мостов временно отключена. Используй конфигурации нод отдельно."
)


@router.post("/api/bridges")
def create_bridge(body: BridgeData, _=Depends(write_access)):
    raise HTTPException(410, _DISABLED)


@router.get("/api/bridges/{bridge_id}")
def bridge_detail(bridge_id: str, _=Depends(read_access)):
    raise HTTPException(410, _DISABLED)


@router.post("/api/bridges/{bridge_id}/import")
def import_existing(
    bridge_id: str, body: SnapshotData, _=Depends(write_access)
):
    raise HTTPException(410, _DISABLED)


@router.post("/api/bridges/{bridge_id}/plans")
def preview_exit(
    bridge_id: str, body: ExitPlanData, _=Depends(write_access)
):
    raise HTTPException(410, _DISABLED)


@router.get("/api/plans/{plan_id}")
def get_plan(plan_id: str, _=Depends(read_access)):
    raise HTTPException(410, _DISABLED)


@router.post("/api/plans/{plan_id}/approve")
def approve(plan_id: str, _=Depends(write_access)):
    raise HTTPException(410, _DISABLED)


@router.get("/api/template/default")
def default_bridge_template(_=Depends(read_access)):
    raise HTTPException(410, _DISABLED)


@router.get("/api/template/variables")
def template_variables(_=Depends(read_access)):
    return {
        "note": "Доступны только переменные самой ноды. Топология мостов отключена.",
        "variables": [
            {"key": "source.code", "description": "Код ноды"},
            {
                "key": "source.domain",
                "description": "Домен и TLS-пути ноды",
            },
        ],
    }
