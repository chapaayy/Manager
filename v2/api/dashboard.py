from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import storage
from ..core.auth import read_access, write_access

router = APIRouter()


class MonitoringSettingsData(BaseModel):
    interval: float


class NodeSSHCredentialData(BaseModel):
    password: str = Field(min_length=1, max_length=512)


@router.get("/api/dashboard")
def dashboard(_=Depends(read_access)):
    return {
        "panel": storage.get_panel(),
        "nodes": storage.list_nodes(),
        "bridges": [],
        "phase": "preview-only",
    }


@router.get("/api/settings/monitoring")
def monitoring_settings(_=Depends(read_access)):
    return {"interval": storage.monitoring_interval()}


@router.put("/api/settings/monitoring")
def update_monitoring_settings(body: MonitoringSettingsData, _=Depends(write_access)):
    try:
        return storage.set_monitoring_interval(body.interval)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


@router.get("/api/nodes/{node_id}/ssh-credentials")
def get_node_ssh_credentials(node_id: str, _=Depends(read_access)):
    try:
        return storage.node_ssh_credentials(node_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from None


@router.put("/api/nodes/{node_id}/ssh-credentials")
def put_node_ssh_credentials(
    node_id: str, body: NodeSSHCredentialData, _=Depends(write_access)
):
    try:
        storage.save_node_ssh_password(node_id, body.password)
        return storage.node_ssh_credentials(node_id)
    except (LookupError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from None


@router.delete("/api/nodes/{node_id}/ssh-credentials")
def delete_node_ssh_credentials(node_id: str, _=Depends(write_access)):
    try:
        return storage.clear_node_ssh_password(node_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from None
