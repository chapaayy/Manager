import json

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .. import agent_bootstrap, agent_release, agent_transport, agent_updates
from ..core.auth import read_access, write_access
from .node_access import node_password

router = APIRouter()


class AgentHeartbeatData(BaseModel):
    version: str = Field(default="", max_length=40)
    metrics: dict = Field(default_factory=dict)


class AgentTaskData(BaseModel):
    action: str = Field(min_length=4, max_length=35)
    payload: dict = Field(default_factory=dict)
    confirmed: bool = False


class AgentBootstrapData(BaseModel):
    password: str = Field(default="", max_length=512)
    confirm_ssh_migration: bool = False


class AgentUpdateData(BaseModel):
    confirmed: bool = False
    password: str = Field(default="", max_length=512)


class AgentAutoUpdateData(BaseModel):
    enabled: bool


class AgentRevokeData(BaseModel):
    confirmed: bool = False


def agent_required(request: Request):
    node_id = request.headers.get("X-Node-Id", "")
    if not agent_transport.authenticate(
        node_id, request.headers.get("Authorization", "")
    ):
        raise HTTPException(401, "Агент не авторизован")
    return node_id


@router.post("/api/agent/v1/heartbeat")
def agent_heartbeat(body: AgentHeartbeatData, node_id=Depends(agent_required)):
    try:
        return agent_transport.heartbeat(node_id, body.model_dump())
    except agent_transport.AgentError as exc:
        raise HTTPException(422, str(exc)) from None


@router.get("/api/agent/v1/pull")
async def agent_pull(node_id=Depends(agent_required)):
    return await agent_transport.long_poll(node_id, 25)


@router.post("/api/agent/v1/report")
def agent_report(body: dict, node_id=Depends(agent_required)):
    try:
        if len(json.dumps(body)) > 155000:
            raise HTTPException(413, "Результат агента слишком большой")
        return agent_transport.report(node_id, body)
    except agent_transport.AgentError as exc:
        raise HTTPException(422, str(exc)) from None


@router.get("/api/agents")
def agents_status(_=Depends(read_access)):
    return {"agents": agent_transport.nodes_status()}


@router.get("/api/agents/{node_id}/monitoring")
def agent_monitoring(
    node_id: str, seconds: int = 3600, since: int = 0, _=Depends(read_access)
):
    try:
        return agent_transport.monitoring_history(node_id, seconds, since)
    except (LookupError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from None


@router.get("/api/agents/{node_id}/update-status")
def agent_update_status(node_id: str, _=Depends(read_access)):
    try:
        return agent_updates.current(node_id)
    except (LookupError, agent_updates.UpdateError) as exc:
        raise HTTPException(422, str(exc)) from None


@router.put("/api/agents/{node_id}/auto-update")
def agent_set_auto(
    node_id: str, body: AgentAutoUpdateData, _=Depends(write_access)
):
    try:
        return agent_updates.set_auto(node_id, body.enabled)
    except (LookupError, agent_updates.UpdateError) as exc:
        raise HTTPException(422, str(exc)) from None


@router.post("/api/agents/{node_id}/update")
def agent_start_update(node_id: str, body: AgentUpdateData, _=Depends(write_access)):
    try:
        return agent_updates.manual(
            node_id,
            confirmed=body.confirmed,
            password=node_password(node_id, body.password),
        )
    except (
        LookupError,
        agent_updates.UpdateError,
        agent_bootstrap.AgentBootstrapError,
    ) as exc:
        raise HTTPException(422, str(exc)) from None


@router.get("/api/agent/v1/update/manifest")
def agent_update_manifest(node_id=Depends(agent_required)):
    return agent_release.release()


@router.get("/api/agent/v1/update/binary/{arch}")
def agent_binary(arch: str, node_id=Depends(agent_required)):
    try:
        path = agent_release.artifact(arch)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "Artifact unavailable") from None
    return FileResponse(
        str(path),
        media_type="application/octet-stream",
        headers={"Cache-Control": "no-store"},
    )


@router.post("/api/agents/{node_id}/bootstrap")
def bootstrap_agent(
    node_id: str, body: AgentBootstrapData, _=Depends(write_access)
):
    try:
        return agent_bootstrap.install_existing(
            node_id,
            node_password(node_id, body.password),
            body.confirm_ssh_migration,
        )
    except (LookupError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from None
    except Exception:
        raise HTTPException(
            502, "Не удалось установить агент по первоначальному SSH"
        ) from None


@router.post("/api/agents/{node_id}/repair-helper")
def repair_agent_helper(
    node_id: str, body: AgentBootstrapData, _=Depends(write_access)
):
    try:
        return agent_bootstrap.repair_existing(
            node_id,
            node_password(node_id, body.password),
            body.confirm_ssh_migration,
        )
    except (
        LookupError,
        agent_bootstrap.AgentBootstrapError,
        ValueError,
    ) as exc:
        raise HTTPException(422, str(exc)) from None
    except Exception:
        raise HTTPException(
            502, "Не удалось исправить служебные права агента на VPS"
        ) from None


@router.post("/api/agents/{node_id}/tasks")
def agent_enqueue(node_id: str, body: AgentTaskData, _=Depends(write_access)):
    if body.action == "agent.update":
        raise HTTPException(
            422, "Обновляй агент через отдельную кнопку в настройках ноды"
        )
    if body.action in ("docker.restart", "service.restart", "config.apply") and not body.confirmed:
        raise HTTPException(422, "Подтверди изменение VPS")
    try:
        return agent_transport.enqueue(node_id, body.action, body.payload)
    except (agent_transport.AgentError, LookupError) as exc:
        raise HTTPException(422, str(exc)) from None


@router.get("/api/agents/{node_id}/tasks/{job_id}")
def agent_job(node_id: str, job_id: str, _=Depends(read_access)):
    try:
        return agent_transport.job_status(node_id, job_id)
    except LookupError:
        raise HTTPException(404, "Задание не найдено") from None


@router.post("/api/agents/{node_id}/revoke")
def agent_revoke(
    node_id: str, body: AgentRevokeData, _=Depends(write_access)
):
    if not body.confirmed:
        raise HTTPException(422, "Подтверди отключение агента")
    return agent_transport.revoke(node_id)
