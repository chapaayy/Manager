from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import agent_bootstrap, agent_transport
from ..nodes import security as security_settings
from ..core.auth import read_access, write_access
from .node_access import node_password

router = APIRouter()


class SSHProtectionHelperData(BaseModel):
    password: str = Field(default="", max_length=512)
    confirmed: bool = False


class SSHProtectionInstallData(BaseModel):
    admin_ip: str = Field(min_length=7, max_length=45)
    confirmed: bool = False


class SSHProtectionUnbanData(BaseModel):
    ip: str = Field(min_length=7, max_length=45)
    confirmed: bool = False


class NodeSecuritySettingsData(BaseModel):
    config: dict
    revision: int = Field(ge=0)


class NodeSecurityApplyData(BaseModel):
    revision: int = Field(ge=1)
    confirmed: bool = False


@router.post("/api/agents/{node_id}/ssh-protection/helper")
def ssh_protection_helper(
    node_id: str, body: SSHProtectionHelperData, _=Depends(write_access)
):
    try:
        return agent_bootstrap.enable_ssh_security(
            node_id, node_password(node_id, body.password), body.confirmed
        )
    except (
        LookupError,
        agent_bootstrap.AgentBootstrapError,
        ValueError,
    ) as exc:
        raise HTTPException(422, str(exc)) from None


@router.post("/api/agents/{node_id}/ssh-protection/install")
def ssh_protection_install(
    node_id: str, body: SSHProtectionInstallData, _=Depends(write_access)
):
    if not body.confirmed:
        raise HTTPException(422, "Подтверди установку только SSH Fail2Ban")
    try:
        return agent_transport.enqueue(
            node_id,
            "security.fail2ban.install",
            body.model_dump(),
            ttl=900,
            internal=True,
        )
    except (LookupError, agent_transport.AgentError) as exc:
        raise HTTPException(422, str(exc)) from None


@router.post("/api/agents/{node_id}/ssh-protection/unban")
def ssh_protection_unban(
    node_id: str, body: SSHProtectionUnbanData, _=Depends(write_access)
):
    if not body.confirmed:
        raise HTTPException(422, "Подтверди разблокировку SSH IP")
    try:
        return agent_transport.enqueue(
            node_id,
            "security.fail2ban.unban",
            body.model_dump(),
            ttl=300,
            internal=True,
        )
    except (LookupError, agent_transport.AgentError) as exc:
        raise HTTPException(422, str(exc)) from None


@router.get("/api/nodes/{node_id}/security-settings")
def node_security_settings(node_id: str, _=Depends(read_access)):
    try:
        return security_settings.get(node_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from None


@router.put("/api/nodes/{node_id}/security-settings")
def node_security_settings_save(
    node_id: str, body: NodeSecuritySettingsData, _=Depends(write_access)
):
    try:
        return security_settings.save(node_id, body.config, body.revision)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


@router.post("/api/nodes/{node_id}/security-settings/apply")
def node_security_settings_apply(
    node_id: str, body: NodeSecurityApplyData, _=Depends(write_access)
):
    if not body.confirmed:
        raise HTTPException(422, "Подтверди применение настроек сети и защиты")
    try:
        return security_settings.queue_apply(node_id, body.revision)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from None
    except (ValueError, agent_transport.AgentError) as exc:
        raise HTTPException(422, str(exc)) from None
