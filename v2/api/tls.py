from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import agent_transport
from ..nodes import tls as node_cert_sync
from ..core.auth import read_access, write_access

router = APIRouter()


class NodeTLSMigrationData(BaseModel):
    code: str = Field(min_length=2, max_length=32)
    certificate_job_id: str = Field(min_length=30, max_length=45)
    compose_job_id: str = Field(min_length=30, max_length=45)


@router.get("/api/node-certificates")
def node_certificates(_=Depends(read_access)):
    return node_cert_sync.status()


@router.post("/api/node-certificates/{node_id}/migrate")
def migrate_node_certificate(
    node_id: str, body: NodeTLSMigrationData, _=Depends(write_access)
):
    try:
        return node_cert_sync.migrate_to_local_paths(
            node_id, body.code, body.certificate_job_id, body.compose_job_id
        )
    except (
        node_cert_sync.CertificateSyncError,
        agent_transport.AgentError,
        LookupError,
    ) as exc:
        raise HTTPException(422, str(exc)) from None


@router.post("/api/node-certificates/{node_id}/sync")
def sync_node_certificate(node_id: str, _=Depends(write_access)):
    try:
        return node_cert_sync.sync(node_id)
    except (
        node_cert_sync.CertificateSyncError,
        agent_transport.AgentError,
        LookupError,
    ) as exc:
        raise HTTPException(422, str(exc)) from None
