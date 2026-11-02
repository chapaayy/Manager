import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import node_lifecycle, node_removal, storage
from ..core.auth import read_access, write_access
from ..core.errors import api_failure
from ..template_engine import Endpoint

router = APIRouter()


class NodeData(BaseModel):
    code: str
    name: str = Field(min_length=1, max_length=80)
    country: str
    domain: str
    role: str = Field(default="regular", pattern=r"^regular$")


class NodeRemovalConfirm(BaseModel):
    code: str = Field(min_length=2, max_length=32)
    remove_remote: bool = True
    delete_profile: bool = True
    shared_confirmation: str = Field(default="", max_length=100)
    expected_shared_ids: list[str] = Field(default_factory=list, max_length=1000)


class NodeArchiveData(BaseModel):
    archived: bool


class NodeLifecycleConfirm(BaseModel):
    code: str = Field(min_length=2, max_length=32)
    delete_profile: bool = True


class NodeAbandonConfirm(BaseModel):
    code: str = Field(min_length=2, max_length=32)
    acknowledge_unverified: bool = False


@router.post("/api/nodes")
def create_node(body: NodeData, _=Depends(write_access)):
    try:
        endpoint = Endpoint(
            body.code.upper().strip(),
            body.domain.lower().strip(),
            body.country.upper().strip(),
        )
        return storage.create_node(
            code=endpoint.code,
            name=body.name.strip(),
            domain=endpoint.domain,
            country=endpoint.country,
            role=body.role,
        )
    except (ValueError, sqlite3.IntegrityError) as exc:
        api_failure(exc)


@router.get("/api/nodes/{node_id}/removal-preview")
def node_removal_preview(node_id: str, _=Depends(read_access)):
    try:
        return node_removal.preview(node_id)
    except (node_lifecycle.LifecycleError, LookupError) as exc:
        raise HTTPException(422, str(exc)) from None


@router.post("/api/nodes/{node_id}/remove")
def node_removal_execute(
    node_id: str, body: NodeRemovalConfirm, _=Depends(write_access)
):
    try:
        return node_removal.remove(
            node_id,
            body.code,
            delete_remote=body.remove_remote,
            delete_profile=body.delete_profile,
            shared_confirmation=body.shared_confirmation,
            expected_shared_ids=body.expected_shared_ids,
        )
    except (
        node_removal.RemovalError,
        node_lifecycle.LifecycleError,
        LookupError,
    ) as exc:
        raise HTTPException(422, str(exc)) from None


@router.get("/api/nodes/{node_id}/lifecycle")
def lifecycle_preview(node_id: str, _=Depends(read_access)):
    try:
        return node_lifecycle.preview(node_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from None


@router.put("/api/nodes/{node_id}/archive")
def lifecycle_archive(
    node_id: str, body: NodeArchiveData, _=Depends(write_access)
):
    try:
        return node_lifecycle.archive(node_id, body.archived)
    except (node_lifecycle.LifecycleError, LookupError) as exc:
        raise HTTPException(422, str(exc)) from None


@router.post("/api/nodes/{node_id}/detach-dependencies")
def lifecycle_detach(
    node_id: str, body: NodeLifecycleConfirm, _=Depends(write_access)
):
    try:
        return node_lifecycle.detach_dependencies(node_id, body.code)
    except (node_lifecycle.LifecycleError, LookupError) as exc:
        raise HTTPException(422, str(exc)) from None


@router.post("/api/nodes/{node_id}/forget")
def lifecycle_forget(
    node_id: str, body: NodeLifecycleConfirm, _=Depends(write_access)
):
    try:
        return node_lifecycle.forget(node_id, body.code)
    except (node_lifecycle.LifecycleError, LookupError) as exc:
        raise HTTPException(422, str(exc)) from None


@router.post("/api/nodes/{node_id}/abandon")
def lifecycle_abandon(
    node_id: str, body: NodeAbandonConfirm, _=Depends(write_access)
):
    try:
        return node_lifecycle.abandon_interrupted(
            node_id, body.code, body.acknowledge_unverified
        )
    except (node_lifecycle.LifecycleError, LookupError) as exc:
        raise HTTPException(422, str(exc)) from None


@router.post("/api/nodes/{node_id}/delete-remnawave")
def lifecycle_remnawave(
    node_id: str, body: NodeLifecycleConfirm, _=Depends(write_access)
):
    try:
        return node_lifecycle.delete_remnawave(
            node_id, body.code, body.delete_profile
        )
    except (node_lifecycle.LifecycleError, LookupError) as exc:
        raise HTTPException(422, str(exc)) from None


@router.post("/api/nodes/{node_id}/full/start")
def lifecycle_start(
    node_id: str, body: NodeLifecycleConfirm, _=Depends(write_access)
):
    raise HTTPException(
        410, "Очистка VPS отключена. Используй удаление через Remnawave API."
    )


@router.post("/api/nodes/{node_id}/full/advance")
def lifecycle_advance(
    node_id: str, body: NodeLifecycleConfirm, _=Depends(write_access)
):
    raise HTTPException(
        410, "Очистка VPS отключена. Используй удаление через Remnawave API."
    )


@router.delete("/api/nodes/{node_id}")
def delete_node_draft(node_id: str, _=Depends(write_access)):
    try:
        return storage.delete_unused_draft(node_id)
    except (ValueError, LookupError) as exc:
        api_failure(exc)
    except sqlite3.IntegrityError:
        raise HTTPException(
            409, "Черновик используется другой записью. Удаление отменено."
        ) from None
