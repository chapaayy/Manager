import sqlite3

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from .. import library
from ..core.auth import read_access, write_access
from ..core.errors import api_failure

router = APIRouter()


class ConfigFileData(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    kind: str
    content: str = Field(min_length=1, max_length=250000)
    revision: int | None = None


class PresetData(BaseModel):
    mode: str = Field(default="custom", pattern=r"^(custom|direct)$")
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=600)
    config_ids: list[str] = Field(min_length=1, max_length=4)


@router.get("/api/configs")
def configs(_=Depends(read_access)):
    return library.list_files()


@router.post("/api/configs")
def new_config(body: ConfigFileData, _=Depends(write_access)):
    try:
        return library.save_file(
            name=body.name, kind=body.kind, content=body.content
        )
    except (ValueError, sqlite3.IntegrityError) as exc:
        api_failure(exc)


@router.get("/api/configs/{config_id}")
def config_detail(config_id: str, _=Depends(read_access)):
    try:
        return library.get_file(config_id)
    except LookupError as exc:
        api_failure(exc)


@router.put("/api/configs/{config_id}")
def edit_config(
    config_id: str, body: ConfigFileData, _=Depends(write_access)
):
    try:
        return library.save_file(
            name=body.name,
            kind=body.kind,
            content=body.content,
            file_id=config_id,
            revision=body.revision,
        )
    except (ValueError, LookupError) as exc:
        api_failure(exc)


@router.delete("/api/configs/{config_id}")
def delete_config(config_id: str, _=Depends(write_access)):
    try:
        return library.delete_file(config_id)
    except (ValueError, LookupError) as exc:
        api_failure(exc)


@router.get("/api/presets")
def presets(_=Depends(read_access)):
    return library.list_presets()


@router.post("/api/presets")
def new_preset(body: PresetData, _=Depends(write_access)):
    try:
        return library.save_preset(
            name=body.name,
            description=body.description,
            config_ids=body.config_ids,
            mode=body.mode,
        )
    except (ValueError, LookupError, sqlite3.IntegrityError) as exc:
        api_failure(exc)


@router.put("/api/presets/{preset_id}")
def edit_preset(
    preset_id: str, body: PresetData, _=Depends(write_access)
):
    try:
        return library.save_preset(
            name=body.name,
            description=body.description,
            config_ids=body.config_ids,
            preset_id=preset_id,
            mode=body.mode,
        )
    except (ValueError, LookupError) as exc:
        api_failure(exc)


@router.delete("/api/presets/{preset_id}")
def delete_preset(preset_id: str, _=Depends(write_access)):
    try:
        return library.delete_preset(preset_id)
    except LookupError as exc:
        api_failure(exc)
