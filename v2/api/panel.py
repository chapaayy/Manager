import ipaddress

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import remnawave, storage
from ..core.auth import write_access

router = APIRouter()


class PanelData(BaseModel):
    url: str
    token: str = Field(default="", max_length=2048)
    caddy_api_key: str = Field(default="", max_length=2048)
    outbound_ip: str = ""


class PanelProfile(BaseModel):
    uuid: str
    inbounds: list[str] = Field(min_length=1, max_length=30)


@router.put("/api/panel")
def update_panel(body: PanelData, _=Depends(write_access)):
    url = remnawave.validate_url(body.url.strip())
    outbound = body.outbound_ip.strip()
    if outbound:
        try:
            ip = ipaddress.ip_address(outbound)
            if ip.version != 4 or not ip.is_global:
                raise ValueError("Исходящий IP панели должен быть публичным IPv4")
        except ValueError as exc:
            message = str(exc) if "публичным" in str(exc) else "Некорректный исходящий IPv4"
            raise HTTPException(422, message) from None
    if body.token and len(body.token) < 16:
        raise HTTPException(422, "API-токен слишком короткий")
    try:
        return storage.set_panel(
            url=url,
            outbound_ip=outbound,
            token=body.token.strip() if body.token.strip() else None,
            caddy_api_key=body.caddy_api_key.strip() if body.caddy_api_key.strip() else None,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


@router.post("/api/panel/check")
def check_panel(_=Depends(write_access)):
    try:
        return remnawave.panel_status()
    except remnawave.PanelError as exc:
        raise HTTPException(502, str(exc)) from None


@router.put("/api/panel/profile")
def update_panel_profile(body: PanelProfile, _=Depends(write_access)):
    try:
        remnawave.validate_profile_selection(body.uuid, body.inbounds)
        return storage.set_panel_profile(body.uuid, body.inbounds)
    except remnawave.PanelError as exc:
        raise HTTPException(422, str(exc)) from None
