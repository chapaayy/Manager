from fastapi import APIRouter, Depends, HTTPException

from .. import web_updates
from ..core.auth import read_access, write_access

router = APIRouter()


@router.get("/api/health")
def health():
    return {"ok": True, "product": "XPPN Manager 2.1 Preview", "deployment": False}


@router.get("/api/system/update")
def update_status(_=Depends(read_access)):
    return web_updates.status()


@router.post("/api/system/update/check")
def update_check(_=Depends(write_access)):
    try:
        return web_updates.check_available()
    except ValueError as exc:
        raise HTTPException(503, str(exc)) from None


@router.post("/api/system/update")
def trigger_update(_=Depends(write_access)):
    try:
        return web_updates.request_update()
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
