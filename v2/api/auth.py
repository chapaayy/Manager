from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field

from ..core import auth as auth_core

router = APIRouter()


class Login(BaseModel):
    username: str = Field(default="admin", min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=512)


@router.post("/api/auth/login")
def login(body: Login, request: Request, response: Response):
    return auth_core.login(body.username, body.password, request, response)


@router.get("/api/auth/session")
def session(sid=Depends(auth_core.read_access)):
    return {"ok": True, "csrf": auth_core.csrf_token(sid)}


@router.post("/api/auth/logout")
def logout(response: Response, _=Depends(auth_core.write_access)):
    return auth_core.logout(response)
