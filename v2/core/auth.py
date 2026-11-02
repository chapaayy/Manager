"""Manager browser authentication and CSRF dependencies."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time

from fastapi import HTTPException, Request, Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from . import config

COOKIE = "xppn_v2_session"
SESSION_MAX = 12 * 3600
_failed_login: dict[str, list[float]] = {}


def validate_configuration() -> None:
    config.session_secret()
    config.admin_username()
    config.admin_password_hash()


def _password_ok(password: str) -> bool:
    value = config.admin_password_hash()
    if value:
        _, iterations, salt, digest = value.replace("$", ":").split(":")
        computed = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt), int(iterations)
        )
        return hmac.compare_digest(computed, bytes.fromhex(digest))
    return hmac.compare_digest(
        hashlib.sha256(password.encode()).digest(),
        hashlib.sha256(config.legacy_admin_password().encode()).digest(),
    )


def signer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(config.session_secret(), salt="xppn-v2-auth-cookie")


def csrf_token(sid: str) -> str:
    return hmac.new(
        config.session_secret().encode(), ("csrf:" + sid).encode(), hashlib.sha256
    ).hexdigest()


def read_access(request: Request) -> str:
    cookie = request.cookies.get(COOKIE)
    if not cookie:
        raise HTTPException(401, "Требуется авторизация")
    try:
        data = signer().loads(cookie, max_age=SESSION_MAX)
    except (BadSignature, SignatureExpired):
        raise HTTPException(401, "Сессия закончилась. Войди повторно") from None
    if (
        not isinstance(data, dict)
        or data.get("version") != 2
        or not isinstance(data.get("sid"), str)
    ):
        raise HTTPException(401, "Недействительная сессия")
    return data["sid"]


def write_access(request: Request) -> str:
    sid = read_access(request)
    token = request.headers.get("X-CSRF-Token", "")
    if not hmac.compare_digest(token, csrf_token(sid)):
        raise HTTPException(403, "Защита формы: обнови страницу")
    return sid


def login(username: str, password: str, request: Request, response: Response) -> dict:
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    failures = [stamp for stamp in _failed_login.get(ip, []) if now - stamp < 900]
    if len(failures) >= 6:
        raise HTTPException(429, "Слишком много попыток. Повтори позже")

    valid_user = hmac.compare_digest(
        username.encode(), config.admin_username().encode()
    )
    if not (valid_user and _password_ok(password)):
        failures.append(now)
        _failed_login[ip] = failures
        raise HTTPException(401, "Неверный пароль")

    _failed_login.pop(ip, None)
    sid = secrets.token_urlsafe(32)
    response.set_cookie(
        COOKIE,
        signer().dumps({"version": 2, "sid": sid}),
        max_age=SESSION_MAX,
        httponly=True,
        samesite="strict",
        secure=config.cookie_secure(),
        path="/",
    )
    return {"ok": True, "csrf": csrf_token(sid)}


def logout(response: Response) -> dict:
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}
