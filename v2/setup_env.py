"""Interactive installer support: domain, login and secure stored password hash.

Reads password from stdin (NUL-terminated), never from command-line arguments.
Existing encryption secrets and SQLite data are preserved across updates.
"""
import argparse
import base64
import hashlib
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile

ROUNDS = 600000
DOMAIN = re.compile(r"(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
USERNAME = re.compile(r"[A-Za-z0-9_.-]{3,40}\Z")
KEYS = ("XPPN_V2_DB", "XPPN_V2_DOMAIN", "XPPN_V2_ADMIN_USER",
        "XPPN_V2_ADMIN_PASSWORD_HASH", "XPPN_V2_SESSION_SECRET",
        "XPPN_DATA_KEY", "XPPN_V2_COOKIE_SECURE")


class SetupError(ValueError):
    pass


def validate(domain: str, username: str, password: str, *, has_hash: bool) -> tuple[str, str]:
    domain = domain.strip().lower()
    username = username.strip()
    if not DOMAIN.fullmatch(domain) or domain.endswith(".local") or domain.endswith(".example.com"):
        raise SetupError("Укажи публичный домен, например dashboard.myservice.com")
    if not USERNAME.fullmatch(username):
        raise SetupError("Логин: 3–40 латинских символов, цифры, точка, _ или -")
    if password and (len(password) < 12 or len(password) > 256 or "\n" in password or "\r" in password):
        raise SetupError("Пароль должен содержать 12–256 символов без переносов строк")
    if not password and not has_hash:
        raise SetupError("При первой установке обязательно задай пароль не короче 12 символов")
    return domain, username


def make_hash(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ROUNDS)
    return "pbkdf2_sha256$%d$%s$%s" % (ROUNDS, salt.hex(), digest.hex())


def read_env(path: Path) -> tuple[list[str], dict[str, str]]:
    if not path.exists():
        return [], {}
    lines = path.read_text(encoding="utf-8").splitlines()
    values = {}
    for line in lines:
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(.*)", line)
        if match:
            values[match.group(1)] = match.group(2)
    return lines, values


def configure(path: Path, domain: str, username: str, password: str) -> dict:
    path = Path(path)
    lines, old = read_env(path)
    previous_hash = old.get("XPPN_V2_ADMIN_PASSWORD_HASH", "")
    previous_raw = old.get("XPPN_V2_ADMIN_PASSWORD", "")
    supplied = password or (previous_raw if not previous_hash else "")
    domain, username = validate(domain, username, supplied, has_hash=bool(previous_hash))
    hashed = previous_hash if previous_hash and not password else make_hash(supplied)
    if not re.fullmatch(r"pbkdf2_sha256\$\d+\$[a-f0-9]{32}\$[a-f0-9]{64}", hashed):
        raise SetupError("Неверный формат сохранённого хеша пароля")
    key = old.get("XPPN_DATA_KEY", "")
    if key:
        try:
            if len(base64.urlsafe_b64decode(key)) != 32:
                raise ValueError()
        except (ValueError, TypeError) as exc:
            raise SetupError("Старый ключ шифрования повреждён. Базу нельзя перезаписывать.") from exc
    else:
        key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    session = old.get("XPPN_V2_SESSION_SECRET", "")
    if session and len(session) < 32:
        raise SetupError("Найден слишком короткий SESSION_SECRET")
    if not session:
        session = secrets.token_urlsafe(48)
    values = dict(old)
    values.update({
        "XPPN_V2_DB": old.get("XPPN_V2_DB", "/data/xppn-v2.db"),
        "XPPN_V2_DOMAIN": domain,
        "XPPN_V2_ADMIN_USER": username,
        "XPPN_V2_ADMIN_PASSWORD_HASH": hashed,
        "XPPN_V2_SESSION_SECRET": session,
        "XPPN_DATA_KEY": key,
        "XPPN_V2_COOKIE_SECURE": "1",
    })
    values.pop("XPPN_V2_ADMIN_PASSWORD", None)
    others = [ln for ln in lines if not any(ln.startswith(k + "=")
              for k in set(KEYS) | {"XPPN_V2_ADMIN_PASSWORD"})]
    others = [ln for ln in others if not ln or ln.startswith("#") or
              re.fullmatch(r"[A-Z][A-Z0-9_]*=.*", ln)]
    data = "\n".join(others + [k + "=" + values[k] for k in KEYS]) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".xppn-v2-env-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return {"domain": domain, "username": username,
            "keys_preserved": bool(old.get("XPPN_DATA_KEY")),
            "password_changed": bool(password) or not bool(previous_hash)}


def main():
    parser = argparse.ArgumentParser(description="Set XPPN v2 domain and admin credentials")
    parser.add_argument("--file", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--username", required=True)
    args = parser.parse_args()
    raw = sys.stdin.buffer.read(2048)
    if not raw.endswith(b"\0"):
        raise SetupError("Не удалось получить пароль из защищённого ввода")
    result = configure(Path(args.file), args.domain, args.username,
                       raw[:-1].decode("utf-8"))
    print("Домен:", result["domain"])
    print("Логин:", result["username"])
    print("Пароль сохранён только как хеш; секреты базы сохранены.")


if __name__ == "__main__":
    try:
        main()
    except (SetupError, UnicodeDecodeError) as e:
        print("Ошибка настройки:", e, file=sys.stderr)
        raise SystemExit(1)
