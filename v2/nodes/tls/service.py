"""TLS verification, reload and guarded inline-PEM migration."""
from __future__ import annotations

from copy import deepcopy
import re
import time

from ... import agent_transport, remnawave, storage
from .errors import CertificateSyncError, LocalTLSError
from .profile import certificate_slot, paths
from .state import LOCK, update_status
from .validation import agent_status


def report(node_id: str, data: dict) -> dict:
    node, fingerprint, expires = agent_status(node_id, data)
    job = storage.get_install_job(node_id)
    if not job.get("remote_uuid") or not job.get("profile_uuid"):
        raise LocalTLSError("Нода не зарегистрирована")

    _, certificates = certificate_slot(node, job)
    certificate = certificates[0]
    if certificate != paths(node["domain"]):
        if "key" in certificate or "certificate" in certificate:
            return {
                "expires_at": expires,
                "fingerprint": fingerprint,
                "updated": False,
                "mode": "migration_required",
            }
        raise LocalTLSError(
            "Пути сертификатов в профиле отличаются от файлов ноды"
        )

    with storage.connect() as db:
        previous = db.execute(
            """SELECT fingerprint,last_checked
               FROM node_tls_sync WHERE node_id=?""",
            (node_id,),
        ).fetchone()
    changed = bool(
        previous
        and previous["last_checked"]
        and previous["fingerprint"] != fingerprint
    )
    if changed:
        try:
            remnawave.restart_node(job["remote_uuid"])
        except remnawave.PanelError:
            raise LocalTLSError(
                "Не удалось перезапустить Xray этой ноды через Remnawave API"
            ) from None

        healthy = False
        for _ in range(10):
            time.sleep(2)
            try:
                telemetry = remnawave.node_health(job["remote_uuid"])
                if telemetry["connected"] and telemetry["xray_running"]:
                    healthy = True
                    break
            except remnawave.PanelError:
                pass
        if not healthy:
            raise LocalTLSError(
                "После обновления TLS Xray не подтвердил запуск; отпечаток не обновлён"
            )

    update_status(node_id, fingerprint, expires, changed)
    return {
        "expires_at": expires,
        "fingerprint": fingerprint,
        "updated": changed,
        "mode": "node_local_paths",
    }


def migration(
    node_id: str,
    code: str,
    cert_job_id: str,
    compose_job_id: str,
) -> dict:
    node = storage.get_node(node_id)
    if code != node["code"]:
        raise LocalTLSError("Подтверди точный код ноды")

    agents = {item["id"]: item for item in agent_transport.nodes_status()}
    if not agents.get(node_id, {}).get("online"):
        raise LocalTLSError("Агент должен быть онлайн")

    job = storage.get_install_job(node_id)
    if (
        node["status"] != "ready"
        or not job.get("remote_uuid")
        or not job.get("profile_uuid")
    ):
        raise LocalTLSError("Нода не готова к миграции")

    for job_id, action in (
        (cert_job_id, "cert.status"),
        (compose_job_id, "config.read"),
    ):
        if not isinstance(job_id, str) or len(job_id) > 45:
            raise LocalTLSError("Нет свежей проверки агента")
        state = agent_transport.job_status(node_id, job_id)
        if (
            state["status"] != "done"
            or state["action"] != action
            or time.time() - state["updated_at"] > 300
        ):
            raise LocalTLSError(
                "Проверка агента не завершена или устарела"
            )

    cert_data = agent_transport.job_status(node_id, cert_job_id)["result"]
    compose_data = agent_transport.job_status(node_id, compose_job_id)["result"]
    fingerprint = cert_data.get("fingerprint")
    expires = cert_data.get("expires_at")
    if (
        cert_data.get("domain") != node["domain"]
        or not isinstance(fingerprint, str)
        or not re.fullmatch("[0-9a-f]{64}", fingerprint)
        or type(expires) is not int
        or expires < int(time.time()) + 3600
        or any(key in cert_data for key in ("key", "chain", "certificate"))
    ):
        raise LocalTLSError(
            "Агент не подтвердил действующий сертификат нужной ноды"
        )

    compose = compose_data.get("content")
    if (
        compose_data.get("name") != "node-compose"
        or not isinstance(compose, str)
    ):
        raise LocalTLSError("Не проверен Docker Compose ноды")
    if not re.search(
        r"""(?m)^\s*-\s*['"]?/opt/nginx/certs:/opt/nginx/certs:ro['"]?\s*$""",
        compose,
    ):
        raise LocalTLSError(
            "В Docker Compose ноды нет read-only mount сертификатов"
        )

    profile, certificates = certificate_slot(node, job)
    original = profile["config"]
    certificate = certificates[0]
    expected = paths(node["domain"])
    if certificate == expected:
        update_status(node_id, fingerprint, expires, False)
        return {"migrated": False, "already_file_backed": True}
    if (
        "keyFile" in certificate
        or "certificateFile" in certificate
        or "key" not in certificate
        or "certificate" not in certificate
    ):
        raise LocalTLSError("Неизвестный TLS профиль: миграция запрещена")

    config = deepcopy(original)
    inbounds = [
        inbound
        for inbound in config["inbounds"]
        if inbound.get("tag") == node["code"] + "_VLESS_TLS_IN"
    ]
    inbounds[0]["streamSettings"]["tlsSettings"]["certificates"] = [expected]

    try:
        remnawave.replace_profile_config(job["profile_uuid"], config)
    except remnawave.PanelError:
        raise LocalTLSError("API отклонило локальные пути TLS") from None

    try:
        remnawave.restart_node(job["remote_uuid"])
        ready = False
        for _ in range(12):
            time.sleep(2)
            health = remnawave.node_health(job["remote_uuid"])
            if health["connected"] and health["xray_running"]:
                ready = True
                break
        if not ready:
            raise LocalTLSError("Xray не подтвердил запуск")
    except Exception:
        try:
            remnawave.replace_profile_config(job["profile_uuid"], original)
            remnawave.restart_node(job["remote_uuid"])
        except Exception:
            raise LocalTLSError(
                "Миграция и автоматический откат не подтверждены; проверь профиль своей ноды"
            ) from None
        raise LocalTLSError(
            "Проверка Xray после миграции не прошла; прежний профиль восстановлен"
        ) from None

    update_status(node_id, fingerprint, expires, True)
    return {
        "migrated": True,
        "mode": "node_local_paths",
        "panel_server_unchanged": True,
    }


def apply_agent_export(node_id: str, data: dict) -> dict:
    raise CertificateSyncError(
        "Передача приватных ключей отключена: используй cert.status"
    )


def apply_agent_status(node_id: str, data: dict) -> dict:
    try:
        with LOCK:
            return report(node_id, data)
    except LocalTLSError as exc:
        raise CertificateSyncError(str(exc)) from None


def migrate_to_local_paths(
    node_id: str,
    code: str,
    cert_job_id: str,
    compose_job_id: str,
):
    try:
        with LOCK:
            return migration(
                node_id, code, cert_job_id, compose_job_id
            )
    except LocalTLSError as exc:
        raise CertificateSyncError(str(exc)) from None


def sync(node_id: str) -> dict:
    return agent_transport.enqueue(node_id, "cert.status", ttl=180)
