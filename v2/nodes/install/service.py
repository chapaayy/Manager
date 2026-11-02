"""Installation orchestration. SSH/render/Remnawave details live elsewhere."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import re

from ... import preset_deploy, remnawave, storage
from .. import security as node_security
from ...template_engine import Endpoint, TemplateError
from . import remote, render, ssh
from .registration import complete_panel_registration

POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="xppn-vps")


def resume_registration(node_id: str, password: str):
    def stage(status: str, note: str):
        storage.set_install_status(node_id, status, note)

    try:
        node = storage.get_node(node_id)
        job = storage.get_install_job(node_id)
        source = Endpoint(node["code"], node["domain"], node["country"])
        stage("installing", "Проверяем установленный VPS по SSH")
        transport, _ = ssh.ssh_open(
            job["ip"], job["port"], password, job["ssh_fingerprint"]
        )
        try:
            ssh.verify_existing_install(transport, source)
        finally:
            transport.close()
        stage("installing", "VPS проверен, продолжаем с Remnawave")
        complete_panel_registration(node_id, source)
    except Exception as exc:
        if isinstance(exc, (ValueError, TemplateError, remnawave.PanelError)):
            detail = str(exc)
        else:
            detail = type(exc).__name__ + ": смотри состояние сервисов на VPS"
        if password:
            detail = detail.replace(password, "[СКРЫТО]")
        stage("failed", detail[:350])
    finally:
        password = ""


def start_resume(
    node_id: str, password: str, confirmed: bool = False
) -> dict:
    if not confirmed:
        raise ValueError(
            "Подтверди продолжение установки без переустановки VPS"
        )
    node = storage.get_node(node_id)
    job = storage.get_install_job(node_id)
    if job["stage"] not in ("failed", "interrupted"):
        raise ValueError(
            "Продолжить можно только неудачную или прерванную установку"
        )
    if job["remote_uuid"]:
        raise ValueError(
            "Нода уже зарегистрирована. Повторная регистрация запрещена."
        )
    source = Endpoint(node["code"], node["domain"], node["country"])
    transport, _ = ssh.ssh_open(
        job["ip"], job["port"], password, job["ssh_fingerprint"]
    )
    try:
        ssh.verify_existing_install(transport, source)
    finally:
        transport.close()

    storage.queue_resume_install(node_id)
    try:
        POOL.submit(resume_registration, node_id, password)
    except Exception:
        storage.set_install_status(
            node_id, "failed", "Не удалось запустить продолжение"
        )
        raise
    return {
        "node_id": node_id,
        "stage": "queued",
        "message": "Продолжение с регистрации в Remnawave запущено",
    }


def deploy(
    node_id: str,
    ip: str,
    port: int,
    password: str,
    expected_fp: str,
    panel_ip: str,
):
    node = storage.get_node(node_id)
    source = Endpoint(node["code"], node["domain"], node["country"])

    def stage(status: str, message: str):
        storage.set_install_status(node_id, status, message)

    try:
        stage("installing", "Проверка доступа и чистоты VPS")
        outcome = ssh.preflight(
            ip, port, password, source.domain, expected_fp
        )
        if not outcome["ready"]:
            raise ValueError("; ".join(outcome["warnings"]))

        stage("installing", "Запрашиваем ключ ноды из Remnawave")
        key = remnawave.node_secret()
        snapshot = storage.get_install_preset(node_id)
        files = render.render_files(source, key, panel_ip, snapshot)

        transport, _ = ssh.ssh_open(ip, port, password, expected_fp)
        try:
            remote.stage_files(transport, files)
            stage(
                "installing",
                "Устанавливаем Docker, Nginx, TLS и Remnawave Node",
            )
            remote.run_install_script(
                transport, lambda step: stage("installing", step)
            )
            node_security.mark_bootstrap_applied(node_id)
            stage(
                "installing",
                "Certbot хранит TLS-файлы на VPS; PEM не передаётся на панель",
            )
            stage("installing", "Устанавливаем Node Manager Agent")
            from ... import agent_bootstrap

            agent_bootstrap.install_on_transport(transport, node_id)
        finally:
            transport.close()

        complete_panel_registration(node_id, source)
    except Exception as exc:
        if isinstance(exc, (ValueError, TemplateError, remnawave.PanelError)):
            detail = str(exc)
        else:
            detail = type(exc).__name__ + ": смотри состояние сервисов на VPS"
        if password:
            detail = detail.replace(password, "[СКРЫТО]")
        stage("failed", detail[:350])
    finally:
        password = ""


def start_install(
    *,
    code: str,
    country: str,
    name: str,
    domain: str,
    role: str,
    ip: str,
    port: int,
    password: str,
    fingerprint_value: str,
    panel_ip: str,
    existing_node_id: str | None = None,
    preset_id: str | None = None,
) -> dict:
    if role != "regular":
        raise ValueError(
            "Система мостов отключена: новая VPS создаётся как обычная нода"
        )
    if not ssh.FP.fullmatch(fingerprint_value):
        raise ValueError(
            "Нужно подтвердить SSH fingerprint из предварительной проверки"
        )
    if not re.fullmatch(r"[A-Z][A-Z0-9_-]{1,19}", code):
        raise ValueError("Некорректное имя ноды")

    ssh.check_ip(panel_ip)
    inspection = ssh.preflight(
        ip, port, password, domain, fingerprint_value
    )
    if not inspection["ready"]:
        raise ValueError(
            "Установка отменена: " + "; ".join(inspection["warnings"])
        )

    preset_id = preset_id or preset_deploy.default_preset_id()
    snapshot = preset_deploy.render_snapshot(
        preset_id, Endpoint(code, domain, country), role
    )
    remnawave.node_secret()

    created_new = existing_node_id is None
    if existing_node_id:
        node = storage.get_node(existing_node_id)
        if node["status"] != "planned":
            raise ValueError(
                "Сервер уже устанавливался. Повторная установка запрещена."
            )
        expected = {
            "code": code,
            "name": name,
            "domain": domain,
            "country": country,
            "role": role,
        }
        if any(node[key] != value for key, value in expected.items()):
            raise ValueError(
                "Данные отличаются от сохранённого черновика. "
                "Открой его карточку для продолжения установки."
            )
    else:
        node = storage.create_node(
            code=code,
            name=name,
            domain=domain,
            country=country,
            role=role,
        )

    try:
        storage.create_install_job(
            node["id"], ip, port, fingerprint_value
        )
        storage.save_node_ssh_password(node["id"], password)
        storage.save_install_preset(
            node["id"], preset_id, snapshot
        )
    except Exception:
        if created_new:
            with storage.transaction() as connection:
                connection.execute(
                    """DELETE FROM nodes
                       WHERE id=? AND status='planned' AND
                       NOT EXISTS (
                         SELECT 1 FROM node_installations WHERE node_id=?
                       )""",
                    (node["id"], node["id"]),
                )
        raise

    POOL.submit(
        deploy,
        node["id"],
        ip,
        port,
        password,
        fingerprint_value,
        panel_ip,
    )
    return {
        "node_id": node["id"],
        "stage": "queued",
        "message": "Установка запущена",
    }
