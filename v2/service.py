"""Explicitly staged bridge orchestration.

A plan is never a deployment. Applying must be a separate authenticated,
audited, two-phase operation with a real Remnawave/Xray test-and-rollback
adapter. This module deliberately cannot touch an existing VPS.
"""
from __future__ import annotations

import json
import uuid
from . import storage
from .template_engine import (
    Endpoint, Exit, TemplateError, render_bridge, extend_existing_bridge,
    diff_configs, safe_preview, variables_map,
)


def as_endpoint(node: dict) -> Endpoint:
    return Endpoint(code=node["code"], domain=node["domain"], country=node["country"])


def prepare_bridge_exit(bridge_id: str, exit_node_id: str, outgoing_uuid: str,
                        requested_inbound_port: int | None = None,
                        config_template_id: str | None = None) -> dict:
    bridge = storage.get_bridge(bridge_id)
    output = storage.get_node(exit_node_id)
    if output["role"] != "exit":
        raise TemplateError("К мосту можно подключить только ноду с ролью «Выходная»")
    if any(e["id"] == exit_node_id for e in bridge["exits"]):
        raise TemplateError("Выходная нода уже подключена")
    if bridge["plans"]:
        raise TemplateError("Сначала заверши предыдущий план моста; нельзя создавать параллельные изменения")
    source = as_endpoint(bridge["entry"])
    e = Exit(endpoint=as_endpoint(output), user_id=outgoing_uuid,
             inbound_port=requested_inbound_port)
    current = storage.get_snapshot(bridge_id)
    if current is None:
        if requested_inbound_port is not None:
            raise TemplateError("Первый выход моста использует фиксированные 443 и 8443; порт выбирать не нужно")
        if bridge["exits"]:
            raise TemplateError("Не хватает снимка действующего конфига. Сначала импортируй его.")
        custom = None
        if config_template_id:
            from . import library
            row = library.get_file(config_template_id)
            if row["kind"] != "xray":
                raise TemplateError("Для Xray нужен файл типа Xray JSON")
            custom = json.loads(row["content"])
        proposed = render_bridge(source, [e], template=custom)
    else:
        if config_template_id:
            raise TemplateError("Для уже работающего моста берём импортированный JSON, а не перезаписываем его шаблоном")
        proposed = extend_existing_bridge(current, source, e)
    after = safe_preview(proposed)
    before = safe_preview(current) if current is not None else {}
    preview_diff = diff_configs(before, after)
    used = next(i["port"] for i in proposed["inbounds"]
                if i["tag"] == f"{source.code}_{e.endpoint.code}_VLESS_TLS_IN")
    result = storage.create_plan(
        bridge_id, exit_node_id, content=proposed, outgoing_uuid=outgoing_uuid,
        inbound_port=used, diff_redacted=preview_diff)
    result["config"] = after
    result["variables"] = variables_map(source, [e])
    result["actions"] = [
        "Подготовить/проверить TLS и VLESS на выходной ноде",
        "Проверить совпадение межсерверного UUID на обеих сторонах",
        "Сохранить резервную версию текущего Xray Config Profile",
        "Проверить новый JSON и доступность выбранного порта",
        "После отдельного подтверждения применить только целевой профиль",
        "Проверить маршруты и восстановить старую версию при ошибке",
    ]
    result["requires_live_apply"] = True
    return result


def plan_public(plan_id: str) -> dict:
    plan = storage.get_plan(plan_id)
    plan["config"] = safe_preview(storage.get_plan_config(plan_id))
    return plan
