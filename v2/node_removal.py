"""Remove Manager records and API-owned Remnawave objects, never touch the VPS.

The old agent-based full cleanup remains a legacy state only. This API never
queues a job, uses SSH, edits the Remnawave host or touches Docker.
"""
from __future__ import annotations

import threading
import re

from . import node_lifecycle, remnawave, storage, vps_install
from .node_cert_sync import _attached_profile
from .template_engine import Endpoint

_LOCK = threading.RLock()


class RemovalError(ValueError):
    pass


def _install(node_id):
    try:
        return storage.get_install_job(node_id)
    except LookupError:
        return None


def _nodes():
    result = remnawave.request("GET", "/api/nodes").get("response")
    if not isinstance(result, list) or not all(isinstance(x, dict) for x in result):
        raise RemovalError("Remnawave вернула неполный список нод")
    return result


def _profile_users(rows, profile_uuid, remote_uuid):
    others = []
    for row in rows:
        try:
            attached, known = _attached_profile(row)
        except ValueError:
            raise RemovalError("Remnawave вернула некорректные привязки профилей") from None
        if not known:
            raise RemovalError("Нельзя проверить привязки всех нод к профилям Remnawave")
        if attached == profile_uuid and row.get("uuid") != remote_uuid:
            uid = row.get("uuid")
            if not isinstance(uid, str) or not uid:
                raise RemovalError("У другой ноды нет UUID. Удаление общего профиля запрещено")
            others.append({"uuid": uid, "name": str(row.get("name") or uid)[:100]})
    return sorted(others, key=lambda item: item["uuid"])


def _remote_state(node, job):
    remote_uuid = job["remote_uuid"] if job else ""
    profile_uuid = job["profile_uuid"] if job else ""
    data = {"remote_uuid": remote_uuid, "profile_uuid": profile_uuid,
            "remote_present": False, "profile_present": False,
            "profile_name": "", "profile_owned": False,
            "shared_nodes": []}
    if not remote_uuid and not profile_uuid:
        return data
    rows = _nodes()
    target = next((r for r in rows if r.get("uuid") == remote_uuid), None)
    data["remote_present"] = target is not None
    if target and profile_uuid:
        try:
            attached, known = _attached_profile(target)
        except ValueError:
            raise RemovalError("У удаляемой ноды некорректная привязка профиля") from None
        if not known or attached != profile_uuid:
            raise RemovalError("В Remnawave изменена привязка Xray-профиля ноды. Проверь вручную")
    if profile_uuid:
        data["shared_nodes"] = _profile_users(rows, profile_uuid, remote_uuid)
        profiles = remnawave.list_profiles()
        if not isinstance(profiles, list):
            raise RemovalError("Не удалось проверить список Xray-профилей")
        selected = next((p for p in profiles if p.get("uuid") == profile_uuid), None)
        if selected:
            full = remnawave.detailed_profile(profile_uuid)
            name = full.get("name")
            expected = vps_install.config_profile_name(Endpoint(
                node["code"], node["domain"], node["country"]),
                "bridge" if node["role"]=="entry" else "direct")
            data["profile_present"] = True
            data["profile_name"] = str(name or "")[:100]
            data["profile_owned"] = name == expected
    return data


def preview(node_id):
    node = storage.get_node(node_id)
    base = node_lifecycle.preview(node_id)
    job = _install(node_id)
    result = {**base, "remnawave_available": True, "remnawave_error": "",
              "remote_uuid": job["remote_uuid"] if job else "",
              "profile_uuid": job["profile_uuid"] if job else "",
              "remote_present": False, "profile_present": False,
              "profile_name": "", "profile_owned": False, "shared_nodes": []}
    try:
        result.update(_remote_state(node, job))
    except (remnawave.PanelError, RemovalError) as exc:
        result["remnawave_available"] = False
        result["remnawave_error"] = (
            "Не удалось безопасно проверить ноды и профили Remnawave. "
            "Доступно только удаление из менеджера.")
    return result


def _check_legacy_tasks(node_id):
    with storage.connect() as db:
        pending = db.execute(
            """SELECT COUNT(*) FROM manager_agent_jobs
               WHERE node_id=? AND action IN ('node.cleanup','node.cleanup.finish')
                 AND status IN ('queued','leased')""", (node_id,)
        ).fetchone()[0]
    if pending:
        raise RemovalError(
            "Есть незавершённая задача старой очистки VPS. "
            "Нельзя гарантировать, что она не выполняется.")


def remove(node_id, code, *, delete_remote, delete_profile,
           shared_confirmation="", expected_shared_ids=None):
    """Explicit Manager deletion, optional strictly scoped Remnawave API work.

    A failed remote step leaves the Manager row in place so the operator can
    retry without repeating already confirmed remote deletes.
    """
    with _LOCK:
        node = node_lifecycle._guard(node_id, code)
        _check_legacy_tasks(node_id)
        if delete_profile and not delete_remote:
            raise RemovalError("Нельзя удалять профиль без операции с Remnawave")
        removed_node = False
        removed_profile = False
        kept_profile = False
        job = _install(node_id)
        if delete_remote and job:
            try:
                state = _remote_state(node, job)
                profile_id = state["profile_uuid"]
                remote_id = state["remote_uuid"]
                shared = state["shared_nodes"]
                if delete_profile and profile_id and state["profile_present"]:
                    if not state["profile_owned"]:
                        raise RemovalError(
                            "Xray-профиль не совпадает с созданным менеджером. "
                            "Сними галочку удаления профиля.")
                    if shared:
                        expected = sorted(expected_shared_ids or [])
                        actual = [x["uuid"] for x in shared]
                        if expected != actual or shared_confirmation != state["profile_name"]:
                            raise RemovalError(
                                "Общий профиль используется другими нодами. "
                                "Нужно заново проверить список и явно подтвердить название профиля.")
                if remote_id and state["remote_present"]:
                    remnawave.delete_node(remote_id)
                    if any(r.get("uuid") == remote_id for r in _nodes()):
                        raise RemovalError("Remnawave не подтвердила удаление ноды; повтори проверку")
                    removed_node = True
                if remote_id:
                    with storage.transaction() as db:
                        db.execute("UPDATE node_installations SET remote_uuid='' WHERE node_id=?", (node_id,))
                        storage.event(db, "node.remnawave.delete", node_id,
                                      "Node removed or confirmed absent via API")
                if delete_profile and profile_id and state["profile_present"]:
                    # Re-check shared users immediately before deleting the profile.
                    current = _profile_users(_nodes(), profile_id, remote_id)
                    if current and (
                        [x["uuid"] for x in current] != [x["uuid"] for x in shared]
                        or shared_confirmation != state["profile_name"]
                    ):
                        raise RemovalError("Привязки общего профиля изменились. Повтори подтверждение")
                    remnawave.delete_profile(profile_id)
                    if any(p.get("uuid") == profile_id for p in remnawave.list_profiles()):
                        raise RemovalError("Remnawave не подтвердила удаление Xray-профиля")
                    removed_profile = True
                if delete_profile and profile_id and not state["profile_present"]:
                    # Another attempt already removed it; no repeat DELETE.
                    removed_profile = False
                if delete_profile and profile_id:
                    with storage.transaction() as db:
                        db.execute("UPDATE node_installations SET profile_uuid='' WHERE node_id=?", (node_id,))
                        storage.event(db, "node.profile.delete", node_id,
                                      "Owned Xray profile removed or confirmed absent via API")
                kept_profile = bool(profile_id and not delete_profile)
            except remnawave.PanelError as exc:
                # Remnawave error bodies can contain secrets; expose only HTTP status.
                match = re.search(r"(?<!\d)HTTP\s+([45]\d\d)\b", str(exc))
                suffix = " (HTTP " + match.group(1) + ")" if match else ""
                raise RemovalError("Remnawave API не подтвердила операцию" + suffix) from None
        elif not delete_remote:
            kept_profile = bool(job and job["profile_uuid"])
        with storage.transaction() as db:
            storage.event(db, "node.manager.removal", node_id,
                          "Remote API requested: " + str(bool(delete_remote)) +
                          "; profile deleted: " + str(bool(delete_profile)) +
                          "; VPS left untouched")
        result = node_lifecycle._delete_record(node_id, "node.manager.removed")
        return {**result, "node_removed": removed_node,
                "profile_removed": removed_profile, "profile_retained": kept_profile,
                "vps_touched": False}
