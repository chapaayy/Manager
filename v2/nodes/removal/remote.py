"""Strictly scoped Remnawave deletion for Manager-owned node objects."""
from __future__ import annotations

from ... import remnawave, storage
from ..profile_ownership import (
    ProfileOwnershipError,
    attached_profile,
    expected_profile_name,
    profile_users,
)
from .errors import RemovalError


def nodes_list() -> list[dict]:
    result = remnawave.request("GET", "/api/nodes").get("response")
    if not isinstance(result, list) or not all(
        isinstance(item, dict) for item in result
    ):
        raise RemovalError("Remnawave вернула неполный список нод")
    return result


def inspect_remote_state(node: dict, job: dict | None) -> dict:
    remote_uuid = job["remote_uuid"] if job else ""
    profile_uuid = job["profile_uuid"] if job else ""
    data = {
        "remote_uuid": remote_uuid,
        "profile_uuid": profile_uuid,
        "remote_present": False,
        "profile_present": False,
        "profile_name": "",
        "profile_owned": False,
        "shared_nodes": [],
    }
    if not remote_uuid and not profile_uuid:
        return data

    rows = nodes_list()
    target = next(
        (row for row in rows if row.get("uuid") == remote_uuid),
        None,
    )
    data["remote_present"] = target is not None

    if target and profile_uuid:
        try:
            attached, known = attached_profile(target)
        except ProfileOwnershipError as exc:
            raise RemovalError(
                "У удаляемой ноды некорректная привязка профиля"
            ) from exc
        if not known or attached != profile_uuid:
            raise RemovalError(
                "В Remnawave изменена привязка Xray-профиля ноды. Проверь вручную"
            )

    if profile_uuid:
        try:
            data["shared_nodes"] = profile_users(
                rows, profile_uuid, remote_uuid
            )
        except ProfileOwnershipError as exc:
            raise RemovalError(str(exc)) from None

        profiles = remnawave.list_profiles()
        if not isinstance(profiles, list):
            raise RemovalError(
                "Не удалось проверить список Xray-профилей"
            )
        selected = next(
            (
                profile
                for profile in profiles
                if profile.get("uuid") == profile_uuid
            ),
            None,
        )
        if selected:
            full = remnawave.detailed_profile(profile_uuid)
            name = full.get("name")
            data["profile_present"] = True
            data["profile_name"] = str(name or "")[:100]
            data["profile_owned"] = (
                name == expected_profile_name(node)
            )
    return data


def _clear_remote_uuid(node_id: str) -> None:
    with storage.transaction() as db:
        db.execute(
            """UPDATE node_installations SET remote_uuid=''
               WHERE node_id=?""",
            (node_id,),
        )
        storage.event(
            db,
            "node.remnawave.delete",
            node_id,
            "Node removed or confirmed absent via API",
        )


def _clear_profile_uuid(node_id: str) -> None:
    with storage.transaction() as db:
        db.execute(
            """UPDATE node_installations SET profile_uuid=''
               WHERE node_id=?""",
            (node_id,),
        )
        storage.event(
            db,
            "node.profile.delete",
            node_id,
            "Owned Xray profile removed or confirmed absent via API",
        )


def delete_remote_objects(
    node_id: str,
    node: dict,
    job: dict,
    *,
    delete_profile: bool,
    allow_shared_profile: bool = False,
    shared_confirmation: str = "",
    expected_shared_ids: list[str] | None = None,
) -> dict:
    state = inspect_remote_state(node, job)
    profile_id = state["profile_uuid"]
    remote_id = state["remote_uuid"]
    shared = state["shared_nodes"]

    if delete_profile and profile_id and state["profile_present"]:
        if not state["profile_owned"]:
            raise RemovalError(
                "Xray-профиль не совпадает с созданным менеджером. "
                "Сними галочку удаления профиля."
            )
        if shared:
            if not allow_shared_profile:
                raise RemovalError(
                    "Xray-профиль используется другой нодой"
                )
            expected = sorted(expected_shared_ids or [])
            actual = [item["uuid"] for item in shared]
            if (
                expected != actual
                or shared_confirmation != state["profile_name"]
            ):
                raise RemovalError(
                    "Общий профиль используется другими нодами. "
                    "Нужно заново проверить список и явно подтвердить название профиля."
                )

    removed_node = False
    if remote_id and state["remote_present"]:
        remnawave.delete_node(remote_id)
        if any(
            row.get("uuid") == remote_id for row in nodes_list()
        ):
            raise RemovalError(
                "Remnawave не подтвердила удаление ноды; повтори проверку"
            )
        removed_node = True
    if remote_id:
        _clear_remote_uuid(node_id)

    removed_profile = False
    if delete_profile and profile_id and state["profile_present"]:
        try:
            current = profile_users(
                nodes_list(), profile_id, remote_id
            )
        except ProfileOwnershipError as exc:
            raise RemovalError(str(exc)) from None

        if current:
            if not allow_shared_profile:
                raise RemovalError(
                    "Xray-профиль используется другой нодой"
                )
            if (
                [item["uuid"] for item in current]
                != [item["uuid"] for item in shared]
                or shared_confirmation != state["profile_name"]
            ):
                raise RemovalError(
                    "Привязки общего профиля изменились. Повтори подтверждение"
                )

        remnawave.delete_profile(profile_id)
        if any(
            profile.get("uuid") == profile_id
            for profile in remnawave.list_profiles()
        ):
            raise RemovalError(
                "Remnawave не подтвердила удаление Xray-профиля"
            )
        removed_profile = True

    if delete_profile and profile_id:
        _clear_profile_uuid(node_id)

    return {
        "node_removed": removed_node,
        "profile_removed": removed_profile,
        "profile_retained": bool(
            profile_id and not delete_profile
        ),
    }
