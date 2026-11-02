"""Safe Manager/Remnawave node removal."""
from .errors import RemovalError


def preview(node_id: str) -> dict:
    from .service import preview as operation
    return operation(node_id)


def remove(node_id: str, code: str, **kwargs):
    from .service import remove as operation
    return operation(node_id, code, **kwargs)


def inspect_remote_state(node: dict, job: dict | None) -> dict:
    from .remote import inspect_remote_state as operation
    return operation(node, job)


def delete_remote_objects(*args, **kwargs):
    from .remote import delete_remote_objects as operation
    return operation(*args, **kwargs)


__all__ = [
    "RemovalError","preview","remove","delete_remote_objects",
    "inspect_remote_state",
]
