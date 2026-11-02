"""Safe Manager/Remnawave node removal."""
from .errors import RemovalError
from .service import preview, remove
from .remote import delete_remote_objects, inspect_remote_state

__all__ = [
    "RemovalError","preview","remove","delete_remote_objects",
    "inspect_remote_state",
]
