"""Compatibility facade for Manager persistence.

New code should import the relevant v2.repositories module or v2.core.database
directly. Existing domain modules continue to use storage.* during the staged
refactor so Stage 1 changes structure without changing behavior.
"""
from .core.database import cipher, connect, db_path, decrypt, encrypt, transaction
from .core.events import record as event
from .repositories.schema import init_db
from .repositories.settings import monitoring_interval, set_monitoring_interval
from .repositories.credentials import (
    clear_node_ssh_password,
    node_ssh_credentials,
    save_node_ssh_password,
)
from .repositories.panel import (
    get_caddy_api_key,
    get_panel,
    get_panel_token,
    set_panel,
    set_panel_profile,
)
from .repositories.nodes import (
    _delete_unused_draft_in_tx,
    create_node,
    delete_unused_draft,
    get_node,
    list_nodes,
    remove_one_time_test_rus10,
)
from .repositories.installations import (
    create_install_job,
    delete_failed_install,
    get_install_job,
    get_install_preset,
    mark_interrupted_jobs,
    queue_resume_install,
    save_install_preset,
    set_install_status,
)
from .bridge.repository import (
    approve_plan,
    create_bridge,
    create_plan,
    get_bridge,
    get_plan,
    get_plan_config,
    get_snapshot,
    list_bridges,
    save_snapshot,
)

__all__ = [
    "cipher",
    "connect",
    "db_path",
    "decrypt",
    "encrypt",
    "transaction",
    "event",
    "init_db",
    "monitoring_interval",
    "set_monitoring_interval",
    "clear_node_ssh_password",
    "node_ssh_credentials",
    "save_node_ssh_password",
    "get_caddy_api_key",
    "get_panel",
    "get_panel_token",
    "set_panel",
    "set_panel_profile",
    "create_node",
    "delete_unused_draft",
    "get_node",
    "list_nodes",
    "remove_one_time_test_rus10",
    "create_install_job",
    "delete_failed_install",
    "get_install_job",
    "get_install_preset",
    "mark_interrupted_jobs",
    "queue_resume_install",
    "save_install_preset",
    "set_install_status",
    "approve_plan",
    "create_bridge",
    "create_plan",
    "get_bridge",
    "get_plan",
    "get_plan_config",
    "get_snapshot",
    "list_bridges",
    "save_snapshot",
]
