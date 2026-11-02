"""Single action dispatcher for the root-owned helper."""
from __future__ import annotations

from .cleanup import cleanup_managed, finish_cleanup
from .common import fail
from .operations import execute_regular
from .security_fail2ban import (
    install_ssh_protection,
    unban_ssh_ip,
)
from .security_service import (
    apply_security_settings,
    bootstrap_security,
)
from .security_status import baseline_status
from .updates import schedule_agent_update


def execute(action: str, data: dict):
    if action == "security.fail2ban.install":
        return install_ssh_protection(data)
    if action == "security.fail2ban.unban":
        return unban_ssh_ip(data)
    if action == "security.settings.apply":
        return apply_security_settings(data)
    if action == "security.bootstrap":
        return bootstrap_security(data)
    if action == "agent.update":
        return schedule_agent_update(data)
    if action == "baseline.status":
        return baseline_status()
    if action == "node.cleanup":
        return cleanup_managed(data)
    if action == "node.cleanup.finish":
        return finish_cleanup(data)
    return execute_regular(action, data)
