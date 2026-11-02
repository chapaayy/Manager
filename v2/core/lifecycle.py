"""Manager process startup orchestration."""
from __future__ import annotations

from . import auth
from .. import agent_transport, bundled, storage
from ..nodes import lifecycle as node_lifecycle
from ..nodes import security as security_settings
from ..nodes import tls as node_cert_sync


def startup() -> None:
    auth.validate_configuration()
    storage.init_db()
    agent_transport.initialize()
    security_settings.initialize()
    node_lifecycle.disable_pending_vps_cleanup()
    bundled.seed_defaults()
    storage.mark_interrupted_jobs()
    storage.remove_one_time_test_rus10()
    node_cert_sync.start_background()
