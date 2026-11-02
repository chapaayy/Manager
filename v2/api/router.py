"""Top-level HTTP router composition."""
from fastapi import APIRouter

from . import agents, auth, bridge, configs, dashboard, nodes, panel, security, system, tls, vps, web

router = APIRouter()

# Explicit order keeps static and concrete routes registered before the more
# parameterized resource routes. Public paths themselves are unchanged.
for child in (
    web.router,
    system.router,
    auth.router,
    dashboard.router,
    panel.router,
    vps.router,
    tls.router,
    agents.router,
    security.router,
    nodes.router,
    bridge.router,
    configs.router,
):
    router.include_router(child)
