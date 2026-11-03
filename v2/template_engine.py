"""Compatibility facade for the pre-refactor template engine.

Active Direct-node code imports :mod:`v2.xray`. Bridge-only rendering lives in
:mod:`v2.bridge.renderer`. Keep these re-exports for old scripts/tests while
the disabled Bridge subsystem remains readable.
"""
from .xray import CODE, DOMAIN, Endpoint, TemplateError, new_inbound, validate_rendered
from .bridge.renderer import (
    EXTRA_PORT_END,
    EXTRA_PORT_START,
    PORTS_RESERVED,
    Exit,
    allocate_port,
    diff_configs,
    extend_existing_bridge,
    new_outbound,
    render_bridge,
    render_template_document,
    safe_preview,
    variables_map,
)

__all__ = [
    "CODE",
    "DOMAIN",
    "PORTS_RESERVED",
    "EXTRA_PORT_START",
    "EXTRA_PORT_END",
    "TemplateError",
    "Endpoint",
    "Exit",
    "new_inbound",
    "new_outbound",
    "render_template_document",
    "allocate_port",
    "render_bridge",
    "validate_rendered",
    "diff_configs",
    "safe_preview",
    "variables_map",
    "extend_existing_bridge",
]
