"""Compatibility facade for v2.nodes.install."""
from .template_engine import Endpoint, TemplateError
from .nodes.install import (
    FP,
    POOL,
    READONLY,
    RESUME_PROBE,
    SSH_TIMEOUT,
    check_ip,
    complete_panel_registration,
    config_profile_name,
    deploy,
    fingerprint,
    preflight,
    preview_plan,
    render_files,
    resume_registration,
    run_command,
    ssh_open,
    start_install,
    start_resume,
    verify_existing_install,
    xray_config,
)
from .nodes.install.remote import run_install_script
from .nodes.install.remote import stage_files as _stage_files

__all__ = [
    "Endpoint","TemplateError","FP","POOL","READONLY","RESUME_PROBE",
    "SSH_TIMEOUT","check_ip","complete_panel_registration",
    "config_profile_name","deploy","fingerprint","preflight","preview_plan",
    "render_files","resume_registration","run_command","ssh_open",
    "start_install","start_resume","verify_existing_install","xray_config",
    "run_install_script","_stage_files",
]
