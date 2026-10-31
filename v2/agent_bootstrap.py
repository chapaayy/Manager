"""One-time SSH bootstrap for Node Manager Agent.

All post-bootstrap operations must flow through agent_transport, never SSH.
Only call this module from a confirmed first install or explicit migration.
"""
import os
from pathlib import Path
import re

import paramiko

from . import agent_transport, storage, vps_install

ROOT=Path(__file__).resolve().parent/"agent"


def manager_url() -> str:
    domain=os.environ.get("XPPN_V2_DOMAIN","").strip().lower()
    if not re.fullmatch(r"(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",domain):
        raise ValueError("Укажи XPPN_V2_DOMAIN для подключения агента по HTTPS")
    return "https://"+domain


def install_on_transport(transport: paramiko.Transport,node_id: str) -> dict:
    node=storage.get_node(node_id)
    if node["status"] not in ("installing","ready","registered","failed","interrupted"):
        raise ValueError("Нода не готова к установке агента")
    url=manager_url()
    token=agent_transport.issue_token(node_id)
    env=("MANAGER_URL="+url+"\nNODE_ID="+node_id+
         "\nAGENT_TOKEN="+token+"\n")
    arch=vps_install.run_command(transport,"uname -m",timeout=10).strip()
    binary={"x86_64":"agent-amd64","aarch64":"agent-arm64"}.get(arch)
    if binary is None:
        raise ValueError("Агент не поддерживает архитектуру VPS")
    files={
        "agent-binary":(ROOT/binary).read_bytes(),
        "agent-helper.py":(ROOT/"helper.py").read_bytes(),
        "install.sh":(ROOT/"install-agent.sh").read_bytes(),
        "agent.env":env.encode("ascii"),
    }
    vps_install.run_command(transport,"mkdir -p -m 0700 /root/.node-manager-bootstrap",
                            timeout=15)
    client=paramiko.SFTPClient.from_transport(transport)
    try:
        for name,raw in files.items():
            if len(raw)>14000000:raise ValueError("Пакет агента слишком большой для установки")
            path="/root/.node-manager-bootstrap/"+name
            with client.file(path,"wb") as dest:dest.write(raw)
            client.chmod(path,0o600)
    finally:
        client.close()
    # Output is intentionally hidden; no token is ever printed.
    vps_install.run_command(transport,
        "bash /root/.node-manager-bootstrap/install.sh >/var/log/node-manager-bootstrap.log 2>&1 "
        "&& printf 'AGENT_INSTALLED\\n'",
        timeout=600,max_bytes=1200)
    return {"node_id":node_id,"agent_installed":True,"pending_heartbeat":True}


def install_existing(node_id: str,password: str,confirmed: bool) -> dict:
    if not confirmed:
        raise ValueError("Подтверди однократную установку агента на существующую VPS")
    node=storage.get_node(node_id)
    if node["status"] != "ready":
        raise ValueError("Добавить агент можно только на работающую ноду")
    job=storage.get_install_job(node_id)
    transport,_=vps_install.ssh_open(job["ip"],job["port"],password,job["ssh_fingerprint"])
    try:
        vps_install.verify_existing_install(
            transport,vps_install.Endpoint(node["code"],node["domain"],node["country"]))
        return install_on_transport(transport,node_id)
    finally:
        transport.close()
