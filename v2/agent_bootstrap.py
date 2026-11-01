"""One-time SSH bootstrap for Node Manager Agent.

All post-bootstrap operations must flow through agent_transport, never SSH.
Only call this module from a confirmed first install or explicit migration.
"""
import os
import socket
from pathlib import Path
import re

import paramiko

from . import agent_transport, storage, vps_install

ROOT=Path(__file__).resolve().parent/"agent"


class AgentBootstrapError(ValueError):
    """A deliberately sanitized actionable bootstrap failure."""


STAGE_DESCRIPTION = {
    "preflight": "проверка установочных файлов",
    "dependencies": "проверка или установка зависимостей sudo",
    "user": "создание отдельного пользователя nodemanager",
    "files": "установка файлов и конфигурации агента",
    "binary": "установка исполняемого файла агента",
    "sudoers": "настройка разрешённых привилегий агента",
    "systemd": "подготовка systemd-службы",
    "service": "запуск и проверка systemd-службы",
    "cleanup": "очистка временных файлов",
}


def _remote_bootstrap_failure(transport):
    """Only read machine-generated stage tags. Never expose raw install logs."""
    try:
        status = vps_install.run_command(
            transport,
            "if test -f /var/log/node-manager-bootstrap.log; then "
            "grep -E '^AGENT_(FAILURE|STEP):[a-z_-]+(:[0-9]+)?$' "
            "/var/log/node-manager-bootstrap.log | tail -n 1 || :; fi",
            timeout=12, max_bytes=256).strip()
    except Exception:
        return "Сбой скрипта агента. На VPS смотри журнал установки."
    failure = re.fullmatch(r"AGENT_FAILURE:([a-z_-]+):([0-9]{1,3})", status)
    if failure:
        stage, code = failure.groups()
        description = STAGE_DESCRIPTION.get(stage, "неизвестный этап")
        return ("Ошибка при установке агента: " + description +
                " (код " + code + "). Проверь на VPS службу и журнал установки.")
    return "Скрипт установки агента завершился ошибкой. Проверь журнал установки на VPS."


def manager_url() -> str:
    domain=os.environ.get("XPPN_V2_DOMAIN","").strip().lower()
    if not re.fullmatch(r"(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",domain):
        raise ValueError("Укажи XPPN_V2_DOMAIN для подключения агента по HTTPS")
    return "https://"+domain


def install_on_transport(transport: paramiko.Transport, node_id: str) -> dict:
    node = storage.get_node(node_id)
    if node["status"] not in ("installing","ready","registered","failed","interrupted"):
        raise AgentBootstrapError("Нода не готова к установке агента")
    url = manager_url()
    try:
        arch = vps_install.run_command(transport,"uname -m",timeout=10).strip()
    except Exception:
        raise AgentBootstrapError("SSH подключился, но не удалось определить архитектуру VPS") from None
    binary = {"x86_64":"agent-amd64","aarch64":"agent-arm64"}.get(arch)
    if binary is None:
        raise AgentBootstrapError("Агент не поддерживает архитектуру VPS")
    try:
        files = {
            "agent-binary": (ROOT/binary).read_bytes(),
            "agent-helper.py": (ROOT/"helper.py").read_bytes(),
            "install.sh": (ROOT/"install-agent.sh").read_bytes(),
            "agent-uninstall.sh": (ROOT/"uninstall-agent.sh").read_bytes(),
            "agent-updater.sh": (ROOT/"agent-updater.sh").read_bytes(),
            "fail2ban-setup.sh": (ROOT/"fail2ban-setup.sh").read_bytes(),
        }
    except (OSError, ValueError):
        raise AgentBootstrapError("В образе менеджера отсутствуют файлы агента. "
                                  "Повтори обновление менеджера.") from None
    # Issue the per-node identity only after all read-only checks passed.
    token = agent_transport.issue_token(node_id)
    env = ("MANAGER_URL=" + url + "\nNODE_ID=" + node_id +
           "\nAGENT_TOKEN=" + token + "\n")
    files["agent.env"] = env.encode("ascii")
    try:
        vps_install.run_command(transport,"mkdir -p -m 0700 /root/.node-manager-bootstrap",
                                timeout=15)
        client = paramiko.SFTPClient.from_transport(transport)
        try:
            for name, raw in files.items():
                if not raw or len(raw) > 14000000:
                    raise AgentBootstrapError("Некорректный размер файлов агента")
                path = "/root/.node-manager-bootstrap/" + name
                with client.file(path,"wb") as dest:
                    dest.write(raw)
                client.chmod(path,0o600)
        finally:
            client.close()
    except AgentBootstrapError:
        raise
    except Exception:
        raise AgentBootstrapError(
            "SSH подключился, но копирование файлов агента не удалось. "
            "Проверь SFTP и свободное место на VPS.") from None
    try:
        vps_install.run_command(
            transport,
            "bash /root/.node-manager-bootstrap/install.sh "
            ">/var/log/node-manager-bootstrap.log 2>&1 "
            "&& printf 'AGENT_INSTALLED\n'",
            timeout=600,max_bytes=1200)
    except (RuntimeError,TimeoutError,ValueError,OSError):
        raise AgentBootstrapError(_remote_bootstrap_failure(transport)) from None
    return {"node_id":node_id,"agent_installed":True,"pending_heartbeat":True}


def install_existing(node_id: str, password: str, confirmed: bool) -> dict:
    if not confirmed:
        raise AgentBootstrapError("Подтверди однократную установку агента на существующую VPS")
    node = storage.get_node(node_id)
    if node["status"] != "ready":
        raise AgentBootstrapError("Добавить агент можно только на работающую ноду")
    job = storage.get_install_job(node_id)
    try:
        transport, _ = vps_install.ssh_open(
            job["ip"],job["port"],password,job["ssh_fingerprint"])
    except paramiko.AuthenticationException:
        raise AgentBootstrapError("SSH: пароль root не принят сервером") from None
    except ValueError as exc:
        # vps_install only raises allowlisted, human-readable validation errors.
        raise AgentBootstrapError(str(exc)) from None
    except (socket.timeout,TimeoutError):
        raise AgentBootstrapError("SSH: VPS не отвечает по сохранённому адресу и порту") from None
    except (OSError,paramiko.SSHException):
        raise AgentBootstrapError("SSH: соединение с VPS установить не удалось. "
                                  "Проверь IP, порт SSH и доступ с сервера менеджера.") from None
    try:
        try:
            vps_install.verify_existing_install(
                transport,vps_install.Endpoint(node["code"],node["domain"],node["country"]))
        except ValueError as exc:
            raise AgentBootstrapError(
                "SSH подключился, но проверка готовой ноды не прошла: " + str(exc)) from None
        return install_on_transport(transport,node_id)
    finally:
        transport.close()


def repair_existing(node_id: str, password: str, confirmed: bool) -> dict:
    """Explicit one-time repair of original agent sandbox; preserve identity."""
    if not confirmed:
        raise AgentBootstrapError("Подтверди исправление первоначальной установки агента")
    node=storage.get_node(node_id)
    if node["status"]!="ready":
        raise AgentBootstrapError("Исправление доступно только установленным нодам")
    agent=next((x for x in agent_transport.nodes_status() if x["id"]==node_id),None)
    if not agent or not agent["installed"] or agent["revoked"] or not agent["last_seen"]:
        raise AgentBootstrapError("Сначала установи и подключи агент обычным способом")
    job=storage.get_install_job(node_id)
    try:
        transport,_=vps_install.ssh_open(
            job["ip"],job["port"],password,job["ssh_fingerprint"])
    except paramiko.AuthenticationException:
        raise AgentBootstrapError("SSH: пароль root не принят сервером") from None
    except ValueError as exc:
        raise AgentBootstrapError(str(exc)) from None
    except (socket.timeout,TimeoutError):
        raise AgentBootstrapError("SSH: сервер не отвечает по сохранённому адресу и порту") from None
    except (OSError,paramiko.SSHException):
        raise AgentBootstrapError("SSH: соединение с VPS не удалось") from None
    try:
        try:
            vps_install.verify_existing_install(
                transport,vps_install.Endpoint(node["code"],node["domain"],node["country"]))
        except ValueError as exc:
            raise AgentBootstrapError("Проверка существующей VPS не пройдена: "+str(exc)) from None
        script=(ROOT/"repair-helper.sh").read_bytes()
        if not script or len(script)>24000:
            raise AgentBootstrapError("В менеджере отсутствует скрипт исправления агента")
        path="/root/.node-manager-agent-repair.sh"
        try:
            client=paramiko.SFTPClient.from_transport(transport)
            try:
                with client.file(path,"wb") as target:
                    target.write(script)
                client.chmod(path,0o700)
            finally:
                client.close()
        except Exception:
            raise AgentBootstrapError("Не удалось передать скрипт исправления по SFTP") from None
        try:
            vps_install.run_command(
                transport,"bash /root/.node-manager-agent-repair.sh "
                          ">/var/log/node-manager-repair.log 2>&1 "
                          "&& rm -f /root/.node-manager-agent-repair.sh "
                          "&& printf 'AGENT_REPAIR_SUCCESS\\n'",
                timeout=120,max_bytes=1200)
        except Exception:
            try:
                marker=vps_install.run_command(
                    transport,"if test -f /var/log/node-manager-repair.log; then "
                              "grep -E '^AGENT_REPAIR_FAILURE:[a-z_-]+:[0-9]+$' "
                              "/var/log/node-manager-repair.log | tail -n 1 || :; fi",
                    timeout=10,max_bytes=150).strip()
            except Exception:
                marker=""
            match=re.fullmatch(r"AGENT_REPAIR_FAILURE:([a-z_-]+):([0-9]{1,3})",marker)
            label={"preflight":"проверка службы агента",
                   "backup":"резервное копирование настроек",
                   "write":"изменение systemd-ограничений",
                   "service":"проверка доступа к helper и перезапуск агента",
                   "cleanup":"очистка"}.get(match.group(1),"применение исправления") if match else "применение исправления"
            raise AgentBootstrapError(
                "Не удалось исправить агент: "+label+
                ". Предыдущая настройка восстановлена, если перезапуск не прошёл.") from None
        # Token hash and local agent credentials remain unchanged.
        return {"node_id":node_id,"repaired":True,"credentials_unchanged":True}
    finally:
        transport.close()


def upgrade_existing(node_id:str,password:str,confirmed:bool)->dict:
    """One-time SSH migration of existing v1.2 agent; preserve its token/env."""
    if not confirmed:
        raise AgentBootstrapError("Подтверди однократное SSH-обновление агента")
    node=storage.get_node(node_id)
    if node["status"]!="ready":
        raise AgentBootstrapError("Нода не установлена")
    job=storage.get_install_job(node_id)
    agent=next((x for x in agent_transport.nodes_status() if x["id"]==node_id),None)
    if not agent or not agent["online"] or agent["revoked"]:
        raise AgentBootstrapError("Требуется работающий зарегистрированный агент")
    try:
        t,_=vps_install.ssh_open(job["ip"],job["port"],password,job["ssh_fingerprint"])
    except paramiko.AuthenticationException:
        raise AgentBootstrapError("Неверный SSH пароль root") from None
    except (ValueError,socket.timeout,TimeoutError,OSError,paramiko.SSHException) as exc:
        raise AgentBootstrapError("SSH обновление недоступно: проверь доступ и fingerprint VPS") from None
    try:
        try:
            vps_install.verify_existing_install(t,vps_install.Endpoint(node["code"],node["domain"],node["country"]))
        except ValueError:
            raise AgentBootstrapError("Существующая VPS не прошла проверку целостности") from None
        arch=vps_install.run_command(t,"uname -m",timeout=10).strip()
        binary_name={"x86_64":"agent-amd64","aarch64":"agent-arm64"}.get(arch)
        if not binary_name:
            raise AgentBootstrapError("Неподдерживаемая архитектура VPS")
        try:
            files={"agent-binary":(ROOT/binary_name).read_bytes(),
                   "agent-helper.py":(ROOT/"helper.py").read_bytes(),
                   "agent-updater.sh":(ROOT/"agent-updater.sh").read_bytes(),
                   "upgrade.sh":(ROOT/"upgrade-agent.sh").read_bytes()}
            import hashlib
            from . import agent_release
            files["agent-version"]=(agent_release.release()["version"]+" "+
                                    hashlib.sha256(files["agent-binary"]).hexdigest()+"\n").encode("ascii")
        except OSError:
            raise AgentBootstrapError("В Manager отсутствуют файлы новой версии агента") from None
        if any(not item or len(item)>14000000 for item in files.values()):
            raise AgentBootstrapError("Некорректные файлы обновления агента")
        vps_install.run_command(t,"mkdir -p -m 0700 /root/.node-manager-agent-upgrade",timeout=12)
        client=paramiko.SFTPClient.from_transport(t)
        try:
            for filename,contents in files.items():
                with client.file("/root/.node-manager-agent-upgrade/"+filename,"wb") as dest:
                    dest.write(contents)
                client.chmod("/root/.node-manager-agent-upgrade/"+filename,0o600)
        finally:
            client.close()
        try:
            result=vps_install.run_command(
                t,"bash /root/.node-manager-agent-upgrade/upgrade.sh",
                timeout=90,max_bytes=1000)
            if "AGENT_UPGRADE:restarted" not in result:
                raise AgentBootstrapError("Не подтверждён запуск обновлённого агента")
        except (RuntimeError,TimeoutError,OSError,ValueError):
            raise AgentBootstrapError("Не удалось обновить агент; проверь systemd node-manager-agent. "
                                     "Резервные копии сохранены на VPS") from None
        return {"node_id":node_id,"upgraded":True,"credentials_unchanged":True,
                "pending_heartbeat":True}
    finally:
        t.close()
