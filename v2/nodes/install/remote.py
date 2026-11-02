"""Allowlisted remote bootstrap execution over authenticated SSH."""
from __future__ import annotations

import time

import paramiko

from .ssh import SSH_TIMEOUT, run_command


def run_install_script(transport, on_step):
    channel = transport.open_session(timeout=SSH_TIMEOUT)
    channel.settimeout(120)
    try:
        channel.exec_command("bash /root/.xppn-pending/remote-install.sh")
        buffer = ""
        total = 0
        deadline = time.monotonic() + 1200
        while (
            not channel.exit_status_ready()
            or channel.recv_ready()
            or channel.recv_stderr_ready()
        ):
            if time.monotonic() > deadline:
                raise TimeoutError("Установка VPS превысила 20 минут")
            for ready, recv in (
                (channel.recv_ready, channel.recv),
                (channel.recv_stderr_ready, channel.recv_stderr),
            ):
                while ready():
                    chunk = recv(16384)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > 1500000:
                        raise RuntimeError("Слишком большой вывод удалённой установки")
                    buffer += chunk.decode(errors="replace")
                    if len(buffer) > 30000:
                        buffer = buffer[-30000:]
                    if "\n" in buffer:
                        lines = buffer.split("\n")
                        buffer = lines[-1]
                        for line in lines[:-1]:
                            if line.startswith("STEP: "):
                                on_step(line[6:150])
            time.sleep(0.1)
        rc = channel.recv_exit_status()
        if rc != 0:
            raise RuntimeError(
                f"Удалённая установка не завершилась успешно (код {rc}). Смотри VPS."
            )
    finally:
        channel.close()


def stage_files(transport, files: dict):
    run_command(
        transport, "mkdir -p -m 0700 /root/.xppn-pending", timeout=15
    )
    sftp = paramiko.SFTPClient.from_transport(transport)
    try:
        for name, content in files.items():
            path = "/root/.xppn-pending/" + name
            with sftp.file(path, "wb") as target:
                target.write(content.encode("utf-8"))
            sftp.chmod(path, 0o600)
    finally:
        sftp.close()
