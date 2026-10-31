# Node Manager Agent — first release

This is the first agent-based VPS control plane. The Manager, not Remnawave
Panel, manages hosts. Remnawave Panel remains API-only. No certificate
directory or other services are installed on the Panel VPS.

## Architecture

- New clean VPS: initial fingerprint-pinned SSH connection installs Docker,
  Nginx, Certbot, Remnawave Node and Node Manager Agent.
- After bootstrap: agent initiates outbound HTTPS 443 to the Manager and
  authenticates with a random per-node bearer secret. Manager stores only
  SHA-256(token), supports revocation and credential rotation.
- No incoming agent port or post-install SSH passwords are needed.
- Current transport is authenticated HTTPS polling ~5 seconds, plus
  heartbeat ~15 seconds. It is not yet WebSocket or mTLS.
- Go agent is precompiled for amd64 and arm64 in the Manager Docker image;
  node VPS does not require a Go compiler or toolchain.
- Go daemon runs as unprivileged nodemanager under systemd with isolation.
  Privileged helper is root-owned and has tightly allowlisted operations
  through sudoers. No arbitrary shell or arbitrary filesystem access.
- Jobs have a UUID, expiration and status. Timed-out leased jobs are NOT
  automatically retried, preventing duplicate side effects.
- Agent secret is stored in /etc/node-manager/agent.env as root:nodemanager
  with permissions 0640. No root SSH password is saved.

## Supported actions now

- System load, RAM, disk space, uptime, online status, version.
- Docker state for nginx and remnanode, bounded Docker log tail.
- Explicit, confirmed restart for nginx or remnanode.
- Systemd service state for docker.service, certbot.timer and node firewall.
- Restart certbot.timer (only this allowlisted systemd service).
- Read nginx.conf and both known Docker Compose configuration files.
- Apply nginx.conf with SHA-256 version guard, root-only backup, nginx -t,
  rollback on failure and in-place inode preserving writes for bind mounts.
- Certbot status and checked, in-memory PEM forwarding through the existing
  Remnawave API profile integration, without storing certificate bytes in the
  Manager DB or returning private keys to the browser.

## New VPS and existing VPS

New server: use Добавить VPS. The first SSH install automatically installs
and starts the agent. The manager can operate through that agent afterwards.

Already installed node: open Агенты VPS, select the node and click
Установить агент (один раз SSH), provide the root password and confirm.
Manager verifies the original pinned SSH host key and remote node identity,
installs the agent and waits for its independent outbound heartbeat.
No reinstall of Remnawave is performed. Existing nodes remain unchanged on
a Manager upgrade alone.

System SSH server is NOT automatically disabled. A human administrator may
still need emergency break-glass access if the agent cannot connect.

## Certificate lifecycle

Certbot issues and renews on each VPS. Certificate and key files remain in
/opt/nginx/certs (read-only mount in remnanode). Every six hours while the
Manager is online, it queues cert.export tasks for connected agents.
Manager validates domain, validity and key, updates only the dedicated
Manager-owned Xray Config Profile via Remnawave API, and requests a targeted
restart when the profile's certificate actually changes. Other Xray fields
and file-backed/manual profiles remain untouched.

Remnawave Config Profile currently keeps inline TLS PEM data for API
compatibility. It does not need any Panel filesystem mount. The Manager
does not store PEM. Be aware that the Remnawave Panel profile itself contains
the certificate and private key, as it already did before this change.

## Limitations and next phases

This release is the foundation, not yet the entire planned agent platform:
- mTLS + authenticated persistent WebSocket instead of HTTPS polling/token.
- Signed in-band self-updates of agent binaries.
- Transactional editing of all Docker Compose configurations.
- Central continuous logs, retention controls and historical search.
- Automatic failover/recovery and production rollout validation.

Do not deploy simultaneously to the whole fleet. Verify on one test VPS
with the actual manager hostname and Remnawave API before bulk migration.
