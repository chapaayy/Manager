# TLS certificates: file-backed Remnawave integration (opt-in)

XPPN Manager now stages verified TLS certificates in the Docker volume
**xppn-v2-panel-certs**. Remnawave reads these files via the path
`/var/lib/remnawave/configs/xray/ssl/XPPN`, following the official Remnawave
[Node TLS certificate documentation](https://docs.rw/install/remnawave-node/).

**Existing Xray profiles and live VPS do not change during a manager upgrade.**
Every live Xray migration requires a separate confirmation and an encrypted rollback snapshot.

## Choose deployment mode

**Different VPS (your Manager/Remnawave setup):** use **Настроить удалённую панель**.

1. In **Сертификаты** provide the public IPv4, SSH port, root password and **verified SSH fingerprint** of the VPS hosting **Remnawave Panel** (NOT a traffic node).
2. Confirm one-time installation. Manager installs a restricted forced-command certificate receiver under `/usr/local/libexec/xppn-panel-cert-import.py` and creates `/opt/xppn-panel-certs`. It stores only an encrypted SSH private key, never the root password.
3. On the **Remnawave Panel VPS**, add this bind mount to the existing backend service:

```yaml
services:
  remnawave:
    volumes:
      - /opt/xppn-panel-certs:/var/lib/remnawave/configs/xray/ssl/XPPN:ro
```

Keep all existing mounts and other configuration. Validate the Compose file and recreate **only** the panel backend in a planned maintenance window. The restricted SSH receiver is installed on the panel VPS, not on RUS10.

4. After the panel backend has access to that directory, click **Включить файловую синхронизацию** and confirm. Then sync a node certificate, verify panel file readability, and only then migrate a live profile.

**Same Docker host:** a shared named Docker volume also works (the option described below). Do not use that local-volume procedure when Manager and Remnawave Panel run on different machines.

## Optional: same Docker host

A Docker named volume cannot be shared across unrelated Docker hosts.
Use the remote SSH receiver described above if the panel is on another VPS.

The Manager Compose stack creates the named Docker volume automatically.

In the **Remnawave Panel backend** service in its compose file add:

```yaml
services:
  remnawave:
    volumes:
      - xppn-v2-panel-certs:/var/lib/remnawave/configs/xray/ssl/XPPN:ro
volumes:
  xppn-v2-panel-certs:
    external: true
    name: xppn-v2-panel-certs
```

Merge these lines into the existing service and existing top-level `volumes`
section; do not replace other mounts or services. Apply in a maintenance window
with `docker compose up -d --no-deps remnawave` **after verifying the compose
configuration**.

Confirm the panel backend can read a staged certificate without printing keys:

```bash
docker exec remnawave test -r /var/lib/remnawave/configs/xray/ssl/XPPN/RUS10/current/fullchain.pem
docker exec remnawave test -r /var/lib/remnawave/configs/xray/ssl/XPPN/RUS10/current/privkey.key
```

The corresponding node directory exists **only after first sync**. A missing
directory before staging is expected.

## Workflow

1. Open **Сертификаты**. Select local-volume or remote SSH mode as appropriate, mount the certificate directory in the Remnawave backend, and enable sync.
2. For RUS10 (or another already installed node), click **Синхронизировать**,
   provide root SSH password for this one transfer. The password is never stored.
3. The manager pins the original SSH fingerprint, validates certificate expiry,
   DNS SAN, and matching private key, and publishes files atomically. The private
   key never appears in API responses.
4. After checking the mounted files **inside the Remnawave container**, click
   **Перейти на файлы**. Check the preview and confirm the live Xray change.
   The manager only replaces the TLS certificate references in its own inbound,
   saves an encrypted backup of the complete former Xray profile, patches the
   full config and requests one Remnawave node restart. Existing routes remain.
5. Click **Автосинхронизация** to enroll a 3072-bit RSA SSH key with a forced,
   restricted command on the VPS. This key cannot grant an interactive shell,
   forwarding or a terminal. It only exports that VPS's certificate and key.
   Private SSH material is stored encrypted in XPPN's SQLite database.
6. Every 6 hours, while Manager is running, it checks enrolled nodes, stages
   updated TLS certificates and requests a Remnawave node restart **only if**
   a file-backed node receives a new certificate fingerprint.

The "Откатить Xray" action restores the previously encrypted config and requests
another restart. Staged files are intentionally preserved for inspection.

## Certificate renewal and leaked keys

The VPS installer already enables `certbot.timer` and deploys renewal hooks
that copy new certificates to `/opt/nginx/certs`. The manager copies the new
bundle on the next automatic synchronization.

**RUS10's previous private key was pasted in a conversation**. Treat it as
compromised and reissue with a **new private key**, rather than relying on the
existing certificate's validity. During a planned maintenance window on RUS10:

```bash
certbot certonly --webroot -w /opt/nginx/acme -d rus10.gowayot.com \
  --force-renewal --new-key --non-interactive --agree-tos
/usr/local/sbin/xppn-cert-refresh
```

Only use these commands on the expected RUS10 VPS after checking the installed
Certbot and renewal setup. Then manually **Синхронизировать** before migrating
its existing Xray profile. Any still-running inline key must eventually be
replaced by the file-backed profile. Check certificate validity from a client
and the Xray logs after the change.

## Security and limitations

- Panel mount configuration, verification and re-creating the Remnawave
  backend container are operator-controlled. The web manager never touches
  the panel's Docker socket or rewrites its Compose file.
- When panel and Manager are on separate VPS, use the restricted SSH receiver. Keep port 22 restricted and verify the host fingerprint before enrollment.
- The manager's encrypted database and the named volume become sensitive
  assets; restrict backups, administrators and filesystem permissions.
- The panel must have read permissions on the mounted files; if it runs as an
  unprivileged UID, adjust group access safely.
- The panel-to-node restart request returns before end-to-end client
  connectivity is guaranteed. Verify Hosts, Internal Squads, real TLS handshake
  and Xray status. Any failures should be investigated before rollout.
- Existing profiles remain inline unless explicitly migrated. Disabling
  synchronization is refused while file-backed profiles exist.
- Background checks run every six hours while the Manager process is up;
  it is not a guarantee of a precise cron execution time.
