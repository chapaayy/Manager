# Node-only TLS certificates — API-only Remnawave integration

## Rules for production

- Certbot **issues and renews on each Node VPS**, never on the Panel server.
- The only certificate files are on that Node VPS:
  /opt/nginx/certs/<domain>_privkey.key and
  /opt/nginx/certs/<domain>_fullchain.pem.
- Remnawave Node mounts /opt/nginx/certs read-only at the same container path.
- The dedicated Remnawave Xray Config Profile stores **only** keyFile and
  certificateFile. Manager never sends certificate or private-key PEM to
  Remnawave Panel, and never stores PEM in its own database.
- Manager does not install anything, create any file, mount any volume, or
  change any container on the **Remnawave Panel VPS**.
- Only allowed Panel API writes: create this Node, create its dedicated
  Config Profile, optionally PATCH only that dedicated unshared profile
  during explicitly confirmed migration, or restart this exact Node after
  Certbot renewal. Other Node/Profile assignments are never changed.

## Why node-only paths work in Remnawave

Remnawave Backend version 3.4.4:
src/common/helpers/xray-config/xray-config.validator.ts,
XRayConfig.resolveCertificate:

1. Reads certificateFile/keyFile from the Panel backend if accessible.
2. If reading fails, catch returns the *original certificate object*, keeping
   its file paths unchanged.
3. The resulting config goes to Remnawave Node and Xray-core can then read
   the files locally, provided the Node has the correct Docker bind mount.

The backend performs this operation in
src/modules/users/queries/get-prepared-config-with-users/get-prepared-config-with-users.handler.ts.
Sources:
https://github.com/remnawave/backend/blob/3.4.4/src/common/helpers/xray-config/xray-config.validator.ts
https://github.com/remnawave/backend/blob/3.4.4/src/modules/users/queries/get-prepared-config-with-users/get-prepared-config-with-users.handler.ts

Caution: if the Panel backend *can* access a matching file path, it may
inline that PEM when delivering config. No such directories or mounts
are created on the Panel by this Manager.

## New Node installation

The first SSH bootstrap installs Certbot and the Node's read-only bind
mount. Manager creates the exact Node-owned Config Profile using only
file paths. No private key is collected by SSH or copied to the Panel API.
Remnawave Node startup must confirm Xray health.

The Xray inbound contains:

    "certificates": [
      {
        "keyFile": "/opt/nginx/certs/<domain>_privkey.key",
        "certificateFile": "/opt/nginx/certs/<domain>_fullchain.pem"
      }
    ]

## Automatic renewal

Every six hours (and manually through Сертификаты нод), Manager queues
cert.status through the authenticated outbound Node Agent. Agent verifies
cert/key matching, hostname, validity and the read-only Docker mount, then
sends back *only public metadata*: domain, certificate hash and expiry.
Manager validates that the remote Node's Config Profile is exclusively
owned by this Node. If the stored certificate hash changed, Manager asks
Remnawave API to restart only that Node so Xray re-reads its local files.
No API PATCH or private key transmission occurs for renewal.

Older Agent 1.0/1.1 may provide only a certificate summary without the new
container/read-only mount checks. For an older Agent, migration also checks
the provisioned Node Docker Compose before changing the profile.

## Existing Manager-created Node with inline PEM

Use Сертификаты нод -> Перейти на локальные TLS for **one Node at a time**:

1. Confirm exact Node code.
2. Manager gets fresh cert.status and Node Docker Compose through the Agent,
   checking expected local files, expiry and read-only bind mount declaration.
3. It checks the existing Remnawave profile name, active Node/profile
   association and absence of any other Node using that profile.
4. It PATCHes **only** the certificate object in that dedicated profile to
   the two Node-local paths, restarts **only this Node** and checks telemetry.
5. If Xray fails to recover, Manager immediately tries to restore the
   previous profile and restart the same Node. The previous PEM is retained
   **in memory only during this migration request**, never persisted in
   Manager's database.
6. Nothing is migrated automatically when Manager is upgraded.

The rollback is best effort: network/API outages can prevent its completion.
Before real deployment, verify this migration on one disposable test VPS,
and do not use the migration button on unrelated/shared production profiles.

## Security

- Access to the Remnawave profile API should remain strictly limited.
- Never paste PEM private keys or full TLS config containing keys into
  chats or tickets. Rotate any previously leaked private keys.
- Node-local files must be protected against unauthorized local access.
- The Manager cannot prove actual TLS handshake success from Remnawave's
  Node/Xray telemetry alone; verify a real TLS client connection afterward.
