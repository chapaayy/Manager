# XPPN Manager v2 architecture

This document describes the current `v2/rebuild-single-panel` architecture.
It is the source of truth for module boundaries and filesystem ownership.
README.md stays product/operator oriented; this file is for implementation work.

## 1. System boundary

XPPN Manager has three distinct execution environments:

1. **Manager VPS**
   - FastAPI application.
   - SQLite database.
   - static web UI.
   - outbound Remnawave API client.
   - Agent job queue and heartbeat endpoints.
   - root-owned host updater outside the web container.

2. **Node VPS**
   - Remnawave Node / Xray container.
   - Nginx container.
   - Certbot and node-local TLS files.
   - outbound Node Manager Agent.
   - narrow root-owned helper used only through allowlisted actions.

3. **Remnawave Panel**
   - existing external control plane.
   - Manager changes it only through the Remnawave HTTP API.
   - Manager does not mount Panel files, certificates or Docker volumes.

The browser never talks directly to Node VPSs or Remnawave. It talks only to
Manager over HTTPS.

## 2. Dependency direction

The intended backend dependency direction is:

```text
app.py
  -> api/*
      -> nodes/*, library, agent_*, integrations/remnawave/*
          -> repositories/*, core/*
              -> SQLite / HTTPS / Agent transport
```

Rules:

- `app.py` only creates FastAPI, installs middleware/static files and includes
  the top-level router.
- HTTP modules in `v2/api/` validate HTTP input and translate domain errors to
  HTTP responses. They do not own SQL.
- Node behavior lives under `v2/nodes/`.
- Remnawave HTTP behavior lives under `v2/integrations/remnawave/`.
- SQL implementations live in repositories/domain repositories, not API files.
- the web application never receives the Docker socket or arbitrary root shell.
- active Direct-node code must not depend on the disabled Bridge subsystem.

## 3. Active backend layout

```text
v2/
├── app.py
├── api/
│   ├── router.py
│   ├── auth.py
│   ├── dashboard.py
│   ├── nodes.py
│   ├── node_access.py
│   ├── vps.py
│   ├── agents.py
│   ├── tls.py
│   ├── security.py
│   ├── configs.py
│   ├── panel.py
│   ├── system.py
│   └── web.py
├── core/
│   ├── auth.py
│   ├── config.py
│   ├── database.py
│   ├── errors.py
│   ├── events.py
│   ├── http.py
│   └── lifecycle.py
├── repositories/
│   ├── schema.py
│   ├── nodes.py
│   ├── installations.py
│   ├── credentials.py
│   ├── panel.py
│   └── settings.py
├── nodes/
│   ├── install/
│   ├── lifecycle/
│   ├── removal/
│   ├── security/
│   ├── tls/
│   ├── naming.py
│   └── profile_ownership.py
├── integrations/remnawave/
├── xray.py
├── agent_transport.py
├── agent_bootstrap.py
├── agent_updates.py
├── agent_release.py
├── library.py
├── bundled.py
└── preset_deploy.py
```

### Xray boundary

`v2/xray.py` contains the Xray primitives used by active Direct nodes:

- `Endpoint`
- `TemplateError`
- node-local TLS VLESS inbound generation
- structural Xray validation

It contains no Bridge topology.

## 4. Disabled Bridge subsystem

Bridge/topology is disabled in the product, but historical rows and rendering
logic are preserved non-destructively.

All implementation now lives under:

```text
v2/bridge/
├── api.py
├── repository.py
├── service.py
├── renderer.py
└── data/xray_bridge_template.json
```

The old endpoints remain registered only to return HTTP 410 for compatibility.
The template-variable endpoint remains read-only and exposes only node variables.

Historical SQLite tables are intentionally retained:

- `bridges`
- `bridge_exits`
- `plans`

They are not dropped during normal updates. Dropping them would require a
separate database migration with backup, an explicit policy for historical
records and rollback tests.

Compatibility modules remain temporarily:

- `v2/template_engine.py`
- `v2/service.py`
- `v2/repositories/bridge.py`
- `v2/api/bridge.py`

They contain re-exports only. New active code must not import them.

The editable starter library still contains the old Bridge Xray example. It is
not an install preset and does not create roles, topology or routes.

## 5. Frontend layout

The browser UI uses classic JavaScript without a framework/build step.

```text
static/
├── core.js
├── app.js
├── nodes.js
├── library.js
├── settings.js
├── node-detail.js
├── node-monitoring.js
├── node-security.js
├── vps.js
├── index.html
└── style.css
```

Responsibilities:

- `core.js`: API/auth/state/navigation, Agent task waiting, shared modal/timer.
- `app.js`: composition and startup only.
- `nodes.js`: node list and node service actions.
- `library.js`: configs and presets.
- `settings.js`: Remnawave, monitoring interval and Manager updates.
- `node-detail.js`: selected-node workspace.
- `node-monitoring.js`: live/history monitoring.
- `node-security.js`: desired vs actual network/security state.
- `vps.js`: clean VPS preflight/install/recovery.

There are no separate active Agent/TLS pages and no Bridge plan UI.

## 6. New VPS installation flow

```text
Browser
  -> POST /api/vps/preview
  -> POST /api/vps/install
  -> Manager validates saved preset + SSH fingerprint
  -> initial SSH only
  -> remote-install.sh
       -> Docker/Certbot prerequisites
       -> Nginx :80
       -> Let's Encrypt
       -> security.bootstrap through the modular root helper
       -> Node API TCP/2222 protected
       -> start Remnawave Node
  -> Remnawave API creates/updates only Manager-owned node/profile objects
  -> Agent bootstrap
  -> Agent heartbeat
  -> first TLS verification queued
```

SSH is bootstrap/recovery transport, not the normal management channel.

## 7. Agent and privileged helper

The Go Agent is an unprivileged outbound HTTPS client. It performs:

- heartbeat / metrics
- long-poll job fetch
- allowlist enforcement
- result upload
- self-update staging

Privileged implementation is split under `v2/agent/helperlib/`.

Installed Node VPS artifacts:

```text
/usr/local/bin/node-manager-agent
/usr/local/libexec/node-manager-helper
/usr/local/libexec/node-manager-helperlib.zip
/usr/local/libexec/node-manager-updater
/usr/local/libexec/node-manager-fail2ban
/etc/node-manager/agent.env
/etc/systemd/system/node-manager-agent.service
/etc/sudoers.d/nodemanager-agent
/var/lib/node-manager/
```

The Agent user cannot submit arbitrary shell. The helper accepts only structured,
validated actions.

Fresh `security.bootstrap` is not an installed Agent sudo action. It is allowed
only from the fixed fresh-install staging launcher under
`/root/.xppn-pending/agent-helper.py`.

## 8. TLS ownership

TLS private material belongs to the Node VPS.

Node files:

```text
/etc/letsencrypt/live/<domain>/
/opt/nginx/certs/<domain>_fullchain.pem
/opt/nginx/certs/<domain>_privkey.key
```

The Remnawave Node container receives:

```text
/opt/nginx/certs:/opt/nginx/certs:ro
```

The Xray Config Profile stores only:

- `keyFile`
- `certificateFile`

Manager and Remnawave Panel do not store or mount the Node private key.

## 9. Node filesystem

Managed runtime locations:

```text
/opt/nginx/
  nginx.conf
  docker-compose.yml
  www/
  acme/
  logs/
  certs/

/opt/remnanode/
  docker-compose.yml
  node.env
  domain
  panel-ip

/var/log/remnanode/
```

Managed host security files may include:

```text
/etc/sysctl.d/90-xppn-baseline.conf
/etc/xppn-baseline-previous
/etc/fail2ban/jail.d/90-xppn-sshd.local
/usr/local/sbin/xppn-node-firewall
/etc/systemd/system/xppn-node-firewall.service
/etc/logrotate.d/xppn-nginx
/etc/logrotate.d/xppn-remnanode
```

The firewall helper owns only its dedicated Node API chains. It does not reset
global INPUT/FORWARD policy.

## 10. Manager VPS filesystem

Repository and environment:

```text
/opt/xppn-manager-v2/
/opt/xppn-manager-v2/v2/.env
```

Application data inside the Manager container:

```text
/data/xppn-v2.db
```

Host update state:

```text
/var/lib/xppn-v2-update/
/etc/xppn-v2-update.json
/usr/local/libexec/xppn-v2-updater.py
/etc/systemd/system/xppn-v2-updater.path
/etc/systemd/system/xppn-v2-updater.service
/root/xppn-v2-backups/
```

The historical `.env.preview` filename is supported only as a transition
fallback for existing installations.

## 11. Docker Compose naming

Primary files are:

- `v2/compose.yml`
- `v2/compose.public.yml`
- `v2/compose.attach.yml`

Development uses:

- `v2/compose.dev.yml`
- `v2/.env.dev`
- loopback port 8791
- project `xppn-v2-dev`
- a separate development volume

The old `compose.preview.yml` is retained temporarily because the root updater
from the previous release refers to that exact filename after it fetches new
Git code.

The Compose project name `xppn-v2-preview` is also intentionally retained for
production for now. It is a **stable legacy identity**, not a statement that the
current product is preview-only. Renaming the project would change the default
named volume identity and can make the existing SQLite volume appear missing.
That rename requires a dedicated volume migration, not a cosmetic refactor.

## 12. Manager self-update flow

```text
Browser
  -> fixed empty request marker
  -> systemd.path
  -> root-owned xppn-v2-updater.py
  -> verify repo/branch/clean tree
  -> SQLite online backup + env backup
  -> fast-forward Git
  -> rebuild only Manager container
  -> HTTP health check
  -> rollback Git + container on failure
```

The web container has no Docker socket.

## 13. Persistence and secrets

SQLite uses WAL and an application encryption key from `XPPN_DATA_KEY`.

Encrypted-at-rest values include relevant credentials/config contents. Secret
values are not returned by ordinary public API responses.

`storage.py` remains a compatibility facade. New persistence code should use
the domain repository or `core.database` directly.

## 14. Legacy v1 migration

The one-time v1 panel reader is isolated at:

```text
v2/legacy/migrate_v1.py
```

`v2/migrate.py` is only a compatibility entry point.

The tool:

- opens the old SQLite database read-only
- imports only the primary Remnawave connection
- does not import legacy nodes/VPS deployment state
- refuses to overwrite a configured v2 database

It is not part of Manager startup.

## 15. Compatibility shims

Compatibility files exist to avoid breaking old imports in one release. They
must stay small and must not gain new behavior.

Current shims include:

- `v2/template_engine.py`
- `v2/service.py`
- `v2/repositories/bridge.py`
- `v2/api/bridge.py`
- `v2/migrate.py`
- older staged domain facades such as `v2/vps_install.py`,
  `v2/node_local_tls.py`, `v2/node_removal.py`, etc.

New implementation must target the canonical package, not a shim.

## 16. Change rules

For architecture refactors:

1. branch from current `v2/rebuild-single-panel`
2. preserve public API contracts unless the change explicitly retires one
3. change structure before behavior
4. keep existing VPS state untouched by Manager-code updates
5. run full CI, Compose validation and Docker HTTP smoke test
6. merge only green code
7. never use `main` for v2 work

For destructive database cleanup:

1. create an explicit migration
2. take/verify backup first
3. test migration and rollback
4. never silently drop historical Bridge tables
