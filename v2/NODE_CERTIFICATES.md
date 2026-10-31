# Certbot on the node: TLS profile compatibility

**Important:** with unmodified Remnawave Panel and only the documented
Remnawave HTTP API, node-local `keyFile` / `certificateFile` references
inside a Remnawave Config Profile are **not supported**. These paths
are resolved and read on the **Panel backend**, which then forwards the
certificate material to the Node. A Docker volume that exists only on the
Node cannot make these file paths available to the Panel.

Official reference: https://docs.rw/install/remnawave-node/#xray-ssl-cert-for-node

## What actually happens today

- Certbot issues and renews certificates **on the Node VPS**.
- The source PEM and private key are stored in
  `/opt/nginx/certs/<domain>_fullchain.pem` and
  `/opt/nginx/certs/<domain>_privkey.key` (private key with restricted
  filesystem permissions).
- Remnawave Node Docker mounts these files read-only at the same paths.
  **This volume alone does not make Remnawave Profile file references work.**
- Agent v1.x reads the latest files through its authenticated outbound HTTPS
  connection to Manager. Manager validates the domain, validity period,
  and key/certificate match; it updates the dedicated Remnawave Xray
  Config Profile through the existing API and requests a targeted restart
  only if the material actually changed.
- **Remnawave itself therefore also stores the full certificate and
  private key as inline PEM in its Xray Config Profile**, as visible in its
  configuration editor. Manager does not persist PEM in its own database
  or return it to the browser.
- No certificate directories, Docker volumes or other components are
  installed on the Panel VPS by Manager.

## Why we did not silently replace PEM with paths

A working Xray-core process can read its own local keyFile directly, but
Remnawave's documented pipeline performs its file expansion *before*
sending the Xray config to the Node. Replacing the inline PEM with a path
only present on the Node risks the Panel failing to push a valid config,
breaking all TLS clients on the affected Node.

The Manager wizard now shows a **redacted inline PEM representation**
instead of incorrectly promising node-only paths in the actual Remnawave
profile. The API adapter explicitly rejects node-only `/opt/nginx/certs/`
and `/etc/letsencrypt/live/` paths when creating/updating a Remnawave
profile. This protects existing working Nodes.

## Paths-only architecture requires a deliberate upstream change

To keep the certificate's private key **exclusively** on the Node and
show only `keyFile` / `certificateFile` in Remnawave Config Profiles,
Remnawave must pass these paths through to the Node *without* resolving
them on the Panel. This requires a supported upstream feature or a
carefully versioned change to the Remnawave Panel/Node protocol. Neither
can be safely delivered through today's API-only integration.

Alternatively, the supported upstream model can use file references
by mounting the certificate files on the Panel backend; however, that
violates the project's explicit requirement that no certificate files
be created or mounted on the Panel VPS. Manager therefore does **not**
implement that route.

## Security

- Treat Remnawave Config Profile access as access to your live TLS private
  key. Restrict which administrators can read or export these profiles.
- Do not paste or screenshot visible PEM private key lines from the Panel.
- Rotate any key previously exposed in chat or screenshots and reissue
  the certificate with a **new private key**, then synchronize it via
  Agent / Remnawave API after verifying that the new files are correct.
- Installing this compatibility update does **not** change an already
  running Node or rewrite an existing Remnawave profile.
