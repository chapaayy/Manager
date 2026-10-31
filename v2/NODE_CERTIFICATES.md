# Node-owned Certbot certificates

This feature does not create, copy or mount any certificate files on the
Remnawave Panel VPS. The Panel is used only through its existing HTTP API.

## Installed VPS layout

On every new node, Certbot issues and renews TLS files under
/etc/letsencrypt/live/<domain>. The deploy hook copies the latest certificate
and private key to the node's /opt/nginx/certs directory.

The remnanode Docker Compose already mounts that directory read-only:

    volumes:
      - /opt/nginx/certs:/opt/nginx/certs:ro
      - /var/log/remnanode:/var/log/remnanode

No extra mounts on the Panel or other servers are needed.

## Important Remnawave compatibility limitation

Xray-core can use keyFile and certificateFile on its own machine. However,
Remnawave documents that file references inside a Remnawave Xray Config Profile
are resolved by the Panel backend, not by a Node. A keyFile pointing only to
the node-local directory therefore cannot be assumed to work through this API.

To keep the known-working Remnawave integration without changing the Panel:

- Certbot and the authoritative certificate files stay on the node.
- The Manager fetches the newest files using pinned SSH access and validates
  SAN/domain, validity dates and the matching private key.
- Only the TLS key/certificate fields of this Manager-owned dedicated profile
  are refreshed via the existing Remnawave API. Other Xray fields are preserved.
- Remnawave's Config Profile therefore necessarily retains inline PEM just as
  it did with the original installer. The Manager does not persist those bytes.
- A file-backed, shared or otherwise unfamiliar profile is never rewritten.

Thus this design **does not** make Remnawave's API JSON smaller. It avoids
unverified changes that might break a working Node.

## Automatic update after Certbot renewal

1. Update Manager from v2/rebuild-single-panel.
2. Open the new Сертификаты нод page.
3. For an already installed, ready node, use Включить авто and provide the
   root SSH password once. Approve the installation of the restricted SSH key.
4. The key is restricted by an authorized_keys forced command and cannot open
   an interactive shell. It can read only that VPS's certificate and key.
   The private SSH key is encrypted in the Manager database. The root
   password is never stored.
5. Every six hours while Manager is running, it reads the latest TLS files
   from the VPS. When required, it patches only that node's dedicated Xray
   profile through the Remnawave API and requests a targeted node restart.

For a one-off sync without SSH key enrollment, use Проверить и применить.

If the Remnawave profile belongs to another node, has been changed manually,
or the pinned SSH fingerprint differs, the Manager refuses to rewrite it.

Installing this update changes no existing VPS or Xray profile. Automatic
certificate synchronization is opt-in, per node.

## Verify on the node

Without printing private certificate contents:

    systemctl status certbot.timer --no-pager
    ls -ld /opt/nginx/certs
    docker compose -f /opt/remnanode/docker-compose.yml config -q

Use the Сертификаты нод page for expiry and last-checked status.

The TLS private key previously pasted from RUS10 should be rotated by
reissuing the certificate with a genuinely new private key before using it
for live traffic.

## Security notes

Remnawave receives inline PEM material over its TLS-protected API by design;
the private key can still exist in Remnawave's own profile store. It is not
stored or returned by the Manager. Do not log API payloads or publish the
Remnawave configuration JSON.

A renewed certificate is applied on the next successful Manager sync. The
certbot deploy hook intentionally does not restart Remnawave Node before the
API profile has been updated; otherwise it would reload the old PEM.
