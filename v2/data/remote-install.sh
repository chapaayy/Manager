#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
export DEBIAN_FRONTEND=noninteractive

DOMAIN="$(cat /root/.xppn-pending/domain)"
PANEL_IP="$(cat /root/.xppn-pending/panel-ip)"
[[ "$DOMAIN" =~ ^[a-z0-9][a-z0-9.-]*\.[a-z]{2,63}$ ]] || exit 51
[[ "$PANEL_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || exit 52
[[ "$(id -u)" == 0 ]] || exit 53

if [[ -e /opt/remnanode || -e /opt/nginx ]]; then
  echo "ABORT: Existing nginx/remnanode directories. No files changed."
  exit 54
fi
for port in 80 443 2222; do
  if ss -ltnH | awk '{print $4}' | grep -Eq "(^|:)$port$"; then
    echo "ABORT: Port $port already in use."
    exit 55
  fi
done

. /etc/os-release
[[ "$ID" == ubuntu || "$ID" == debian ]] || exit 56

echo "STEP: Installing Docker, Certbot and required system tools"
apt-get update -qq
apt-get install -y -qq docker.io docker-compose-v2 certbot iptables   ca-certificates curl logrotate python3
systemctl enable --now docker
docker info >/dev/null
docker compose version >/dev/null

install -d -m 0755   /opt/nginx /opt/nginx/www /opt/nginx/acme /opt/nginx/logs   /opt/nginx/certs /opt/remnanode /var/log/remnanode
install -m 0644 /root/.xppn-pending/nginx.conf /opt/nginx/nginx.conf
install -m 0644 /root/.xppn-pending/nginx-compose.yml /opt/nginx/docker-compose.yml
install -m 0644 /root/.xppn-pending/remnanode-compose.yml /opt/remnanode/docker-compose.yml
install -m 0600 /root/.xppn-pending/node.env /opt/remnanode/node.env
install -m 0644 /root/.xppn-pending/index.html /opt/nginx/www/index.html
install -m 0600 /root/.xppn-pending/domain /opt/remnanode/domain
install -m 0600 /root/.xppn-pending/panel-ip /opt/remnanode/panel-ip

echo "STEP: Starting Nginx on port 80"
docker compose -f /opt/nginx/docker-compose.yml config -q
docker compose -f /opt/nginx/docker-compose.yml up -d nginx
docker exec nginx nginx -t

echo "STEP: Acquiring TLS certificate"
certbot certonly --webroot -w /opt/nginx/acme -d "$DOMAIN"   --non-interactive --agree-tos --register-unsafely-without-email --keep-until-expiring
CERT="/etc/letsencrypt/live/$DOMAIN"
test -s "$CERT/fullchain.pem" && test -s "$CERT/privkey.pem"
install -m 0644 "$CERT/fullchain.pem" "/opt/nginx/certs/$DOMAIN""_fullchain.pem"
install -m 0600 "$CERT/privkey.pem" "/opt/nginx/certs/$DOMAIN""_privkey.key"

cat >/usr/local/sbin/xppn-cert-refresh <<'HOOK'
#!/usr/bin/env bash
set -Eeuo pipefail
domain="$(cat /opt/remnanode/domain)"
source="/etc/letsencrypt/live/$domain"
install -m 0644 "$source/fullchain.pem" "/opt/nginx/certs/$domain""_fullchain.pem"
install -m 0600 "$source/privkey.pem" "/opt/nginx/certs/$domain""_privkey.key"
logger -t node-certbot "TLS files refreshed on this VPS; Manager will verify and reload Xray if needed"
HOOK
chmod 0700 /usr/local/sbin/xppn-cert-refresh

install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat >/etc/letsencrypt/renewal-hooks/deploy/xppn-node.sh <<'HOOK'
#!/usr/bin/env bash
exec /usr/local/sbin/xppn-cert-refresh
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/xppn-node.sh
systemctl enable --now certbot.timer >/dev/null 2>&1 || true

echo "STEP: Applying unified network and security baseline"
test -s /root/.xppn-pending/agent-helper.py
test -s /root/.xppn-pending/agent-helperlib.zip
python3 /root/.xppn-pending/agent-helper.py security.bootstrap   </dev/null >/var/log/xppn-security-bootstrap.json
chmod 0600 /var/log/xppn-security-bootstrap.json
systemctl is-enabled --quiet xppn-node-firewall.service
systemctl is-active --quiet xppn-node-firewall.service

echo "STEP: Starting Remnawave Node"
docker compose -f /opt/remnanode/docker-compose.yml config -q
docker compose -f /opt/remnanode/docker-compose.yml up -d remnanode
test "$(docker inspect --format '{{.State.Running}}' remnanode)" = true
echo "STEP: REMNANODE_RUNNING"

rm -rf /root/.xppn-pending
echo "STEP: COMPLETE"
