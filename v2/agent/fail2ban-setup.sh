#!/usr/bin/env bash
# SSH-only Fail2Ban setup; systemd transient service; no arbitrary shell inputs.
set -Eeuo pipefail
umask 077
admin="$1"
STATE=/var/lib/node-manager/ssh-protection.state
CONF=/etc/fail2ban/jail.d/90-xppn-sshd.local
mkdir -p -m 0700 /var/lib/node-manager
emit(){ printf '%s\n' "$1" > "$STATE"; logger -t xppn-ssh-protection -- "$1"; }
valid_ip(){
  python3 - "$1" <<'PY'
import ipaddress,sys
try:
 a=ipaddress.ip_address(sys.argv[1])
 assert a.is_global and a.version==4
except (ValueError,AssertionError):
 sys.exit(1)
PY
}
if ! valid_ip "$admin"; then emit invalid-admin-ip; exit 11; fi
if ! systemctl is-active --quiet ssh.service && ! systemctl is-active --quiet sshd.service; then
  emit ssh-not-active; exit 12
fi
ssh_ports="$(/usr/sbin/sshd -T 2>/dev/null | awk '$1=="port" && $2~/^[0-9]+$/ {if(out!="") out=out",";out=out $2} END{print out}')"
if [[ ! "$ssh_ports" =~ ^[0-9]{1,5}(,[0-9]{1,5})*$ ]]; then
  emit ssh-port-unavailable; exit 13
fi
if [[ -e "$CONF" ]]; then
  if systemctl is-active --quiet fail2ban.service && fail2ban-client status sshd >/dev/null 2>&1; then
    emit already-protected; exit 0
  fi
  emit existing-xppn-config-needs-review; exit 14
fi
if command -v fail2ban-client >/dev/null; then
  emit existing-fail2ban-needs-review; exit 15
fi
if ! command -v nft >/dev/null && ! command -v iptables >/dev/null; then
  emit no-supported-firewall-tool; exit 16
fi
emit installing-packages
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
if ! apt-get -o DPkg::Lock::Timeout=60 install -y -qq fail2ban python3-systemd >/dev/null 2>&1; then
  emit package-install-failed; exit 17
fi
mkdir -p -m 0755 /etc/fail2ban/jail.d
if [[ -e "$CONF" ]]; then emit config-conflict; exit 18; fi
panel_ip="$(cat /opt/remnanode/panel-ip 2>/dev/null || true)"
if ! valid_ip "$panel_ip"; then panel_ip=""; fi
cat >"$CONF" <<CFG
# XPPN: dedicated SSH-only protection; no Docker or node API changes.
[sshd]
enabled = true
backend = systemd
mode = normal
port = $ssh_ports
maxretry = 6
findtime = 600
bantime = 3600
ignoreip = 127.0.0.1/8 ::1 $admin $panel_ip
CFG
chmod 0644 "$CONF"
if ! fail2ban-client -t >/dev/null 2>&1; then
  rm -f -- "$CONF"
  emit configuration-invalid; exit 19
fi
if ! systemctl enable fail2ban.service >/dev/null 2>&1 ||
   ! systemctl restart fail2ban.service >/dev/null 2>&1 ||
   ! fail2ban-client status sshd >/dev/null 2>&1; then
  rm -f -- "$CONF"
  systemctl disable --now fail2ban.service >/dev/null 2>&1 || true
  emit ssh-jail-not-started; exit 20
fi
emit ssh-protected
