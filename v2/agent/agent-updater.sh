#!/usr/bin/env bash
# Root-owned, locally scheduled update. Never uses SSH, sudoers edits or Docker.
# Requires a SHA-256 pinned binary previously downloaded over authenticated HTTPS.
set -Eeuo pipefail
umask 077
version="$1"
digest="$2"
[[ "$version" =~ ^1\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || exit 11
[[ "$digest" =~ ^[a-f0-9]{64}$ ]] || exit 12
install_dir=/usr/local/bin
state=/var/lib/node-manager
candidate="$state/update.bin"
target="$install_dir/node-manager-agent"
install -d -m 0700 -o root -g root /var/backups/node-manager
backup="/var/backups/node-manager/previous-agent"
ack="$state/update-ok"
pending="$state/update-pending"
[[ -f "$candidate" && ! -L "$candidate" && -f "$target" && ! -L "$target" ]] || exit 13
[[ "$(sha256sum "$candidate" | awk '{print $1}')" == "$digest" ]] || exit 14
tmp="$(mktemp "$install_dir/.node-manager-agent.XXXXXXXX")"
trap 'rm -f -- "$tmp"' EXIT
install -m 0755 -o root -g root "$candidate" "$tmp"
[[ "$(sha256sum "$tmp" | awk '{print $1}')" == "$digest" ]] || exit 15
install -m 0700 -o root -g root "$target" "$backup"
printf '%s %s\n' "$version" "$digest" > "$pending"
chown root:nodemanager "$pending"
chmod 0640 "$pending"
rm -f -- "$ack"
mv -f -- "$tmp" "$target"
if ! systemctl restart node-manager-agent.service; then
  install -m 0755 -o root -g root "$backup" "$target"
  systemctl restart node-manager-agent.service || true
  rm -f -- "$pending" "$candidate"
  exit 16
fi
verified=0
for _ in $(seq 1 18); do
  if [[ -f "$ack" && ! -L "$ack" &&
        "$(cat "$ack" 2>/dev/null)" == "$version $digest" ]] &&
        systemctl is-active --quiet node-manager-agent.service; then
    verified=1
    break
  fi
  sleep 5
done
if [[ "$verified" == 1 ]]; then
  rm -f -- "$pending" "$ack" "$candidate"
  logger -t xppn-agent-update "Update to $version verified"
else
  install -m 0755 -o root -g root "$backup" "$target"
  systemctl restart node-manager-agent.service || true
  rm -f -- "$pending" "$ack" "$candidate"
  logger -t xppn-agent-update "Update to $version rolled back after missing heartbeat"
  exit 17
fi
