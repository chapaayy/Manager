#!/usr/bin/env bash
# Conservative XPPN baseline for a freshly installed VPS only.
# Never change INPUT/FORWARD policy, sshd, Docker or network interfaces.
set -Eeuo pipefail
umask 077
say(){
  # No personal data, commands, tokens or IPs are logged: only allowlisted tags.
  printf 'BASELINE:%s\n' "$1"
  if [[ "$1" =~ ^[a-z0-9-]+$ ]]; then
    printf '%s\n' "$1" >> /var/log/xppn-baseline-status.log
  fi
}
SYSCTL_FILE=/etc/sysctl.d/90-xppn-baseline.conf
F2B_FILE=/etc/fail2ban/jail.d/90-xppn-sshd.local
ROTATE_FILE=/etc/logrotate.d/xppn-nginx

install_bbr() {
  if [[ -e "$SYSCTL_FILE" ]]; then say bbr-existing-not-modified; return; fi
  if ! command -v sysctl >/dev/null; then
    say bbr-not-supported; return
  fi
  if command -v modprobe >/dev/null; then
    modprobe tcp_bbr >/dev/null 2>&1 || true
    modprobe sch_fq >/dev/null 2>&1 || true
  fi
  if ! sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | tr ' ' '\n' | grep -Fxq bbr; then
    say bbr-not-supported; return
  fi
  local old_cc old_qdisc
  old_cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
  old_qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"
  if [[ ! "$old_cc" =~ ^[a-z0-9_]+$ || ! "$old_qdisc" =~ ^[a-z0-9_]+$ ]]; then
    say bbr-status-unavailable; return
  fi
  cat >"$SYSCTL_FILE" <<'CONF'
# Only BBR and FQ. No socket buffers, MTU or kernel backlog overrides.
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
CONF
  chmod 0644 "$SYSCTL_FILE"
  if ! sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 ||
     [[ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" != bbr ]] ||
     [[ "$(sysctl -n net.core.default_qdisc 2>/dev/null)" != fq ]]; then
    rm -f -- "$SYSCTL_FILE"
    sysctl -w "net.ipv4.tcp_congestion_control=$old_cc" >/dev/null 2>&1 || true
    sysctl -w "net.core.default_qdisc=$old_qdisc" >/dev/null 2>&1 || true
    say bbr-reverted; return
  fi
  printf 'tcp_congestion_control=%s\ndefault_qdisc=%s\n' "$old_cc" "$old_qdisc" > /etc/xppn-baseline-previous
  chmod 0600 /etc/xppn-baseline-previous
  say bbr-enabled
}

install_ssh_f2b() {
  if [[ -e "$F2B_FILE" ]]; then say fail2ban-existing-not-modified; return; fi
  local peer panel_ip ssh_ports
  peer="$(printenv SSH_CONNECTION 2>/dev/null | awk '{print $1}' || true)"
  if [[ -z "$peer" ]]; then
    peer="$(printenv SSH_CLIENT 2>/dev/null | awk '{print $1}' || true)"
  fi
  if [[ ! "$peer" =~ ^[0-9a-fA-F:.]+$ || -z "$peer" ]]; then
    say fail2ban-skipped-unknown-ssh-peer; return
  fi
  panel_ip="$(cat /opt/remnanode/panel-ip 2>/dev/null || true)"
  [[ "$panel_ip" =~ ^[0-9.]+$ ]] || panel_ip=''
  ssh_ports="$(/usr/sbin/sshd -T 2>/dev/null | awk '$1=="port" && $2~/^[0-9]+$/ {if(out!="")out=out",";out=out $2} END {print out}')"
  if [[ -z "$ssh_ports" || ! "$ssh_ports" =~ ^[0-9,]+$ ]]; then
    say fail2ban-skipped-ssh-port-unknown; return
  fi
  if command -v fail2ban-client >/dev/null; then
    say fail2ban-existing-not-modified; return
  fi
  if ! NEEDRESTART_MODE=l apt-get -o DPkg::Lock::Timeout=30 install -y -qq fail2ban python3-systemd >/dev/null 2>&1; then
    say fail2ban-package-unavailable; return
  fi
  install -d -m 0755 /etc/fail2ban/jail.d
  cat >"$F2B_FILE" <<CONF
# Only SSH. Do not change sshd or the host firewall defaults.
[sshd]
enabled = true
backend = systemd
mode = normal
port = $ssh_ports
maxretry = 6
findtime = 600
bantime = 3600
ignoreip = 127.0.0.1/8 ::1 $peer $panel_ip
CONF
  chmod 0644 "$F2B_FILE"
  if ! fail2ban-client -t >/dev/null 2>&1 ||
     ! systemctl enable fail2ban.service >/dev/null 2>&1 ||
     ! systemctl restart fail2ban.service >/dev/null 2>&1 ||
     ! fail2ban-client status sshd >/dev/null 2>&1; then
    rm -f -- "$F2B_FILE"
    systemctl disable --now fail2ban.service >/dev/null 2>&1 || true
    say fail2ban-reverted; return
  fi
  say fail2ban-ssh-enabled
}

install_nginx_logrotate() {
  if [[ -e "$ROTATE_FILE" ]]; then say nginx-logrotate-existing-not-modified; return; fi
  cat >"$ROTATE_FILE" <<'ROTATE'
/opt/nginx/logs/*.log {
    daily
    size 20M
    rotate 7
    compress
    missingok
    notifempty
    copytruncate
}
ROTATE
  chmod 0644 "$ROTATE_FILE"
  if ! logrotate -d "$ROTATE_FILE" >/dev/null 2>&1; then
    rm -f -- "$ROTATE_FILE"
    say nginx-logrotate-not-enabled
  else
    say nginx-logrotate-enabled
  fi
}

install_bbr || say bbr-skipped-error
install_ssh_f2b || say fail2ban-skipped-error
install_nginx_logrotate || say nginx-logrotate-skipped-error
say complete-no-firewall-or-ssh-modifications
