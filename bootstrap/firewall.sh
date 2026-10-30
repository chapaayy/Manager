#!/usr/bin/env bash
# Enforce panel-only reachability on the node control port after each reboot.
set -Eeuo pipefail
[[ -r /etc/xppn-node-panel-ip ]] || exit 0
# Written only by the trusted host helper after validation.
source /etc/xppn-node-panel-ip
[[ "$PANEL_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || exit 1
# Do not modify any other port (including SSH).
/usr/sbin/iptables -C INPUT -p tcp --dport 2222 -j DROP 2>/dev/null || /usr/sbin/iptables -I INPUT 1 -p tcp --dport 2222 -j DROP
/usr/sbin/iptables -C INPUT -p tcp --dport 2222 -s "$PANEL_IP" -j ACCEPT 2>/dev/null || /usr/sbin/iptables -I INPUT 1 -p tcp --dport 2222 -s "$PANEL_IP" -j ACCEPT
/usr/sbin/ip6tables -C INPUT -p tcp --dport 2222 -j DROP 2>/dev/null || /usr/sbin/ip6tables -I INPUT 1 -p tcp --dport 2222 -j DROP
