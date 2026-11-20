#!/usr/bin/env bash
# Uninstall the sing-box 5-in-1 node installed by install.sh.
# Removes the service, binary, config, keys and generated client files.
# It does NOT revert SSH hardening (key-only login, fail2ban, UFW rules):
# those are system-level protections and stay in place on purpose.
# Usage: sudo bash uninstall.sh
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then echo "Please run as root (sudo)." >&2; exit 1; fi

systemctl disable --now sing-box 2>/dev/null || true
rm -f /etc/systemd/system/sing-box.service
systemctl daemon-reload
rm -rf /etc/s-box /usr/local/bin/sing-box

echo "sing-box removed. UFW rules, fail2ban and SSH hardening were left as-is."
echo "To close the node ports in UFW as well, run:"
echo "  ufw delete allow 443/tcp; ufw delete allow 8443/udp"
echo "  ufw delete allow 8444/udp; ufw delete allow 8445/tcp; ufw delete allow 8446/tcp"
