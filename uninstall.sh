#!/usr/bin/env bash
#
# uninstall.sh - stop and remove Soar Client.
#
# Usage: sudo bash uninstall.sh [--purge]
#   --purge  also remove /etc/soar-client, /var/lib/soar-client, and the user.

set -euo pipefail

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

[ "$(id -u)" -eq 0 ] || {
  echo "error: run this uninstaller as root" >&2
  exit 1
}

systemctl disable --now soar-client.service 2>/dev/null || true
for unit in $(systemctl list-units --type=service --all --no-legend 'soar-client@*.service' 2>/dev/null | awk '{print $1}'); do
  systemctl disable --now "$unit" 2>/dev/null || true
done
rm -f /etc/systemd/system/soar-client.service /etc/systemd/system/soar-client@.service
systemctl daemon-reload

rm -f /usr/local/bin/soar-client /usr/local/bin/soar-client-run /usr/local/bin/soar-client-instance

if [ "$PURGE" -eq 1 ]; then
  rm -rf /etc/soar-client /var/lib/soar-client
  userdel soar-client 2>/dev/null || true
  groupdel soar-client 2>/dev/null || true
  echo "Soar Client removed, including configuration and state."
else
  echo "Soar Client removed. Configuration kept in /etc/soar-client."
  echo "Run with --purge to remove it and the service user."
fi
