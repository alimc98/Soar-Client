#!/usr/bin/env bash
#
# install.sh - install Soar Client on a systemd Linux host.
#
# Run as root from the unpacked release directory:
#   sudo bash install.sh
#
# Optional environment variables (used only when creating client.json):
#   SOAR_ZONE="zone.u.example.com"
#   SOAR_PUBLIC_KEY="base64-encoded-32-byte-ed25519-public-key="
#
# The installer never stops another service. If the old whitedns-soar service
# is active, stop it yourself before starting soar-client.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || die "run this installer as root"

if ! command -v systemctl >/dev/null 2>&1; then
  die "systemd is required"
fi

# Find the binary in a release directory or in a source checkout's dist/.
BIN=""
for candidate in \
  "$SCRIPT_DIR/soar-client" \
  "$SCRIPT_DIR/soar-client-linux-amd64" \
  "$SCRIPT_DIR/soar-client-linux-arm64" \
  "$SCRIPT_DIR/dist/soar-client-linux-amd64" \
  "$SCRIPT_DIR/dist/soar-client-linux-arm64"; do
  if [ -x "$candidate" ]; then
    BIN="$candidate"
    break
  fi
done
[ -n "$BIN" ] || die "soar-client binary not found next to this script"

say "Installing Soar Client..."
install -m 0755 "$BIN" /usr/local/bin/soar-client

# Service account.
if ! getent group soar-client >/dev/null 2>&1; then
  groupadd --system soar-client
fi
if ! id -u soar-client >/dev/null 2>&1; then
  NOLOGIN="$(command -v nologin || echo /sbin/nologin)"
  useradd --system --gid soar-client --home-dir /var/lib/soar-client \
    --shell "$NOLOGIN" soar-client
fi

install -d -m 0750 -o root -g soar-client /etc/soar-client
install -d -m 0750 -o soar-client -g soar-client /var/lib/soar-client

# Client configuration. Never overwrite an existing working profile.
if [ ! -f /etc/soar-client/client.json ]; then
  install -m 0640 -o root -g soar-client "$SCRIPT_DIR/config.example.json" /etc/soar-client/client.json
  if [ -n "${SOAR_ZONE:-}" ] && [ -n "${SOAR_PUBLIC_KEY:-}" ]; then
    sed -i \
      -e "s|your-zone.u.example.com|${SOAR_ZONE}|g" \
      -e "s|BASE64_32_BYTE_ED25519_PUBLIC_KEY=|${SOAR_PUBLIC_KEY}|g" \
      /etc/soar-client/client.json
  fi
fi

# Manual resolver list.
if [ ! -f /etc/soar-client/resolvers.txt ]; then
  install -m 0640 -o root -g soar-client "$SCRIPT_DIR/resolvers.example.txt" /etc/soar-client/resolvers.txt
fi

# Candidate CIDR list for auto mode.
if [ ! -f /etc/soar-client/candidates.txt ]; then
  if [ -f "$SCRIPT_DIR/candidates.txt" ]; then
    install -m 0644 -o root -g root "$SCRIPT_DIR/candidates.txt" /etc/soar-client/candidates.txt
  elif [ -f "$SCRIPT_DIR/data/resolver-candidates.txt" ]; then
    install -m 0644 -o root -g root "$SCRIPT_DIR/data/resolver-candidates.txt" /etc/soar-client/candidates.txt
  fi
fi

# Mode selector and wrapper.
if [ ! -f /etc/soar-client/mode.env ]; then
  install -m 0640 -o root -g soar-client "$SCRIPT_DIR/mode.env.example" /etc/soar-client/mode.env
fi
install -m 0755 "$SCRIPT_DIR/soar-client-run" /usr/local/bin/soar-client-run

install -m 0644 "$SCRIPT_DIR/soar-client.service" /etc/systemd/system/soar-client.service
systemctl daemon-reload

if grep -q 'your-zone.u.example.com' /etc/soar-client/client.json; then
  say ""
  say "Configuration still has placeholders. Edit it before starting:"
  say "  /etc/soar-client/client.json"
  say ""
  say "Then start the service:"
  say "  systemctl enable --now soar-client"
  exit 0
fi

if systemctl is-active --quiet whitedns-soar.service 2>/dev/null; then
  say ""
  say "warning: whitedns-soar.service is active and may hold 127.0.0.1:10886."
  say "         Disable it before starting soar-client:"
  say "           systemctl disable --now whitedns-soar"
  say ""
  exit 0
fi

systemctl enable --now soar-client.service
say ""
say "Soar Client installed and started."
say "  status : systemctl status soar-client"
say "  logs   : journalctl -u soar-client -f"
say "  mode   : /etc/soar-client/mode.env"
say "  config : /etc/soar-client/client.json"
say "  list   : /etc/soar-client/resolvers.txt"
say "  SOCKS  : from client.json (default 127.0.0.1:10886; TCP CONNECT only)"
say "           public binds require username/password in client.json"
