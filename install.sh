#!/usr/bin/env bash
#
# install.sh - install the WhiteDNS resolver scanner on Ubuntu/Debian.
#
# Run as root:  sudo bash install.sh
#
# Installs the headless scanner into /usr/local/bin and drops the sample
# candidate list next to it. The scanner needs no terminal, so it can run from
# a systemd timer or cron on a headless server.

set -euo pipefail

PREFIX=/usr/local
BINDIR="$PREFIX/bin"
DESTDIR="${WHITEDNS_SCAN_DIR:-/etc/whitedns-scan}"

say()  { printf '%s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  die "run this installer as root (sudo bash install.sh)"
fi
if ! command -v systemctl >/dev/null 2>&1; then
  die "systemd is required (Ubuntu/Debian server)"
fi

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SRC="$DIR/dnsscan-linux-$ARCH"
[[ -f "$SRC" ]] || die "scanner binary for linux/$ARCH not found next to this script"

install -d -m 0755 "$BINDIR"
install -m 0755 "$SRC" "$BINDIR/dnsscan"

install -d -m 0755 "$DESTDIR"
if [[ -f "$DIR/resolver-candidates.txt" && ! -f "$DESTDIR/resolver-candidates.txt" ]]; then
  install -m 0644 "$DIR/resolver-candidates.txt" "$DESTDIR/resolver-candidates.txt"
fi
if [[ -f "$DIR/scan-resolvers.sh" ]]; then
  install -m 0755 "$DIR/scan-resolvers.sh" "$DESTDIR/scan-resolvers.sh"
fi

say "Installed:"
say "  $BINDIR/dnsscan"
say "  $DESTDIR/scan-resolvers.sh"
say "  $DESTDIR/resolver-candidates.txt"
say ""
say "Run a scan:"
say "  cd $DESTDIR && sudo ./scan-resolvers.sh --samples 5 --workers 64"
say ""
say "The accepted resolver list is written to $DESTDIR/resolvers-valid.txt"
say "and the full report set to $DESTDIR/dns-scan/."
say ""
say "Point the client at the result, for example:"
say "  echo \"WHITEDNS_RESOLVERS=\$(tr '\\n' ',' < $DESTDIR/resolvers-valid.txt)\" \\"
say "    >> /etc/whitedns-bridge/bridge.env"
say "  systemctl restart whitedns-bridge"
