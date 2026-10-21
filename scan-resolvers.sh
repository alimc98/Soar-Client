#!/usr/bin/env bash
#
# scan-resolvers.sh - run the headless WhiteDNS resolver scanner on this host.
#
# The scanner probes candidate DNS resolvers and keeps only the ones that
# actually carry a tunnel: a clean recursive answer, no poisoning, no NXDOMAIN
# hijacking, and TXT passthrough intact. The surviving IPs are written where
# the client can read them.
#
# Usage:
#   ./scan-resolvers.sh [options]
#
# Options:
#   -l, --list FILE       candidate list (IPs and/or CIDR ranges)  [./resolver-candidates.txt]
#   -s, --samples N       addresses to sample per CIDR range      [5]
#   -w, --workers N       concurrent resolver probes              [64]
#   -p, --protocol P      udp | tcp | both | all                  [both]
#   -t, --timeout SEC     per-probe timeout                       [3]
#   -d, --depth MODE      fast | full                             [full]
#       --txt-domain D    TXT probe target (must have a TXT record) [_dmarc.google.com]
#       --out DIR         report directory                       [./dns-scan]
#       --out-list FILE   file for the accepted resolver IPs     [./resolvers-valid.txt]
#       --rate N          whole-scan query rate limit            [0 = unlimited]
#       --nearby          expand the /24 around every hit and rescan
#   -h, --help            show this help
#
# Exit codes: 0 = at least one resolver accepted, 1 = none accepted, 2 = usage error.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# The scanner may sit next to this script (unpacked release) or be installed
# system-wide by install.sh.
SCANNER=""
for candidate in "$SCRIPT_DIR/dnsscan" "$SCRIPT_DIR/dnsscan-linux-amd64" "$SCRIPT_DIR/dnsscan-linux-arm64" /usr/local/bin/dnsscan; do
  if [[ -x "$candidate" ]]; then
    SCANNER="$candidate"
    break
  fi
done
if [[ -z "$SCANNER" ]]; then
  echo "error: scanner binary not found (looked next to this script and in /usr/local/bin)" >&2
  exit 2
fi

LIST="$SCRIPT_DIR/resolver-candidates.txt"
SAMPLES=5
WORKERS=64
PROTOCOL=both
TIMEOUT=3
DEPTH=full
TXT_DOMAIN="_dmarc.google.com"
OUT_DIR="$SCRIPT_DIR/dns-scan"
OUT_LIST="$SCRIPT_DIR/resolvers-valid.txt"
RATE=0
NEARBY=""

die() { printf 'error: %s\n' "$*" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -l|--list)        LIST="${2:-}"; shift 2 ;;
    -s|--samples)     SAMPLES="${2:-}"; shift 2 ;;
    -w|--workers)     WORKERS="${2:-}"; shift 2 ;;
    -p|--protocol)    PROTOCOL="${2:-}"; shift 2 ;;
    -t|--timeout)     TIMEOUT="${2:-}"; shift 2 ;;
    -d|--depth)       DEPTH="${2:-}"; shift 2 ;;
    --txt-domain)     TXT_DOMAIN="${2:-}"; shift 2 ;;
    --out)            OUT_DIR="${2:-}"; shift 2 ;;
    --out-list)       OUT_LIST="${2:-}"; shift 2 ;;
    --rate)           RATE="${2:-}"; shift 2 ;;
    --nearby)         NEARBY="-nearby"; shift ;;
    -h|--help)        sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)                die "unknown option: $1" ;;
  esac
done

[[ -r "$LIST" ]] || die "candidate list not readable: $LIST"
[[ -x "$SCANNER" ]] || die "scanner binary not executable: $SCANNER"

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

echo "== resolver scan =="
echo "list      : $LIST"
echo "samples   : $SAMPLES per range"
echo "protocol  : $PROTOCOL"
echo "workers   : $WORKERS"
echo "depth     : $DEPTH"
echo "txt probe : $TXT_DOMAIN"
echo "reports   : $OUT_DIR"
echo

set +e
"$SCANNER" \
  -list "$LIST" \
  -samples "$SAMPLES" \
  -workers "$WORKERS" \
  -protocol "$PROTOCOL" \
  -timeout "${TIMEOUT}s" \
  -depth "$DEPTH" \
  -txt-domain "$TXT_DOMAIN" \
  -rate "$RATE" \
  -out "$OUT_DIR" \
  -out-list "$OUT_LIST" \
  $NEARBY
RC=$?
set -e

if [[ $RC -ne 0 ]]; then
  echo "scanner exited with code $RC" >&2
  exit $RC
fi

ACCEPTED=0
[[ -s "$OUT_LIST" ]] && ACCEPTED="$(grep -c . "$OUT_LIST" || true)"
echo
if [[ "$ACCEPTED" -gt 0 ]]; then
  echo "OK: $ACCEPTED resolver(s) accepted -> $OUT_LIST"
  exit 0
fi
echo "WARN: no resolver passed; the tunnel has no usable resolver from this host" >&2
exit 1
