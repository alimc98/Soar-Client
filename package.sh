#!/usr/bin/env bash
#
# package.sh - build the release tarballs for the headless resolver scanner.
#
# Usage:  bash package.sh [version]
#
# Produces dist/whitedns-resolver-scan-<version>-linux-<arch>.tar.gz for
# amd64 and arm64. Run build.sh first so the binaries exist.
#
# Paths are kept relative on purpose: some environments hand native tools
# paths they cannot resolve.

set -euo pipefail

VERSION="${1:-1.0.0}"
ARCHES=(amd64 arm64)

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

rm -rf dist
mkdir -p dist

for arch in "${ARCHES[@]}"; do
  src="dnsscan-linux-$arch"
  [[ -f "$src" ]] || { printf 'error: %s missing; run build.sh first\n' "$src" >&2; exit 1; }

  stage="dist/whitedns-resolver-scan-$VERSION-linux-$arch"
  mkdir -p "$stage"
  cp "$src" "$stage/dnsscan-linux-$arch"
  cp scan-resolvers.sh install.sh resolver-candidates.txt README.md "$stage/"
  chmod 0755 "$stage/dnsscan-linux-$arch" "$stage/scan-resolvers.sh" "$stage/install.sh"

  (cd dist && tar -czf "whitedns-resolver-scan-$VERSION-linux-$arch.tar.gz" \
    "whitedns-resolver-scan-$VERSION-linux-$arch")
  rm -rf "$stage"
  printf 'built dist/whitedns-resolver-scan-%s-linux-%s.tar.gz\n' "$VERSION" "$arch"
done
