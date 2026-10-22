#!/usr/bin/env bash
#
# package.sh - build release tarballs.
#
# Usage: ./package.sh [version]
# Requires the binaries produced by ./build.sh.

set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

VERSION="${1:-1.2.0}"

for arch in amd64 arm64; do
  BIN="dist/soar-client-linux-$arch"
  [ -f "$BIN" ] || {
    echo "error: $BIN is missing; run ./build.sh $VERSION first" >&2
    exit 1
  }
done

for arch in amd64 arm64; do
  STAGE="dist/soar-client-$VERSION-linux-$arch"
  rm -rf "$STAGE"
  mkdir -p "$STAGE"
  cp "dist/soar-client-linux-$arch" "$STAGE/soar-client"
  cp install.sh uninstall.sh soar-client.service soar-client@.service \
    soar-client-run soar-client-instance mode.env.example instance.env.example \
    config.example.json resolvers.example.txt README.md THIRD_PARTY.md CHANGELOG.md "$STAGE/"
  cp data/resolver-candidates.txt "$STAGE/candidates.txt"
  chmod 0755 "$STAGE/soar-client" "$STAGE/install.sh" "$STAGE/uninstall.sh" \
    "$STAGE/soar-client-run" "$STAGE/soar-client-instance"
  tar -czf "dist/soar-client-$VERSION-linux-$arch.tar.gz" -C dist "soar-client-$VERSION-linux-$arch"
  echo "  -> dist/soar-client-$VERSION-linux-$arch.tar.gz"
  rm -rf "$STAGE"
done

echo
echo "Packages complete: version $VERSION"
