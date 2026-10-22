#!/usr/bin/env bash
#
# build.sh - cross-compile Soar Client for Linux.
#
# Usage: ./build.sh [version]
# Output: dist/soar-client-linux-amd64, dist/soar-client-linux-arm64

set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

VERSION="${1:-1.2.0}"

command -v go >/dev/null 2>&1 || {
  echo "error: Go 1.25 or newer is required" >&2
  exit 1
}

mkdir -p dist

for arch in amd64 arm64; do
  echo "Building linux/$arch..."
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
    -trimpath \
    -buildvcs=false \
    -ldflags "-s -w -X main.clientVersion=$VERSION" \
    -o "dist/soar-client-linux-$arch" .
  chmod 0755 "dist/soar-client-linux-$arch"
  echo "  -> dist/soar-client-linux-$arch"
done

echo
echo "Build complete: version $VERSION"
