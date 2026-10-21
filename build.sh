#!/usr/bin/env bash
#
# build.sh - build the headless scanner binaries from upstream sources.
#
# Usage:  bash build.sh [version]
#
# The scanner command lives inside the upstream cleanip-finder module (it
# imports the module's internal dnsscan package), so this script clones that
# repository at a pinned commit, copies our command into its cmd/ tree, and
# cross-compiles the result.
#
# Output: dnsscan-linux-amd64 and dnsscan-linux-arm64 next to this script.
#
# Paths are kept relative on purpose: some environments hand native tools
# (git, go) paths they cannot resolve.

set -euo pipefail

VERSION="${1:-1.0.0}"
UPSTREAM_REPO="https://github.com/WhiteDNS/WhiteDNS-cleanip-finder.git"
UPSTREAM_COMMIT="55960618b924018bda3e883155702ed7312eff98"

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v go >/dev/null 2>&1 || die "go is required (1.25 or newer)"

rm -rf .build
mkdir -p .build

say "Cloning upstream cleanip-finder..."
git clone --quiet "$UPSTREAM_REPO" .build/cleanip-finder
git -C .build/cleanip-finder checkout --quiet "$UPSTREAM_COMMIT"
say "Pinned upstream commit: $UPSTREAM_COMMIT"

say "Adding the headless scanner command..."
mkdir -p .build/cleanip-finder/cmd/dnsscanheadless
cp cmd/dnsscanheadless/main.go .build/cleanip-finder/cmd/dnsscanheadless/main.go

for arch in amd64 arm64; do
  say "Building linux/$arch..."
  (
    cd .build/cleanip-finder
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
      -trimpath -ldflags "-s -w" \
      -o "../../dnsscan-linux-$arch" \
      ./cmd/dnsscanheadless/
  )
  chmod 0755 "dnsscan-linux-$arch"
  say "  -> dnsscan-linux-$arch"
done

rm -rf .build
say ""
say "Build complete. Create the release tarballs with: bash package.sh $VERSION"
