# Third-party components and provenance

## Soar engine

- Module: `github.com/getlantern/soar`
- Version: `v0.2.3`
- License: Apache License 2.0 (see `third_party/soar/LICENSE`)
- Source: https://github.com/getlantern/soar
- Vendored at `third_party/soar/` with the WhiteDNS transport changes from
  `WhiteDNS/WhiteDNS-Desktop` `Soar/third_party/soar/`. The client module uses a
  local `replace` directive so the build is reproducible without network access
  to the upstream module proxy.

## WhiteDNS Desktop Soar CLI

- Source: https://github.com/WhiteDNS/WhiteDNS-Desktop
- Path: `Soar/`
- Version: 1.6.7
- The client configuration schema, SOCKS5 proxy, startup HTTPS check,
  telemetry, and resolver planning are derived from this client.

## WhiteDNS resolver scanner engine (`internal/dnsscan`)

- Source: https://github.com/WhiteDNS/WhiteDNS-cleanip-finder
- Commit: `55960618b924018bda3e883155702ed7312eff98`
- Package: `internal/dnsscan`
- Files copied: `hijack.go`, `probe.go`, `rate_limit.go`, `report.go`,
  `scan.go`, `truth.go`, `utls.go`, `wire.go`
- The package is copied into `internal/dnsscan/` because Go does not allow
  importing another module's `internal/` package. The copied files are
  unmodified except for their location.
- The upstream snapshot at that commit does not contain a standalone LICENSE
  file. The scanner is used here as part of the same WhiteDNS project family.
  If the upstream maintainer requires a different arrangement, the scanner can
  be built as a separate `dnsscan` binary and called by the client instead.

The scanner's acceptance rule and report formats are documented in
`README.md`. It uses `github.com/refraction-networking/utls` v1.8.2 for
browser-like TLS when probing DoT/DoH transports. `utls` and its indirect
dependencies are fetched by Go modules and are not vendored in this repository.

## Candidate and resolver data

- `data/resolver-candidates.txt` is the Iranian IPv4 CIDR snapshot used by the
  standalone `whitedns-resolver-scan` release. It is based on the WhiteDNS
  range set, credited to KevinNet DNS (MIT).
- `data/resolvers/ir.txt`, `global.txt`, `cn.txt`, and `ru.txt` are snapshots
  from Soar v0.2.3 used by the resolver planner. See `data/THIRD_PARTY.md` and
  the KevinNet MIT notice there.
