# Changelog

## 1.2.0 - 2026-10-22

- Add `-username` and `-password` listener overrides.
- Add `SOAR_LISTEN`, `SOAR_USERNAME`, and `SOAR_PASSWORD` environment overrides.
  Precedence is config file < environment < flags.
- Validate the final configuration after overrides, so a public listener can be
  made valid by an environment credential without duplicating the JSON file.
- Add `soar-client@.service`, `soar-client-instance`, and
  `instance.env.example` for multiple independent SOCKS endpoints.
- Export variables sourced from `mode.env` so `SOAR_*` overrides reach the
  binary.
- Document multiple clients, load-balancing limits, and Soar vs CottenDNS.
- Update install, uninstall, package, README, and test report for 1.2.0.

## 1.1.0 - 2026-10-22

- Allow authenticated public SOCKS listeners on `0.0.0.0` / specific IPs.
- Reject unauthenticated non-loopback listeners.
- Add `StartLimitIntervalSec=0` for outage resilience.

## 1.0.0

- Initial combined Soar client and WhiteDNS resolver scanner.
