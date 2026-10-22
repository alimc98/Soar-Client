# Soar Client

A Linux client for the WhiteDNS Soar DNS tunnel, built from the `Soar/` engine
in [WhiteDNS/WhiteDNS-Desktop](https://github.com/WhiteDNS/WhiteDNS-Desktop),
with the WhiteDNS resolver scanner integrated into the same binary.

The client exposes a **loopback SOCKS5 `CONNECT`** proxy. TCP traffic sent to
the proxy travels through an authenticated DNS tunnel to the Soar server. A
resolver can be supplied manually, or the client can scan candidate IPs/CIDRs,
keep the resolvers that actually carry a tunnel, and start with that list.

> This project was renamed from `whitedns-resolver-scan` to `Soar-Client`.
> The old repository only contained the standalone scanner; this repository is
> the combined client + scanner.

> **Status:** client `1.0.0` was tested on 2026-10-22 on AlmaLinux 8.10 against
> a live Soar `0.5.0` server. Manual and auto modes authenticated and carried
> real HTTPS traffic through the tunnel; scan-only and scan+verify paths were
> tested as well.

## What is inside

```
Soar engine (WhiteDNS-Desktop/Soar 1.6.7)
  + SOCKS5 CONNECT proxy
  + authenticated startup HTTPS check
  + resolver discovery / failover
  + integrated WhiteDNS dnsscan engine
      - clean A answer
      - recursion available
      - no NXDOMAIN hijack
      - TXT passthrough
      - EDNS0 on UDP
  + final Soar handshake verification of every scan survivor
```

The scanner checks are generic DNS checks. The final verification is stronger:
it authenticates **your** Soar zone and public key through each candidate and
fetches real HTTPS. A resolver that passes the DNS checks but cannot reach your
server is discarded before the proxy starts.

## Modes

| Mode | How it gets resolvers | Command |
|---|---|---|
| `manual` | Your `resolvers.txt` (IP or `IP:port`, comments allowed) | `soar-client run -config client.json -resolvers resolvers.txt` |
| `auto` | Scans candidates, verifies survivors, then starts the proxy | `soar-client run -config client.json -scan -candidates candidates.txt` |
| `scan` | Scans only; writes reports and a resolver list | `soar-client scan -candidates candidates.txt -out-list resolvers-valid.txt` |

`manual` and `auto` disable Soar's built-in discovery by default, so the list
you measured is the list that is used. Add `-discovery on` if you also want the
bundled country/global fallback.

## Quick start

### 1. Build

Go 1.25 or newer is required.

```bash
./build.sh 1.0.0
```

Output:

```
dist/soar-client-linux-amd64
dist/soar-client-linux-arm64
```

### 2. Install

```bash
sudo bash install.sh
```

or, from a release tarball:

```bash
tar -xzf soar-client-1.0.0-linux-amd64.tar.gz
cd soar-client-1.0.0-linux-amd64
sudo bash install.sh
```

The installer creates:

| Path | Purpose |
|---|---|
| `/usr/local/bin/soar-client` | client + scanner binary |
| `/usr/local/bin/soar-client-run` | reads `/etc/soar-client/mode.env` and starts the client |
| `/etc/soar-client/client.json` | Soar zone, public key, listen address, advanced options |
| `/etc/soar-client/resolvers.txt` | manual resolver list |
| `/etc/soar-client/candidates.txt` | bundled Iranian CIDR list for auto mode |
| `/etc/soar-client/mode.env` | selects manual or auto mode for systemd |
| `/etc/systemd/system/soar-client.service` | systemd unit |
| `/var/lib/soar-client/` | scan reports and generated resolver lists |

Edit `/etc/soar-client/client.json` and set `zone` and `server_public_key` from
the Soar panel account. Then:

```bash
systemctl enable --now soar-client
journalctl -u soar-client -f
```

When the tunnel is ready the log contains:

```
SOAR_READY authenticated=1 https=1
```

The SOCKS proxy is `127.0.0.1:10886` by default.

### 3. Manual mode

Put your working resolvers in `/etc/soar-client/resolvers.txt`:

```
1.1.1.1
8.8.8.8
9.9.9.9
217.218.155.155
178.252.143.133
```

Start:

```bash
soar-client run -config /etc/soar-client/client.json \
  -mode manual -resolvers /etc/soar-client/resolvers.txt
```

Manual mode starts immediately by default: the list is yours, so the client
does not add a verification delay. Use `-verify=on` if you want every entry
checked with a real Soar handshake before the SOCKS listener is opened, or
`-verify=off` to make the fast path explicit.

### 4. Auto mode

```bash
soar-client run -config /etc/soar-client/client.json \
  -mode auto \
  -candidates /etc/soar-client/candidates.txt \
  -scan-out /var/lib/soar-client/scan \
  -scan-list /var/lib/soar-client/resolvers-auto.txt
```

What happens:

1. The candidate file is expanded. CIDR ranges are sampled with `-samples`
   (default 5 addresses per range, spread evenly over usable hosts).
2. Every address is probed by the integrated `dnsscan` engine.
3. Survivors are verified with the real Soar server key/zone and HTTPS.
4. The verified list is written to `-scan-list` and used to start the proxy.
5. Reports are written to `-scan-out`.

The default embedded candidate list is the Iranian CIDR snapshot in
`data/resolver-candidates.txt`. `-candidates embedded` selects it explicitly.

### 5. Scan only

```bash
soar-client scan \
  -candidates /etc/soar-client/candidates.txt \
  -samples 5 \
  -workers 64 \
  -protocol both \
  -depth full \
  -out /var/lib/soar-client/scan \
  -out-list /var/lib/soar-client/resolvers-valid.txt
```

The standalone `scan` subcommand verifies only when you add `-config client.json
-verify`; this is different from `run -mode scan`, which verifies by default:

```bash
soar-client scan -candidates candidates.txt \
  -out-list resolvers-valid.txt \
  -config /etc/soar-client/client.json -verify
```

## Scanner flags

| Flag | Default | Purpose |
|---|---|---|
| `-candidates FILE` | embedded | IPs and/or CIDR ranges; `-list` is an alias |
| `-samples N` | `5` | Addresses per CIDR (`0` = every host; large ranges are refused) |
| `-protocol P` | `both` | `udp`, `tcp`, `both`, `all` |
| `-ports LIST` | `53` | Ports to probe |
| `-workers N` | `64` | Concurrent resolver probes |
| `-scan-timeout D` | `3s` | Per-probe timeout (`-timeout` alias) |
| `-depth MODE` | `full` | `fast` skips hijack validation; `full` runs every check |
| `-domain NAME` | `google.com` | A-record integrity domain |
| `-txt-domain NAME` | `_dmarc.google.com` | TXT passthrough target |
| `-truth P` | `google` | Reference resolver: `google`, `cloudflare`, `quad9` |
| `-score N` | `0` | Minimum compatibility score |
| `-nearby` | off | Expand the `/24` around every hit and rescan |
| `-rate N` | `0` | Whole-scan query rate limit |
| `-rate-per-resolver N` | `0` | Per-resolver query rate limit |
| `-quiet` | off | Only print the final summary |

Accepted resolvers are those with `TunnelReady && Status == valid`: at least
one clean recursive transport with TXT passthrough, and no resolver-wide
NXDOMAIN hijack. For UDP, EDNS0 must also work.

### Why `-txt-domain` matters

The TXT target must actually have a TXT record. The engine's old default
(`google.com`) has none, so every resolver looks like it fails TXT passthrough.
`_dmarc.google.com` works out of the box. For a true end-to-end echo test,
point this at a zone you control.

## Client flags

| Flag | Default | Purpose |
|---|---|---|
| `-config FILE` | — | client JSON; required for manual/auto |
| `-resolvers FILE` | — | manual resolver list |
| `-mode MODE` | inferred | `manual`, `auto`, `scan` |
| `-scan` | off | shorthand for `-mode auto` |
| `-scan-only` | off | shorthand for `-mode scan` |
| `-listen ADDR` | from config | override the loopback SOCKS listener |
| `-discovery on\|off` | off in manual/auto | add bundled Soar discovery fallback |
| `-verify` | `auto` | `auto` = on for auto/scan, off for manual; or `on` / `off` |
| `-verify-workers N` | `2` | concurrent verification probes |
| `-max-resolvers N` | `128` | cap for the runtime list |
| `-version` | — | print versions |

The legacy form still works:

```bash
soar-client -config client.json -resolvers resolvers.txt
```

## systemd mode selection

The unit starts `/usr/local/bin/soar-client-run`, which sources
`/etc/soar-client/mode.env`. To switch modes, edit that file and restart:

```bash
# manual
SOAR_ARGS="-mode manual -resolvers /etc/soar-client/resolvers.txt"

# auto
SOAR_ARGS="-mode auto -candidates /etc/soar-client/candidates.txt -scan-out /var/lib/soar-client/scan -scan-list /var/lib/soar-client/resolvers-auto.txt -samples 5 -workers 64 -depth full -verify-workers 2"
```

```bash
systemctl restart soar-client
```

In auto mode the service scans on every start. That makes startup slower than
manual mode, but the resolver list is always measured on the host that will
actually run the tunnel. For a fast restart, run auto mode once, then switch
the service to the generated list with manual mode.

## Reports

`soar-client scan` writes timestamped files:

```
passed_clean_resolvers_*.txt   accepted resolver IPs
tunnel_ready_ips_*.txt         tunnel-ready shortlist
valid_dns_servers_*.txt        valid DNS servers
resolvers_*.csv                every resolver, one row each
resolvers_*.json               machine-readable full dump
resolvers_*.html               colour-coded table
resolvers_*.xlsx               spreadsheet with status colours
dns-results-*.txt              human-readable per-resolver details
```

The stable list is the `-out-list` / `-scan-list` file. It contains one IP per
line and is what manual mode and the service consume.

## Security notes

- The SOCKS listener **must** be loopback. `0.0.0.0` is rejected.
- Only TCP `CONNECT` is supported. `BIND` and `UDP ASSOCIATE` are rejected.
- The tunnel carries TCP only; do not route UDP/QUIC through it.
- The Soar server controls the destination allow-list (for example ports 80 and
  443). Change it in the panel, not in the client.
- The private key never leaves the server. The client only has the public key.
- `/etc/soar-client/client.json` is mode `0640` and owned by `root:soar-client`.
- Scan reports can reveal network topology; keep `/var/lib/soar-client` private.

## Troubleshooting

| Symptom | What to check |
|---|---|
| `no authenticated DNS tunnel` | zone/public key, NS delegation, server port 53, resolver reachability |
| `no resolver passed the scanner` | use `-depth full`, `-protocol both`, a longer `-samples`, or a different candidate file |
| Auto mode takes a long time | verification is intentionally strict; reduce the candidate set, use `-verify-workers 4`, or scan once and switch to manual |
| A resolver passes DNS but not Soar | expected: the final handshake gate is specific to your server key and zone |
| The proxy connects but sites fail | server `allow_ports`; the client only supports TCP CONNECT |
| Port 10886 is busy | stop the old `whitedns-soar` service or override `-listen` |
| DNS is hijacked on the client host | that is the problem Soar is designed to bypass; the tunnel uses the resolver path, not the host resolver |

## Build and test

```bash
go test ./...
./build.sh 1.0.0
```

The test suite covers the Soar config bounds, SOCKS negotiation, hostname
preservation, HTTPS certificate validation, resolver planning, CIDR expansion,
and candidate parsing. The scanner package is built from the upstream engine;
see `THIRD_PARTY.md` for provenance.

## Repository

The project is published at
[`alimc98/Soar-Client`](https://github.com/alimc98/Soar-Client). It was renamed
from `alimc98/whitedns-resolver-scan`; GitHub redirects the old URL, so old
clones keep working. If an existing clone still uses the old URL, update it:

```bash
git remote set-url origin https://github.com/alimc98/Soar-Client.git
```

Release tag: `soar-client-v1.0.0`.

## Credits

- Soar engine: [getlantern/soar](https://github.com/getlantern/soar) v0.2.3,
  Apache-2.0, with WhiteDNS transport fixes.
- Client source: [WhiteDNS/WhiteDNS-Desktop](https://github.com/WhiteDNS/WhiteDNS-Desktop)
  `Soar/` v1.6.7.
- Scanner engine: [WhiteDNS/WhiteDNS-cleanip-finder](https://github.com/WhiteDNS/WhiteDNS-cleanip-finder)
  `internal/dnsscan` at commit `55960618b924018bda3e883155702ed7312eff98`.
- Iranian resolver/range snapshots: KevinNet DNS, MIT.

See `THIRD_PARTY.md` for details.

---

## راهنمای سریع فارسی

این پروژه همان کلاینت Soar (از ریپوی `WhiteDNS-Desktop`) است که اسکنر ریزالور
هم داخل خودش قرار گرفته و اسمش از `whitedns-resolver-scan` به `Soar-Client`
تغییر کرده است.

حالت دستی:

```bash
soar-client run -config /etc/soar-client/client.json \
  -mode manual -resolvers /etc/soar-client/resolvers.txt
```

حالت خودکار (خودش اسکن می‌کند، ریزالور سالم را پیدا و تأیید می‌کند و بالا
می‌آید):

```bash
soar-client run -config /etc/soar-client/client.json \
  -mode auto -candidates /etc/soar-client/candidates.txt \
  -scan-out /var/lib/soar-client/scan \
  -scan-list /var/lib/soar-client/resolvers-auto.txt
```

فقط اسکن:

```bash
soar-client scan -candidates /etc/soar-client/candidates.txt \
  -out-list /var/lib/soar-client/resolvers-valid.txt
```

خروجی SOCKS روی `127.0.0.1:10886` است و فقط TCP `CONNECT` را پشتیبانی می‌کند.
برای سرویس systemd فایل `/etc/soar-client/mode.env` را ویرایش کنید و بعد
`systemctl restart soar-client` بزنید.
