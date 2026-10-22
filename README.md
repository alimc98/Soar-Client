# Soar Client

A Linux client for the WhiteDNS Soar DNS tunnel, built from the `Soar/` engine
in [WhiteDNS/WhiteDNS-Desktop](https://github.com/WhiteDNS/WhiteDNS-Desktop),
with the WhiteDNS resolver scanner integrated into the same binary.

The client exposes a **SOCKS5 `CONNECT`** proxy. It listens on loopback by
default; a public listener such as `0.0.0.0:10886` is allowed only when SOCKS5
username/password authentication is configured. TCP traffic sent to the proxy
travels through an authenticated DNS tunnel to the Soar server. A resolver can
be supplied manually, or the client can scan candidate IPs/CIDRs, keep the
resolvers that actually carry a tunnel, and start with that list.

> This project was renamed from `whitedns-resolver-scan` to `Soar-Client`.
> The old repository only contained the standalone scanner; this repository is
> the combined client + scanner.

> **Status:** client `1.2.0` adds listener/credential environment overrides and
> a per-instance systemd template for multiple SOCKS endpoints. The tunnel and
> scanner paths were validated on 2026-10-22 on AlmaLinux 8.10 against a live
> Soar `0.5.0` server; manual and auto modes authenticated and carried real
> HTTPS traffic through the tunnel.

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
./build.sh 1.2.0
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
tar -xzf soar-client-1.2.0-linux-amd64.tar.gz
cd soar-client-1.2.0-linux-amd64
sudo bash install.sh
```

The installer creates:

| Path | Purpose |
|---|---|
| `/usr/local/bin/soar-client` | client + scanner binary |
| `/usr/local/bin/soar-client-run` | reads `/etc/soar-client/mode.env` and starts the client |
| `/usr/local/bin/soar-client-instance` | wrapper for `soar-client@.service` instances |
| `/etc/soar-client/client.json` | Soar zone, public key, listen address, advanced options |
| `/etc/soar-client/resolvers.txt` | manual resolver list |
| `/etc/soar-client/candidates.txt` | bundled Iranian CIDR list for auto mode |
| `/etc/soar-client/mode.env` | selects manual or auto mode for the main service |
| `/etc/soar-client/instances/` | one `NAME.env` file per extra instance |
| `/etc/systemd/system/soar-client.service` | main systemd unit |
| `/etc/systemd/system/soar-client@.service` | per-instance systemd template |
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

To expose it to other hosts, set `listen` to `0.0.0.0:10886` (or a specific
interface IP) and set non-empty `username` and `password` in
`/etc/soar-client/client.json`:

```json
{
  "listen": "0.0.0.0:10886",
  "username": "soar",
  "password": "use-a-long-random-password"
}
```

A non-loopback listener without authentication is rejected. Restart the
service after changing the file:

```bash
systemctl restart soar-client
```

SOCKS5 username/password is not encrypted on the client-to-listener hop. If the
port is reachable over an untrusted network, restrict it with a firewall
allow-list, a VPN, or an SSH tunnel.

### 3. Change the SOCKS port, username, or password

The values in `client.json` are defaults. You can override the listener and
credentials without duplicating the tunnel configuration. Precedence is:

```
client.json  <  SOAR_* environment  <  command-line flags
```

| Override | Environment | Flag |
|---|---|---|
| Listen address | `SOAR_LISTEN` | `-listen` |
| SOCKS username | `SOAR_USERNAME` | `-username` |
| SOCKS password | `SOAR_PASSWORD` | `-password` |

Example with environment variables:

```bash
SOAR_LISTEN=0.0.0.0:10887 \
SOAR_USERNAME=soar2 \
SOAR_PASSWORD='use-a-long-random-password' \
soar-client run -config /etc/soar-client/client.json \
  -mode manual -resolvers /etc/soar-client/resolvers.txt
```

For the main systemd service, put the same assignments in
`/etc/soar-client/mode.env`, then restart:

```bash
# /etc/soar-client/mode.env
SOAR_LISTEN=0.0.0.0:10887
SOAR_USERNAME=soar2
SOAR_PASSWORD=use-a-long-random-password
```

```bash
systemctl restart soar-client
```

The flag form is convenient for a one-off test:

```bash
soar-client run -config /etc/soar-client/client.json \
  -mode manual -resolvers /etc/soar-client/resolvers.txt \
  -listen 0.0.0.0:10887 -username soar2 -password 'use-a-long-random-password'
```

> `-password` and `-username` appear in the process list. Prefer the config file
> or `SOAR_*` environment variables for a long-running service. Setting
> `SOAR_USERNAME=` and `SOAR_PASSWORD=` to empty clears the credentials; a
> non-loopback listener will then be rejected by validation.

### 4. Run multiple SOCKS endpoints

A single client process has **one DNS tunnel and one listener**. Starting five
processes gives five independent tunnels. Five ports on one process would share
one tunnel and would not add bandwidth. For five independent tunnels, run five
processes (or five systemd instances), each with its own listener and tunnel
session.

The release includes `soar-client@.service`, a systemd template that reads
`/etc/soar-client/instances/%i.env` and starts
`/usr/local/bin/soar-client-instance`.

Example: five instances on `127.0.0.1:10886`–`10890` (replace the main service,
or use `10887`–`10891` alongside it):

```bash
sudo install -d -m 0750 -o root -g soar-client /etc/soar-client/instances

for i in 1 2 3 4 5; do
  sudo cp /etc/soar-client/instances/example.env \
    "/etc/soar-client/instances/$i.env"
  sudo chmod 600 "/etc/soar-client/instances/$i.env"
done
```

Edit each file. A minimal `1.env`:

```bash
SOAR_LISTEN=127.0.0.1:10886
SOAR_USERNAME=soar1
SOAR_PASSWORD=replace-with-a-long-random-password

# Optional: a different resolver path for this tunnel.
SOAR_ARGS="-mode manual -resolvers /etc/soar-client/instances/1.resolvers"
```

Then enable the instances:

```bash
sudo systemctl enable --now soar-client@{1..5}
systemctl status 'soar-client@*' --no-pager
ss -ltnp | grep -E ':1088[6-9]|:10890'
```

If you already run `soar-client.service` on `10886`, disable it first or start
the instances on different ports:

```bash
sudo systemctl disable --now soar-client
```

If the bonding core runs on another machine, do **not** expose five
unauthenticated public ports. Use a WireGuard/SSH tunnel, or bind to loopback
and forward securely. If a public bind is unavoidable, use a distinct strong
password per instance and restrict the ports with a firewall.

#### Does running five clients make one connection faster?

| Goal | Result |
|---|---|
| More total throughput for many parallel connections | Yes, if the core distributes new TCP connections across healthy tunnels |
| Faster single TCP download / single HTTP stream | No, not with only SOCKS endpoints; that stream stays on one tunnel |
| Survive one tunnel or resolver path failing | Yes, with health checks and failover in the core |
| Aggregate a single stream across all five tunnels | Only with MPTCP or an application-level split plus a remote reassembly agent |

Each process is a separate Soar session with its own `maxStreams` and
`maxInflight` limits. However, if all five use the **same zone/public key**
(one panel account), the account's quota and rate limits, and any panel-side
aggregate stream cap, apply to the account as a whole; five processes cannot
create capacity the account does not have. Different accounts and, more
importantly, different resolver paths give the aggregation something real to
use. If all five use the same six resolvers, they contend for the same DNS
path.

For a bonding core:

- Balance **new TCP connections** (round-robin or least-connections), not
  individual packets of one TCP connection. Packet-level round-robin over five
  SOCKS tunnels causes reordering and will collapse TCP throughput.
- A browser may multiplex many HTTP/2 requests over one TCP connection; that
  connection is still pinned to one tunnel. Per-flow balancing helps page loads
  only when the client opens multiple connections.
- For a single large download, use multiple HTTP range connections (if the
  server supports ranges) or a transport with real multipath support. A
  transparent single-stream bond requires a remote agent that terminates the
  stream, splits it, and reassembles it; five ordinary SOCKS proxies are not
  enough.
- Use `manual` mode for the five instances. Running `auto` five times scans the
  same candidate ranges five times and increases DNS load and startup time.

### 5. Manual mode

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

### 6. Auto mode

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

### 7. Scan only

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
| `-listen ADDR` | from config | override the SOCKS listener (public binds need auth) |
| `-username USER` | from config | override the SOCKS username (visible in `ps`) |
| `-password PASS` | from config | override the SOCKS password (visible in `ps`) |
| `-discovery on\|off` | off in manual/auto | add bundled Soar discovery fallback |
| `-verify` | `auto` | `auto` = on for auto/scan, off for manual; or `on` / `off` |
| `-verify-workers N` | `2` | concurrent verification probes |
| `-max-resolvers N` | `128` | cap for the runtime list |
| `-version` | — | print versions |

The legacy form still works:

```bash
soar-client -config client.json -resolvers resolvers.txt
```

## Soar vs CottenDNS

The panel can show two share profiles for the same panel account: **Soar** and
**CottenDNS**. They are separate tunnel engines, not two modes of this binary:

| Profile | Engine | Client |
|---|---|---|
| Soar | `getlantern/soar` with WhiteDNS transport fixes | this `soar-client` binary |
| CottenDNS | `cottendns-go` | the official CottenDNS client |

This binary is Soar-only. It imports `github.com/getlantern/soar`, reads
`zone`, `server_public_key`, and the `soar` options, and has no CottenDNS code.
A CottenDNS profile cannot be loaded with `-config`, and there is no
`-engine cotten` switch in `1.2.0`.

If the panel account is set to **Soar + Cotten**, both profiles are valid on
the server. To use CottenDNS from Iran, run the official
[CottenDNS client](https://github.com/WhiteDNS/CottenDNS) on a separate SOCKS
port and give the bonding core both endpoints; the server side is already
provisioned. The official client has its own TOML configuration, domains, and
encryption key, so its profile is not interchangeable with the Soar
`client.json`.

Adding a native CottenDNS mode to this binary would mean vendoring or embedding
the CottenDNS engine and merging its configuration/listener model. That is a
separate engine integration, not a configuration toggle; it is not part of
`1.2.0`.

## systemd mode selection

The unit starts `/usr/local/bin/soar-client-run`, which sources
`/etc/soar-client/mode.env` and exports its variables. To switch modes or
override the listener/credentials, edit that file and restart:

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

- The SOCKS listener is loopback by default. A non-loopback bind (for example
  `0.0.0.0:10886`) is accepted only when `username` and `password` are set in
  `client.json`; unauthenticated public listeners are rejected.
- SOCKS5 username/password is not encrypted on the client-to-listener hop. Use
  a firewall allow-list, a VPN, or an SSH tunnel when the listener is reachable
  over an untrusted network. Do not expose it to the whole Internet without
  additional protection.
- Only TCP `CONNECT` is supported. `BIND` and `UDP ASSOCIATE` are rejected.
- The tunnel carries TCP only; do not route UDP/QUIC through it.
- The Soar server controls the destination allow-list (for example ports 80 and
  443). Change it in the panel, not in the client.
- The private key never leaves the server. The client only has the public key.
- `/etc/soar-client/client.json` is mode `0640` and owned by `root:soar-client`.
- Per-instance files under `/etc/soar-client/instances/` contain passwords; use
  mode `0600` and `root:root` ownership. The systemd template reads them as
  root, so the service user does not need read access.
- Environment overrides (`SOAR_PASSWORD`, etc.) are safer than command-line
  flags, but any user who can read the service environment or the env file can
  read the password. Restrict both.
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
./build.sh 1.2.0
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

Release tag: `soar-client-v1.2.0`.

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

خروجی SOCKS به‌صورت پیش‌فرض روی `127.0.0.1:10886` است و فقط TCP `CONNECT` را
پشتیبانی می‌کند. برای دسترسی از بیرون، در `/etc/soar-client/client.json` مقدار
`listen` را مثلاً `0.0.0.0:10886` بگذارید و حتماً `username` و `password` را
تنظیم کنید؛ bind روی آدرس non-loopback بدون احراز هویت رد می‌شود. پورت را در
فایروال فقط برای منابع مجاز باز کنید. بعد از تغییر، سرویس را restart کنید:

```bash
systemctl restart soar-client
```

برای انتخاب حالت manual/auto، فایل `/etc/soar-client/mode.env` را ویرایش کنید.

### تغییر پورت، یوزر و پسورد

مقادیر داخل `client.json` پیش‌فرض هستند و می‌توان بدون دست‌زدن به بقیهٔ کانفیگ
آن‌ها را override کرد. اولویت این است:

```
client.json  <  متغیرهای SOAR_*  <  فلگ‌های خط فرمان
```

```bash
SOAR_LISTEN=0.0.0.0:10887 \
SOAR_USERNAME=soar2 \
SOAR_PASSWORD='یک-رمز-تصادفی-طولانی' \
soar-client run -config /etc/soar-client/client.json \
  -mode manual -resolvers /etc/soar-client/resolvers.txt
```

برای سرویس اصلی، همین سه متغیر را در `/etc/soar-client/mode.env` بگذارید و
`systemctl restart soar-client` بزنید. فلگ‌های `-listen`، `-username` و
`-password` هم هستند، ولی پسورد در `ps` دیده می‌شود؛ برای سرویس دائمی از
فایل یا env استفاده کنید. با خالی‌کردن `SOAR_USERNAME` و `SOAR_PASSWORD`
احراز هویت پاک می‌شود و یک listener عمومی دیگر معتبر نیست.

### چند کلاینت و پنج پورت SOCKS

هر پروسه فقط **یک تونل** دارد. پنج پورت روی یک پروسه، پنج تونل جدا نمی‌سازد و
bandwidth را جمع نمی‌کند. برای پنج تونل مستقل، پنج instance بسازید:

```bash
sudo install -d -m 0750 -o root -g soar-client /etc/soar-client/instances
for i in 1 2 3 4 5; do
  sudo cp /etc/soar-client/instances/example.env \
    "/etc/soar-client/instances/$i.env"
  sudo chmod 600 "/etc/soar-client/instances/$i.env"
done
```

در هر فایل، پورت و یوزر/پس مخصوص همان instance را بگذارید:

```bash
SOAR_LISTEN=127.0.0.1:10886
SOAR_USERNAME=soar1
SOAR_PASSWORD=یک-رمز-تصادفی-طولانی
SOAR_ARGS="-mode manual -resolvers /etc/soar-client/instances/1.resolvers"
```

بعد:

```bash
sudo systemctl enable --now soar-client@{1..5}
systemctl status 'soar-client@*' --no-pager
```

اگر سرویس اصلی روی `10886` فعال است، یا اول آن را غیرفعال کنید یا پورت
instanceها را از `10887` شروع کنید. اگر bonding core روی همان سرور است،
listenerها را روی `127.0.0.1` بگذارید؛ اگر از بیرون استفاده می‌شود،
WireGuard/SSH tunnel بهتر از بازکردن پنج پورت عمومی است.

### آیا پنج کلاینت سرعت یک کانکشن را زیاد می‌کند؟

- برای **چند کانکشن موازی**، اگر core اتصال‌های جدید TCP را بین تونل‌های سالم
  پخش کند، مجموع throughput می‌تواند بیشتر شود.
- برای **یک دانلود/یک استریم TCP**، آن استریم روی یک تونل می‌ماند و پنج کلاینت
  سرعتش را پنج برابر نمی‌کنند. برای یک استریم باید از MPTCP یا تقسیم
  application-level به‌همراه agent مقصد استفاده شود؛ round-robin کردن packet
  روی چند SOCKS باعث reordering و خرابی TCP می‌شود.
- اگر هر پنج کلاینت همان `zone` و `public key` (یک اکانت پنل) را استفاده کنند،
  سهمیه/نرخ و هر سقف aggregate سمت پنل مشترک است. برای aggregation واقعی،
  اکانت‌های جدا و مهم‌تر از آن resolver pathهای متفاوت بدهید. پنج کلاینت با همان
  شش resolver، سر یک مسیر DNS با هم رقابت می‌کنند.
- برای پنج instance از حالت `manual` استفاده کنید؛ `auto` پنج بار اسکن می‌کند و
  بار DNS و زمان startup را زیاد می‌کند.

### Soar یا CottenDNS؟

اکانت پنل می‌تواند هم پروفایل Soar و هم CottenDNS بدهد؛ این دو موتور جدا هستند،
نه دو حالت همین باینری. کلاینت فعلی فقط Soar را می‌فهمد (`getlantern/soar`،
`zone`/`server_public_key`/`soar`). پروفایل CottenDNS با `-config` این برنامه
کار نمی‌کند و در `1.2.0` سوییچ `-engine cotten` وجود ندارد.

اگر اکانت پنل روی «Soar + Cotten» است، سمت سرور هر دو آماده است. برای استفاده از
CottenDNS در ایران، کلاینت رسمی CottenDNS را روی یک پورت SOCKS دیگر اجرا کنید و
هر دو پورت را به bonding core بدهید. CottenDNS کانفیگ TOML، domainها و
encryption key جداگانه دارد. اضافه‌کردن حالت Cotten به این باینری یعنی embed
کردن موتور `cottendns-go` و ادغام مدل کانفیگ/لیسنر آن؛ یک پروژهٔ جدا است، نه
یک فلگ ساده.
