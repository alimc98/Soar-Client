# WhiteDNS Resolver Scanner (headless)

A non-interactive DNS resolver scanner for the WhiteDNS Linux client, built on
the [WhiteDNS cleanip-finder](https://github.com/WhiteDNS/WhiteDNS-cleanip-finder)
engine.

The upstream project ships a terminal UI. A headless client on a Linux server
has no terminal, so this package adds a plain-flag command that runs the same
`internal/dnsscan` engine over SSH and writes the same report set.

## What it checks

A resolver is only accepted when every one of these holds:

| Check | Meaning |
|---|---|
| Clean A answer | The answer matches the truth table, so the resolver is not poisoned. |
| Recursion available | The `RA` bit is set, so it really resolves. |
| No NXDOMAIN hijack | Reserved names are not forged; the resolver is not a lying transparent proxy. |
| TXT passthrough | TXT rdata comes back intact, which is the channel a DNS tunnel rides on. |
| EDNS0 on the UDP path | Large UDP answers are not truncated, so the tunnel can carry payload. |

Rejected resolvers are still reported, with the reason, so a list can be tuned
instead of guessed at.

## Install

On the Ubuntu/Debian client server:

```bash
tar -xzf whitedns-resolver-scan-1.0.0-linux-amd64.tar.gz
cd whitedns-resolver-scan-1.0.0-linux-amd64
sudo bash install.sh
```

That installs:

- `/usr/local/bin/dnsscan` — the scanner
- `/etc/whitedns-scan/scan-resolvers.sh` — the wrapper script
- `/etc/whitedns-scan/resolver-candidates.txt` — the candidate list

## Run a scan

```bash
cd /etc/whitedns-scan
sudo ./scan-resolvers.sh --samples 5 --workers 64
```

The candidate list holds CIDR ranges, so the scanner samples addresses inside
each range instead of probing every address. `--samples 5` means five probes
per range, spread evenly over its usable host addresses.

Output:

```
/etc/whitedns-scan/resolvers-valid.txt   accepted resolver IPs, one per line
/etc/whitedns-scan/dns-scan/              full report set (txt, csv, json, html, xlsx)
```

Exit code is `0` when at least one resolver was accepted, `1` when none was.

## Give the result to the client

The bridge reads its resolvers from the profile or from `WHITEDNS_RESOLVERS`:

```bash
sudo systemctl edit whitedns-bridge
# [Service]
# Environment=WHITEDNS_RESOLVERS=194.29.79.5,185.235.198.1
sudo systemctl restart whitedns-bridge
```

To install the scan result as the default set:

```bash
sudo sh -c 'echo "WHITEDNS_RESOLVERS=$(tr "\n" "," < /etc/whitedns-scan/resolvers-valid.txt)" \
  >> /etc/whitedns-bridge/bridge.env'
sudo systemctl restart whitedns-bridge
```

The client also runs its own discovery: when `discovery` is on in the profile,
it tries the bundled `ir.txt` and `global.txt` lists and samples the bundled
Iranian ranges. The scanner is the tool for replacing that guesswork with a
list measured on the host that will actually run the tunnel.

## Direct use

```bash
dnsscan -list candidates.txt -out reports -samples 5 -protocol both -depth full
```

| Flag | Default | Purpose |
|---|---|---|
| `-list` | — | File of resolver IPs and/or CIDR ranges |
| `-out` | `dns-scan` | Report directory |
| `-out-list` | — | Extra file for the accepted IPs |
| `-samples` | `0` | Addresses per CIDR range (`0` = every address) |
| `-protocol` | `udp` | `udp`, `tcp`, `both`, `all` |
| `-ports` | `53` | Ports to probe |
| `-workers` | `64` | Concurrent probes |
| `-timeout` | `3s` | Per-probe timeout |
| `-depth` | `fast` | `fast` (skips hijack validation) or `full` |
| `-domain` | `google.com` | A-record integrity domain |
| `-txt-domain` | `_dmarc.google.com` | TXT probe target |
| `-truth` | `google` | Reference resolver: `google`, `cloudflare`, `quad9` |
| `-score` | `0` | Minimum compatibility score to keep |
| `-nearby` | off | Expand the `/24` around every hit and rescan it |
| `-rate` | `0` | Whole-scan query rate limit |
| `-rate-per-resolver` | `0` | Per-resolver query rate limit |
| `-quiet` | off | Only print the summary |

### `-txt-domain` matters

The TXT probe target must be a name that actually carries a TXT record. The
engine's default (`google.com`) has none, so every resolver comes back as
`no-txt-passthrough` and nothing is accepted. `_dmarc.google.com` works out of
the box; for a true end-to-end echo test, point it at a zone you control.

## Build from source

The scanner command is `cmd/dnsscanheadless/main.go` in this repo. It imports
the upstream module's internal `dnsscan` package, so it has to be compiled
inside the upstream tree. `build.sh` does that:

```bash
bash build.sh 1.0.0
```

It clones cleanip-finder at a pinned commit, copies the command into
`cmd/dnsscanheadless/`, and cross-compiles `dnsscan-linux-amd64` and
`dnsscan-linux-arm64`. Then:

```bash
bash package.sh 1.0.0
```

## Layout

```
cmd/dnsscanheadless/main.go   the headless scanner command
build.sh                       clone upstream, add the command, compile
package.sh                     build the release tarballs
install.sh                     install on Ubuntu/Debian
scan-resolvers.sh              wrapper around the scanner
resolver-candidates.txt        candidate CIDR ranges
```

## Credits

The scanner engine, the acceptance rule, and the report formats come from
[WhiteDNS/WhiteDNS-cleanip-finder](https://github.com/WhiteDNS/WhiteDNS-cleanip-finder),
used as an upstream dependency and not copied into this repository.

`resolver-candidates.txt` is the Iranian range set shipped with the WhiteDNS
Soar engine, itself credited to KevinNet DNS (MIT).
