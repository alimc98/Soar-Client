// Command dnsscanheadless is a non-interactive DNS resolver scanner.
//
// The TUI in cmd/whitedns needs a terminal, which a headless Linux client
// (the Soar bridge on the Iran-side server) does not have. This command runs
// the same internal/dnsscan engine with plain flags and writes the same
// report set, so a resolver list can be produced on a server over SSH.
//
// Typical use: read a CIDR list, sample addresses per range, scan them for
// resolvers that actually carry a tunnel, and emit the surviving IPs.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"whitedns-go/internal/dnsscan"
)

// defaultTxtDomain is the TXT passthrough probe target. It must be a name that
// actually carries a TXT record: the engine's acceptance rule requires a
// resolver to forward TXT rdata intact, so probing a name without TXT records
// (google.com itself, for example) marks every resolver as not tunnel-ready.
// Point -txt-domain at a zone you control for a true end-to-end echo test.
const defaultTxtDomain = "_dmarc.google.com"

func main() {
	var (
		listPath   = flag.String("list", "", "file with resolver IPs and/or CIDR ranges (one per line)")
		outDir     = flag.String("out", "dns-scan", "directory for scan reports")
		samples    = flag.Int("samples", 0, "addresses to sample per CIDR range (0 = every address)")
		protocol   = flag.String("protocol", "udp", "probe transports: udp | tcp | both | all")
		ports      = flag.String("ports", "53", "comma separated ports to probe")
		workers    = flag.Int("workers", 64, "resolver worker pool size")
		timeout    = flag.Duration("timeout", 3*time.Second, "per-probe timeout")
		depth      = flag.String("depth", "fast", "scan depth: fast | full")
		domain     = flag.String("domain", "google.com", "A-record integrity domain")
		txtDomain  = flag.String("txt-domain", defaultTxtDomain, "TXT passthrough domain (must exist with a TXT record)")
		truth      = flag.String("truth", "google", "reference resolver: google | cloudflare | quad9")
		threshold  = flag.Int("score", 0, "minimum compatibility score to keep (0 = keep all)")
		nearby     = flag.Bool("nearby", false, "expand the /24 around every tunnel-ready hit and rescan it")
		rate       = flag.Float64("rate", 0, "whole-scan query rate limit (0 = unlimited)")
		ratePerRes = flag.Float64("rate-per-resolver", 0, "per-resolver query rate limit (0 = unlimited)")
		outList    = flag.String("out-list", "", "extra file to write the accepted resolver IPs to")
		quiet      = flag.Bool("quiet", false, "only print the final summary")
	)
	flag.Parse()

	if strings.TrimSpace(*listPath) == "" {
		fmt.Fprintln(os.Stderr, "error: -list is required")
		flag.Usage()
		os.Exit(2)
	}

	ips, err := expandTargets(*listPath, *samples)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if len(ips) == 0 {
		fmt.Fprintln(os.Stderr, "error: no addresses to scan")
		os.Exit(1)
	}
	if !*quiet {
		fmt.Printf("Scanning %d resolver addresses (protocol=%s workers=%d depth=%s)\n", len(ips), *protocol, *workers, *depth)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opts := dnsscan.Options{
		TargetDomain:                  *domain,
		TxtDomain:                     *txtDomain,
		Timeout:                       *timeout,
		Ports:                         parsePorts(*ports),
		Protocol:                      *protocol,
		Concurrency:                   *workers,
		TruthProvider:                 *truth,
		ScanDepth:                     *depth,
		ScoreThreshold:                *threshold,
		TestNearby:                    *nearby,
		RateLimitPerSecond:            *rate,
		RateLimitPerResolverPerSecond: *ratePerRes,
	}

	started := time.Now()
	lastPrint := time.Now()
	results := dnsscan.ScanResolvers(ctx, ips, opts, func(done, total int, r dnsscan.ResolverResult) {
		if *quiet {
			return
		}
		if time.Since(lastPrint) < 2*time.Second && done != total {
			return
		}
		lastPrint = time.Now()
		fmt.Printf("  %d/%d  %-16s %-7s score=%d %s\n", done, total, r.IP, r.Status, r.Score, r.TunnelReason)
	})

	elapsed := time.Since(started)
	paths, err := dnsscan.WriteReports(*outDir, results)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: writing reports: %v\n", err)
		os.Exit(1)
	}

	accepted := make([]string, 0, len(results))
	for _, r := range dnsscan.SortResults(results) {
		if r.Passed() {
			accepted = append(accepted, r.IP)
		}
	}
	if *outList != "" {
		if err := writeLines(*outList, accepted); err != nil {
			fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", *outList, err)
			os.Exit(1)
		}
	}

	fmt.Printf("\nScanned %d addresses in %s\n", len(results), elapsed.Round(time.Second))
	fmt.Printf("Accepted (tunnel-ready, clean): %d\n", len(accepted))
	fmt.Printf("Valid:   %d\n", countStatus(results, dnsscan.StatusValid))
	fmt.Printf("Poison:  %d\n", countStatus(results, dnsscan.StatusPoison))
	fmt.Printf("Hijack:  %d\n", countStatus(results, dnsscan.StatusHijack))
	fmt.Printf("Invalid: %d\n", countStatus(results, dnsscan.StatusInvalid))
	fmt.Printf("\nReports in %s\n", paths.Dir)
	fmt.Printf("  passed list:   %s\n", paths.Passed)
	fmt.Printf("  tunnel ready:  %s\n", paths.TunnelReadyIPs)
	fmt.Printf("  valid servers: %s\n", paths.Valid)
	fmt.Printf("  csv:           %s\n", paths.CSV)
	fmt.Printf("  json:          %s\n", paths.JSON)
	if *outList != "" {
		fmt.Printf("  out-list:      %s\n", *outList)
	}
}

func countStatus(results []dnsscan.ResolverResult, status string) int {
	n := 0
	for _, r := range results {
		if r.Status == status {
			n++
		}
	}
	return n
}

func writeLines(path string, lines []string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func parsePorts(raw string) []int {
	fields := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	out := make([]int, 0, len(fields))
	for _, f := range fields {
		if p, err := strconv.Atoi(f); err == nil && p > 0 && p <= 65535 {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []int{53}
	}
	sort.Ints(out)
	return out
}

// expandTargets reads a list of resolver IPs and CIDR ranges and returns the
// addresses to probe. Ranges are sampled at evenly spaced offsets so a large
// /14 contributes a handful of probes instead of a quarter-million.
func expandTargets(path string, samples int) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	out := []string{}
	add := func(ip string) {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			return
		}
		if _, dup := seen[ip]; dup {
			return
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		for _, token := range strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t'
		}) {
			token = strings.Trim(strings.TrimSpace(token), `"'`)
			if token == "" {
				continue
			}
			if strings.Contains(token, "/") {
				expanded, err := expandCIDR(token, samples)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", token, err)
					continue
				}
				for _, ip := range expanded {
					add(ip)
				}
				continue
			}
			add(token)
		}
	}
	return out, nil
}

// expandCIDR returns the addresses to probe for one range. With samples <= 0
// every address is probed; otherwise probes are spaced evenly over the usable
// host addresses, skipping the network and broadcast addresses so a probe
// never lands on an address that cannot answer.
func expandCIDR(cidr string, samples int) ([]string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}
	prefix = prefix.Masked()
	addr := prefix.Addr()
	bits := prefix.Bits()

	first := addr
	if bits < addr.BitLen()-1 {
		first = first.Next() // skip the network address
	}
	last := addr
	for i := bits; i < addr.BitLen(); i++ {
		last = last.Next()
	}
	if bits < addr.BitLen()-1 {
		last = last.Prev() // skip the broadcast address
	}

	usable := uint64(1)
	for cur := first; cur != last && cur.IsValid(); cur = cur.Next() {
		usable++
	}
	if usable == 0 {
		return nil, fmt.Errorf("range has no usable host addresses")
	}

	if samples <= 0 {
		out := make([]string, 0, usable)
		for a := prefix.Addr(); prefix.Contains(a); a = a.Next() {
			out = append(out, a.Unmap().String())
		}
		return out, nil
	}

	n := uint64(samples)
	if n > usable {
		n = usable
	}
	step := usable / n
	if step == 0 {
		step = 1
	}
	out := make([]string, 0, n)
	cur := first
	for i := uint64(0); i < n; i++ {
		out = append(out, cur.Unmap().String())
		for j := uint64(0); j < step && cur != last; j++ {
			cur = cur.Next()
		}
	}
	return out, nil
}
