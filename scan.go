package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alimc98/soar-client/internal/dnsscan"
	"github.com/getlantern/soar"
)

type scanConfig struct {
	listPath        string
	outDir          string
	outList         string
	samples         int
	protocol        string
	ports           string
	workers         int
	timeout         time.Duration
	depth           string
	domain          string
	txtDomain       string
	truth           string
	score           int
	nearby          bool
	rate            float64
	ratePerResolver float64
	quiet           bool
}

func addScanFlags(fs *flag.FlagSet, c *scanConfig) {
	*c = scanConfig{
		outDir:    "dns-scan",
		outList:   "resolvers-valid.txt",
		samples:   5,
		protocol:  "both",
		ports:     "53",
		workers:   64,
		timeout:   3 * time.Second,
		depth:     "full",
		domain:    "google.com",
		txtDomain: "_dmarc.google.com",
		truth:     "google",
	}
	fs.StringVar(&c.listPath, "candidates", "", "file with resolver IPs and/or CIDR ranges")
	fs.StringVar(&c.listPath, "list", "", "alias for -candidates")
	fs.StringVar(&c.outDir, "scan-out", c.outDir, "directory for scan reports")
	fs.StringVar(&c.outDir, "out", c.outDir, "alias for -scan-out")
	fs.StringVar(&c.outList, "scan-list", c.outList, "accepted resolver list")
	fs.StringVar(&c.outList, "out-list", c.outList, "alias for -scan-list")
	fs.IntVar(&c.samples, "samples", c.samples, "addresses to sample per CIDR range (0 = every address)")
	fs.StringVar(&c.protocol, "protocol", c.protocol, "probe transports: udp | tcp | both | all")
	fs.StringVar(&c.ports, "ports", c.ports, "comma separated ports to probe")
	fs.IntVar(&c.workers, "workers", c.workers, "resolver worker pool size")
	fs.DurationVar(&c.timeout, "scan-timeout", c.timeout, "per-probe timeout")
	fs.DurationVar(&c.timeout, "timeout", c.timeout, "alias for -scan-timeout")
	fs.StringVar(&c.depth, "depth", c.depth, "scan depth: fast | full")
	fs.StringVar(&c.domain, "domain", c.domain, "A-record integrity domain")
	fs.StringVar(&c.txtDomain, "txt-domain", c.txtDomain, "TXT passthrough domain (must exist with a TXT record)")
	fs.StringVar(&c.truth, "truth", c.truth, "reference resolver: google | cloudflare | quad9")
	fs.IntVar(&c.score, "score", c.score, "minimum compatibility score to keep (0 = keep all)")
	fs.BoolVar(&c.nearby, "nearby", c.nearby, "expand the /24 around every tunnel-ready hit and rescan it")
	fs.Float64Var(&c.rate, "rate", c.rate, "whole-scan query rate limit (0 = unlimited)")
	fs.Float64Var(&c.ratePerResolver, "rate-per-resolver", c.ratePerResolver, "per-resolver query rate limit (0 = unlimited)")
	fs.BoolVar(&c.quiet, "quiet", c.quiet, "only print the final summary")
}

func runScanCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("soar-client scan", flag.ContinueOnError)
	var sc scanConfig
	addScanFlags(fs, &sc)
	configFile := fs.String("config", "", "optional client config for -verify")
	verify := fs.Bool("verify", false, "verify accepted resolvers with a real Soar handshake")
	verifyWorkers := fs.Int("verify-workers", 2, "concurrent Soar verification probes")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if sc.listPath == "" {
		sc.listPath = "embedded"
	}
	accepted, err := runScan(ctx, sc)
	if err != nil {
		return err
	}
	if !*verify {
		return nil
	}
	if *configFile == "" {
		return errors.New("-verify needs -config so the Soar handshake can be authenticated")
	}
	cfg, err := loadConfig(*configFile)
	if err != nil {
		return err
	}
	verified, err := verifyResolvers(ctx, cfg, accepted, *verifyWorkers)
	if err != nil {
		return err
	}
	if len(verified) == 0 {
		return errors.New("no scanner-accepted resolver passed the Soar handshake")
	}
	if sc.outList != "" {
		if err := writeLines(sc.outList, stripPorts(verified)); err != nil {
			return err
		}
	}
	return nil
}

func runScan(ctx context.Context, sc scanConfig) ([]string, error) {
	ips, err := expandTargets(sc.listPath, sc.samples)
	if err != nil {
		return nil, fmt.Errorf("candidate list: %w", err)
	}
	if len(ips) == 0 {
		return nil, errors.New("no addresses to scan")
	}
	if !sc.quiet {
		fmt.Printf("SCAN_START addresses=%d list=%s protocol=%s workers=%d depth=%s samples=%d\n",
			len(ips), sc.listPath, sc.protocol, sc.workers, sc.depth, sc.samples)
	}
	opts := dnsscan.Options{
		TargetDomain:                  sc.domain,
		TxtDomain:                     sc.txtDomain,
		Timeout:                       sc.timeout,
		Ports:                         parsePorts(sc.ports),
		Protocol:                      sc.protocol,
		Concurrency:                   sc.workers,
		TruthProvider:                 sc.truth,
		ScanDepth:                     sc.depth,
		ScoreThreshold:                sc.score,
		TestNearby:                    sc.nearby,
		RateLimitPerSecond:            sc.rate,
		RateLimitPerResolverPerSecond: sc.ratePerResolver,
	}
	started := time.Now()
	var lastPrint time.Time
	results := dnsscan.ScanResolvers(ctx, ips, opts, func(done, total int, r dnsscan.ResolverResult) {
		if sc.quiet {
			return
		}
		if time.Since(lastPrint) < 2*time.Second && done != total {
			return
		}
		lastPrint = time.Now()
		fmt.Printf("SCAN_PROGRESS done=%d total=%d ip=%s status=%s score=%d tunnel=%t reason=%q\n",
			done, total, r.IP, r.Status, r.Score, r.TunnelReady, r.TunnelReason)
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	elapsed := time.Since(started)
	paths, err := dnsscan.WriteReports(sc.outDir, results)
	if err != nil {
		return nil, fmt.Errorf("writing scan reports: %w", err)
	}

	accepted := make([]string, 0, len(results))
	for _, r := range dnsscan.SortResults(results) {
		if r.Passed() && r.Score >= sc.score {
			accepted = append(accepted, r.IP)
		}
	}
	if sc.outList != "" {
		if err := writeLines(sc.outList, accepted); err != nil {
			return nil, err
		}
	}

	fmt.Printf("SCAN_DONE scanned=%d accepted=%d elapsed=%s\n", len(results), len(accepted), elapsed.Round(time.Second))
	fmt.Printf("SCAN_STATUS valid=%d poison=%d hijack=%d invalid=%d\n",
		countStatus(results, dnsscan.StatusValid),
		countStatus(results, dnsscan.StatusPoison),
		countStatus(results, dnsscan.StatusHijack),
		countStatus(results, dnsscan.StatusInvalid))
	fmt.Printf("SCAN_REPORTS dir=%s passed=%s tunnel_ready=%s csv=%s json=%s\n",
		paths.Dir, paths.Passed, paths.TunnelReadyIPs, paths.CSV, paths.JSON)
	if sc.outList != "" {
		fmt.Printf("SCAN_LIST path=%s count=%d\n", sc.outList, len(accepted))
	}
	if len(accepted) == 0 {
		return nil, errors.New("no resolver passed the scanner")
	}
	return accepted, nil
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

// probeResolver authenticates the Soar server through exactly one resolver and
// verifies real HTTPS. It is the final gate after the generic DNS checks: a
// resolver can pass those checks and still fail this tunnel's key/zone.
func probeResolver(ctx context.Context, cfg config, resolver string, roots *x509.CertPool) bool {
	cfg.Soar.Discovery = false // Another resolver must never validate this candidate.
	client, err := soar.NewClient(cfg.clientConfig([]string{resolver}))
	if err != nil {
		return false
	}
	defer client.Close()
	if startupHTTPS(ctx, client.DialContext, roots) != nil {
		return false
	}
	// A transparent local DNS forwarder can answer even when the candidate IP
	// itself is unreachable, so let the path statistics settle and reject a
	// mostly-lossy path. Real resolvers normally sit well below this threshold.
	select {
	case <-time.After(1500 * time.Millisecond):
	case <-ctx.Done():
		return false
	}
	want, ok := normalizedResolver(resolver)
	if !ok {
		want = resolver
	}
	for _, path := range client.PathStats() {
		if path.Resolver == want && path.Verified && !path.Suspended && path.Loss <= 0.5 {
			return true
		}
	}
	return false
}

// verifyResolvers runs the authenticated Soar handshake against every scanner
// survivor. Results are returned in the original scanner order so the fastest
// / best-scoring resolvers stay first.
func verifyResolvers(ctx context.Context, cfg config, candidates []string, workers int) ([]string, error) {
	if workers <= 0 {
		workers = 4
	}
	if workers > 32 {
		workers = 32
	}
	order := make([]string, 0, len(candidates))
	seen := map[string]bool{}
	for _, item := range candidates {
		resolver, ok := normalizedResolver(item)
		if !ok {
			continue
		}
		if !seen[resolver] {
			seen[resolver] = true
			order = append(order, resolver)
		}
	}
	if len(order) == 0 {
		return nil, errors.New("no valid resolver candidates to verify")
	}
	timeout := time.Duration(min(cfg.Soar.DialTimeoutSeconds, 30)) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	type verdict struct {
		resolver string
		ok       bool
	}
	jobs := make(chan string)
	results := make(chan verdict, len(order))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for resolver := range jobs {
				ok := false
				for attempt := 0; attempt < 2 && !ok; attempt++ {
					probeCtx, cancel := context.WithTimeout(ctx, timeout)
					ok = probeResolver(probeCtx, cfg, resolver, nil)
					cancel()
					if !ok && attempt == 0 {
						select {
						case <-time.After(2 * time.Second):
						case <-ctx.Done():
						}
					}
				}
				results <- verdict{resolver: resolver, ok: ok}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, resolver := range order {
			select {
			case jobs <- resolver:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	verifiedSet := map[string]bool{}
	for v := range results {
		result := "reject"
		if v.ok {
			verifiedSet[v.resolver] = true
			result = "ok"
		}
		fmt.Printf("SCAN_VERIFY resolver=%s result=%s\n", v.resolver, result)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(verifiedSet))
	for _, resolver := range order {
		if verifiedSet[resolver] {
			out = append(out, resolver)
		}
	}
	fmt.Printf("SCAN_VERIFIED total=%d verified=%d\n", len(order), len(out))
	return out, nil
}
