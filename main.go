// Soar Client: a local SOCKS5 CONNECT proxy over an authenticated DNS tunnel,
// with a built-in WhiteDNS resolver scanner.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/getlantern/soar"
)

var clientVersion = "1.1.0"

const engineVersion = "1.6.7"

type options struct {
	Transport            string `json:"transport"`
	Discovery            bool   `json:"discovery"`
	Country              string `json:"country"`
	DiscoveryWant        int    `json:"discoveryWant"`
	DiscoveryConcurrency int    `json:"discoveryConcurrency"`
	DiscoveryPaceMs      int    `json:"discoveryPaceMs"`
	SafeQName            int    `json:"safeQName"`
	MaxQName             int    `json:"maxQName"`
	MaxAnswer            int    `json:"maxAnswer"`
	HoldMs               int    `json:"holdMs"`
	MaxInflight          int    `json:"maxInflight"`
	MaxPathWindow        int    `json:"maxPathWindow"`
	MaxStreams           int    `json:"maxStreams"`
	StreamWindowKiB      int    `json:"streamWindowKiB"`
	SendBufferKiB        int    `json:"sendBufferKiB"`
	SessionIdleSeconds   int    `json:"sessionIdleSeconds"`
	DialTimeoutSeconds   int    `json:"dialTimeoutSeconds"`
}

type config struct {
	Zone            string   `json:"zone"`
	PublicKey       string   `json:"server_public_key"`
	Listen          string   `json:"listen"`
	Username        string   `json:"username"`
	Password        string   `json:"password"`
	SystemResolvers []string `json:"system_resolvers"`
	Soar            options  `json:"soar"`
}

func defaults() config {
	return config{Listen: "127.0.0.1:10886", Soar: options{
		Transport: "auto", Discovery: true, Country: "IR", DiscoveryWant: 2,
		DiscoveryConcurrency: 2, DiscoveryPaceMs: 1000, SafeQName: 101, MaxQName: 253,
		MaxAnswer: 1232, HoldMs: 500, MaxInflight: 128, MaxPathWindow: 32, MaxStreams: 128,
		StreamWindowKiB: 256, SendBufferKiB: 64, SessionIdleSeconds: 90, DialTimeoutSeconds: 90,
	}}
}

func (c config) validate() error {
	if len(c.SystemResolvers) > 8 {
		return errors.New("at most eight network DNS servers are supported")
	}
	for _, resolver := range c.SystemResolvers {
		if _, ok := normalizedResolver(resolver); !ok {
			return errors.New("network DNS server must be an IP address")
		}
	}
	ap, err := netip.ParseAddrPort(c.Listen)
	if err != nil || ap.Port() == 0 {
		return errors.New("listen must be an IP:port with a port between 1 and 65535")
	}
	if !ap.Addr().IsLoopback() && c.Username == "" {
		return errors.New("listen on a non-loopback address requires SOCKS username and password")
	}
	if c.Zone != strings.ToLower(c.Zone) || len(c.Zone) > 45 || !strings.Contains(c.Zone, ".") {
		return errors.New("use one lowercase ASCII tunnel domain, maximum 45 characters")
	}
	for _, label := range strings.Split(c.Zone, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return errors.New("invalid tunnel domain")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return errors.New("tunnel domain must use ASCII letters, numbers, dots and hyphens")
			}
		}
	}
	key, err := base64.StdEncoding.DecodeString(c.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("server PUBLIC key must be a base64-encoded 32-byte Ed25519 key")
	}
	if (c.Username == "") != (c.Password == "") || len(c.Username) > 255 || len(c.Password) > 255 {
		return errors.New("SOCKS authentication needs both username and password, each at most 255 bytes")
	}
	o := c.Soar
	if o.Transport != "auto" && o.Transport != "on" && o.Transport != "only" && o.Transport != "off" {
		return errors.New("resolver transport must be auto, on, only or off")
	}
	if len(o.Country) != 0 && (len(o.Country) != 2 || o.Country[0] < 'A' || o.Country[0] > 'Z' || o.Country[1] < 'A' || o.Country[1] > 'Z') {
		return errors.New("country must be a two-letter code or blank")
	}
	for _, bound := range []struct{ value, low, high int }{
		{o.SafeQName, 101, 253}, {o.MaxQName, o.SafeQName, 253}, {o.MaxAnswer, 512, 1232},
		{o.HoldMs, 100, 1500}, {o.MaxInflight, 8, 1024}, {o.MaxPathWindow, 2, 128}, {o.MaxStreams, 8, 256},
		{o.StreamWindowKiB, 64, 1024}, {o.SendBufferKiB, 32, 1024}, {o.SessionIdleSeconds, 15, 110},
		{o.DialTimeoutSeconds, 5, 120}, {o.DiscoveryWant, 1, 32}, {o.DiscoveryConcurrency, 1, 16}, {o.DiscoveryPaceMs, 100, 5000},
	} {
		if bound.value < bound.low || bound.value > bound.high {
			return errors.New("a Soar advanced setting is outside its supported range; reset to the Balanced preset")
		}
	}
	return nil
}

func (c config) clientConfig(resolvers []string) soar.Config {
	key, _ := base64.StdEncoding.DecodeString(c.PublicKey)
	o := c.Soar
	initial, candidates := c.resolverPlan(resolvers)
	return soar.Config{
		Zone: c.Zone, ServerKey: key, Resolvers: initial, TCP: o.Transport,
		SafeQName: o.SafeQName, MaxQName: o.MaxQName, MaxAnswer: o.MaxAnswer,
		Hold: time.Duration(o.HoldMs) * time.Millisecond, MaxInflight: o.MaxInflight,
		MaxPathWindow: o.MaxPathWindow, MaxStreams: o.MaxStreams,
		StreamWindow: uint64(o.StreamWindowKiB) * 1024, SendBuffer: o.SendBufferKiB * 1024,
		SessionIdle: time.Duration(o.SessionIdleSeconds) * time.Second,
		Discovery: soar.Discovery{Enabled: o.Discovery, Country: o.Country, Candidates: candidates,
			Want: o.DiscoveryWant, Concurrency: o.DiscoveryConcurrency, Pace: time.Duration(o.DiscoveryPaceMs) * time.Millisecond},
	}
}

func loadConfig(path string) (config, error) {
	f, err := os.Open(path)
	if err != nil {
		return config{}, errors.New("engine configuration could not be opened")
	}
	defer f.Close()
	cfg := defaults()
	decoder := json.NewDecoder(io.LimitReader(f, 65536))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return config{}, errors.New("invalid Soar engine JSON configuration")
	}
	if err := cfg.validate(); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := dispatch(ctx, os.Args[1:]); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "SOAR_ERROR: "+err.Error())
		os.Exit(1)
	}
}

func dispatch(ctx context.Context, args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	switch strings.ToLower(args[0]) {
	case "scan":
		return runScanCommand(ctx, args[1:])
	case "run", "client", "connect":
		return runClient(ctx, args[1:])
	case "version", "-version", "--version":
		printVersion()
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return runClient(ctx, args)
	}
}

func printVersion() {
	fmt.Printf("Soar Client %s\n", clientVersion)
	fmt.Printf("Soar engine %s (Soar v0.2.3 + WhiteDNS transport fixes)\n", engineVersion)
	fmt.Println("Scanner engine: WhiteDNS dnsscan (pinned 5596061)")
}

func usage() {
	fmt.Print(`Soar Client - authenticated DNS tunnel SOCKS5 proxy with a resolver scanner

Usage:
  soar-client run  -config client.json -resolvers resolvers.txt
  soar-client run  -config client.json -scan -candidates candidates.txt
  soar-client scan -candidates candidates.txt -out-list resolvers-valid.txt
  soar-client -config client.json -resolvers resolvers.txt     (legacy form)

Modes:
  manual   use the resolver list you provide (default when -resolvers is set)
  auto     scan candidates, verify the survivors, then start the client
  scan     scan only and write reports / a resolver list

Client flags:
  -config FILE        client JSON configuration (required for manual/auto)
  -resolvers FILE     manual IP / IP:port list
  -mode MODE          manual | auto | scan (inferred when omitted)
  -scan               shorthand for -mode auto
  -scan-only          shorthand for -mode scan
  -listen ADDR        override the SOCKS listen address (public binds need auth)
  -discovery on|off   override Soar discovery (default: off in manual/auto)
  -verify auto|on|off  verify survivors with a real Soar handshake
                      (default auto: on for auto/scan, off for manual)
  -verify-workers N   concurrent Soar verification probes (default 2)
  -max-resolvers N    runtime resolver cap (default 128)
  -version            print versions

Scanner flags:
  -candidates FILE    IPs and/or CIDR ranges (default: bundled candidates)
  -list FILE          alias for -candidates
  -scan-out DIR       report directory (default: dns-scan)
  -scan-list FILE     accepted resolver list (alias: -out-list)
  -samples N          addresses per CIDR range (default 5; 0 = every address)
  -protocol P         udp | tcp | both | all (default: both)
  -ports LIST         comma-separated ports (default: 53)
  -workers N          scanner worker pool (default: 64)
  -scan-timeout D     per-probe timeout (default: 3s)
  -depth MODE         fast | full (default: full)
  -domain NAME        A-record integrity domain (default: google.com)
  -txt-domain NAME    TXT passthrough domain (default: _dmarc.google.com)
  -truth PROVIDER     google | cloudflare | quad9 (default: google)
  -score N            minimum compatibility score (default: 0)
  -nearby             expand the /24 around every hit and rescan
  -rate N             whole-scan query rate limit (0 = unlimited)
  -rate-per-resolver N  per-resolver query rate limit (0 = unlimited)
  -quiet              only print the final scan summary
`)
}

func resolveMode(flagMode string, scan, scanOnly bool, resolverFile string) (string, error) {
	if scanOnly {
		return "scan", nil
	}
	mode := strings.ToLower(strings.TrimSpace(flagMode))
	if scan {
		mode = "auto"
	}
	if mode == "" {
		if resolverFile != "" {
			return "manual", nil
		}
		return "auto", nil
	}
	switch mode {
	case "manual", "auto", "scan":
		return mode, nil
	case "scan-only":
		return "scan", nil
	default:
		return "", fmt.Errorf("unknown mode %q; use manual, auto, or scan", flagMode)
	}
}

func runClient(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("soar-client", flag.ContinueOnError)
	configFile := fs.String("config", "", "JSON engine configuration")
	resolverFile := fs.String("resolvers", "", "resolver list file")
	modeFlag := fs.String("mode", "", "manual, auto, or scan")
	scanFlag := fs.Bool("scan", false, "scan candidates, then connect")
	scanOnly := fs.Bool("scan-only", false, "scan candidates and exit")
	listenOverride := fs.String("listen", "", "override the SOCKS listen address")
	discoveryFlag := fs.String("discovery", "", "on or off")
	verifyFlag := fs.String("verify", "auto", "verify survivors: auto, on, or off")
	verifyWorkers := fs.Int("verify-workers", 2, "concurrent Soar verification probes")
	maxResolvers := fs.Int("max-resolvers", 128, "runtime resolver cap")
	version := fs.Bool("version", false, "print version")
	var sc scanConfig
	addScanFlags(fs, &sc)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if *version {
		printVersion()
		return nil
	}

	mode, err := resolveMode(*modeFlag, *scanFlag, *scanOnly, *resolverFile)
	if err != nil {
		return err
	}

	var cfg config
	if *configFile != "" {
		cfg, err = loadConfig(*configFile)
		if err != nil {
			return err
		}
	} else if mode != "scan" {
		return errors.New("-config is required for manual and auto modes")
	}

	if *listenOverride != "" {
		if mode == "scan" {
			return errors.New("-listen is only valid when starting the client")
		}
		cfg.Listen = *listenOverride
		if err := cfg.validate(); err != nil {
			return err
		}
	}

	if mode != "scan" {
		switch strings.ToLower(strings.TrimSpace(*discoveryFlag)) {
		case "":
			// Manual and auto modes deliberately use only the measured list.
			// Pass -discovery on to add the bundled country/global fallback.
			cfg.Soar.Discovery = false
		case "on", "true", "1", "yes":
			cfg.Soar.Discovery = true
		case "off", "false", "0", "no":
			cfg.Soar.Discovery = false
		default:
			return errors.New("-discovery must be on or off")
		}
	}

	verifyEnabled := false
	switch strings.ToLower(strings.TrimSpace(*verifyFlag)) {
	case "auto", "":
		// Auto scanning must prove the tunnel before starting. Manual mode is
		// deliberately fast: the caller already chose the resolvers.
		verifyEnabled = mode == "auto" || mode == "scan"
	case "on", "true", "1", "yes":
		verifyEnabled = true
	case "off", "false", "0", "no":
		verifyEnabled = false
	default:
		return errors.New("-verify must be auto, on, or off")
	}
	if mode == "scan" && *configFile == "" && verifyEnabled {
		verifyEnabled = false
		fmt.Fprintln(os.Stderr, "note: -verify needs -config; scan-only results are not Soar-verified")
	}

	switch mode {
	case "scan":
		if sc.listPath == "" {
			sc.listPath = "embedded"
		}
		accepted, err := runScan(ctx, sc)
		if err != nil {
			return err
		}
		if verifyEnabled {
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
		}
		return nil

	case "auto":
		if sc.listPath == "" {
			sc.listPath = "embedded"
		}
		accepted, err := runScan(ctx, sc)
		if err != nil {
			return err
		}
		resolvers := accepted
		if verifyEnabled {
			verified, err := verifyResolvers(ctx, cfg, accepted, *verifyWorkers)
			if err != nil {
				return err
			}
			resolvers = verified
		}
		if len(resolvers) == 0 {
			return errors.New("auto scan found no resolver that passed the Soar handshake")
		}
		if sc.outList != "" {
			if err := writeLines(sc.outList, stripPorts(resolvers)); err != nil {
				return err
			}
		}
		resolvers = attachDefaultPort(resolvers)
		if !cfg.Soar.Discovery {
			resolvers = capResolvers(resolvers, *maxResolvers)
		}
		return serveClient(ctx, cfg, resolvers, "auto")

	case "manual":
		if *resolverFile == "" {
			return errors.New("-resolvers is required for manual mode")
		}
		resolvers, err := loadResolvers(*resolverFile)
		if err != nil {
			return err
		}
		if len(resolvers) == 0 {
			return errors.New("resolver file has no usable entries")
		}
		if verifyEnabled {
			verified, err := verifyResolvers(ctx, cfg, resolvers, *verifyWorkers)
			if err != nil {
				return err
			}
			if len(verified) == 0 {
				return errors.New("none of the manual resolvers passed the Soar handshake")
			}
			resolvers = verified
		}
		if !cfg.Soar.Discovery {
			resolvers = capResolvers(resolvers, *maxResolvers)
		}
		return serveClient(ctx, cfg, resolvers, "manual")
	}
	return fmt.Errorf("unsupported mode %q", mode)
}

func serveClient(ctx context.Context, cfg config, resolvers []string, mode string) error {
	if len(resolvers) == 0 && !cfg.Soar.Discovery {
		return errors.New("add resolvers or enable Soar discovery")
	}
	if len(resolvers) > 8192 {
		return errors.New("runtime list is too large; scan it first and use the working resolvers")
	}
	if !cfg.Soar.Discovery && len(resolvers) > 128 {
		resolvers = capResolvers(resolvers, 128)
	}
	fmt.Printf("SOAR_MODE mode=%s resolvers=%d discovery=%t\n", mode, len(resolvers), cfg.Soar.Discovery)
	fmt.Println("WD_PROGRESS phase=session percent=90")
	client, err := soar.NewClient(cfg.clientConfig(resolvers))
	if err != nil {
		return errors.New("Soar client configuration could not be started")
	}
	defer client.Close()
	p := &proxy{cfg: cfg, dial: client.DialContext}
	go telemetry(ctx, p, client)
	probeCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Soar.DialTimeoutSeconds)*time.Second)
	err = startupHTTPS(probeCtx, client.DialContext, nil)
	cancel()
	if err != nil {
		if !client.Established() {
			return errors.New("no authenticated DNS tunnel; verify the public key and delegation, or enable discovery/change network resolvers")
		}
		return err
	}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return errors.New("local SOCKS port is unavailable; stop the other connection or choose another proxy port")
	}
	fmt.Printf("SOAR_LISTEN listen=%s auth=%t\n", listener.Addr().String(), cfg.Username != "")
	fmt.Println("SOAR_READY authenticated=1 https=1")
	fmt.Println("WD_PROGRESS phase=connected percent=100")
	return p.serve(ctx, listener)
}

func capResolvers(list []string, max int) []string {
	if max <= 0 || len(list) <= max {
		return list
	}
	fmt.Fprintf(os.Stderr, "warning: using %d of %d resolvers; raise -max-resolvers or use discovery\n", max, len(list))
	return list[:max]
}
