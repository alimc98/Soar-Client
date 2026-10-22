package main

import (
	"bufio"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// candidateSeeds is the bundled Iranian CIDR snapshot. It is embedded so a
// freshly installed client can run -mode auto without downloading a list.
//
//go:embed data/resolver-candidates.txt
var candidateSeeds []byte

func loadResolvers(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("resolver file could not be opened")
	}
	defer f.Close()
	if stat, err := f.Stat(); err != nil || stat.Size() > 16<<20 {
		return nil, errors.New("resolver file exceeds the 16 MiB input limit")
	}
	var out []string
	seen := map[string]bool{}
	s := bufio.NewScanner(io.LimitReader(f, 16<<20))
	for s.Scan() {
		line := strings.TrimSpace(strings.SplitN(s.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		var addr string
		if ip, err := netip.ParseAddr(line); err == nil {
			addr = normalizedAddr(ip)
		} else if ap, err := netip.ParseAddrPort(line); err == nil && ap.Port() != 0 {
			addr = ap.String()
		} else {
			return nil, errors.New("resolver file must contain one IP or IP:port per line")
		}
		if !seen[addr] {
			seen[addr] = true
			out = append(out, addr)
		}
	}
	return out, s.Err()
}

func normalizedAddr(ip netip.Addr) string {
	return netip.AddrPortFrom(ip, 53).String()
}

func writeLines(path string, lines []string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(line)
		b.WriteString("\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

func stripPorts(list []string) []string {
	out := make([]string, 0, len(list))
	for _, item := range list {
		if ap, err := netip.ParseAddrPort(item); err == nil {
			out = append(out, ap.Addr().String())
			continue
		}
		if ip, err := netip.ParseAddr(item); err == nil {
			out = append(out, ip.String())
			continue
		}
		out = append(out, item)
	}
	return out
}

func attachDefaultPort(list []string) []string {
	out := make([]string, 0, len(list))
	for _, item := range list {
		if resolver, ok := normalizedResolver(item); ok {
			out = append(out, resolver)
		}
	}
	return out
}

// expandTargets reads a candidate list of IPs and CIDR ranges. The special
// value "embedded" (or "-") selects the bundled Iranian range snapshot.
func expandTargets(path string, samples int) ([]string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("candidate list is empty")
	}
	if path == "embedded" || path == "-" {
		return expandTargetsFromBytes(candidateSeeds, samples)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) > 16<<20 {
		return nil, errors.New("candidate list exceeds the 16 MiB input limit")
	}
	return expandTargetsFromBytes(raw, samples)
}

func expandTargetsFromBytes(raw []byte, samples int) ([]string, error) {
	seen := map[string]struct{}{}
	out := []string{}
	add := func(ip string) {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			return
		}
		parsed, err := netip.ParseAddr(ip)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %q: not an IP address\n", ip)
			return
		}
		ip = parsed.Unmap().String()
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
			if strings.HasPrefix(token, "[") && strings.HasSuffix(token, "]") {
				token = strings.TrimSuffix(strings.TrimPrefix(token, "["), "]")
			}
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
// host addresses, skipping the network and broadcast addresses.
func expandCIDR(cidr string, samples int) ([]string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}
	prefix = prefix.Masked()
	addr := prefix.Addr()
	bits := prefix.Bits()
	if addr.Is4In6() {
		addr = addr.Unmap()
		bits -= 96
		if bits < 0 {
			return nil, errors.New("invalid IPv4-mapped prefix")
		}
	}
	if addr.Is4() {
		return expandCIDR4(addr, bits, samples, cidr)
	}
	return expandCIDR6(addr, bits, samples, cidr)
}

func expandCIDR4(addr netip.Addr, bits, samples int, cidr string) ([]string, error) {
	hostBits := 32 - bits
	total := uint64(1) << hostBits
	first, last := uint64(0), total-1
	usable := total
	if total > 2 {
		first, last = 1, total-2
		usable = total - 2
	}
	n := samples
	if n <= 0 {
		if usable > 1_000_000 {
			return nil, fmt.Errorf("range %s has %d addresses; use -samples to cap the probe count", cidr, usable)
		}
		n = int(usable)
	}
	if uint64(n) > usable {
		n = int(usable)
	}
	if n <= 0 {
		return nil, errors.New("range has no usable host addresses")
	}
	step := usable / uint64(n)
	if step == 0 {
		step = 1
	}
	base := binary.BigEndian.Uint32(addr.AsSlice())
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		off := first + uint64(i)*step
		if off > last {
			off = last
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], base+uint32(off))
		out = append(out, netip.AddrFrom4(b).String())
	}
	return out, nil
}

func expandCIDR6(addr netip.Addr, bits, samples int, cidr string) ([]string, error) {
	if samples <= 0 {
		return nil, fmt.Errorf("IPv6 range %s needs -samples", cidr)
	}
	hostBits := 128 - bits
	size := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	first := big.NewInt(0)
	last := new(big.Int).Sub(size, big.NewInt(1))
	usable := new(big.Int).Set(size)
	if size.Cmp(big.NewInt(2)) > 0 {
		first = big.NewInt(1)
		last = new(big.Int).Sub(size, big.NewInt(2))
		usable = new(big.Int).Sub(size, big.NewInt(2))
	}
	n := samples
	if big.NewInt(int64(n)).Cmp(usable) > 0 {
		if usable.IsInt64() {
			n = int(usable.Int64())
		}
	}
	if n <= 0 {
		return nil, errors.New("range has no usable host addresses")
	}
	step := new(big.Int).Div(usable, big.NewInt(int64(n)))
	if step.Sign() == 0 {
		step = big.NewInt(1)
	}
	base := new(big.Int).SetBytes(addr.AsSlice())
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		off := new(big.Int).Mul(step, big.NewInt(int64(i)))
		off.Add(off, first)
		if off.Cmp(last) > 0 {
			off.Set(last)
		}
		value := new(big.Int).Add(base, off)
		buf := value.Bytes()
		if len(buf) > 16 {
			return nil, errors.New("address overflow")
		}
		var raw [16]byte
		copy(raw[16-len(buf):], buf)
		out = append(out, netip.AddrFrom16(raw).String())
	}
	return out, nil
}
