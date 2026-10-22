package main

import (
	"net/netip"
	"testing"
)

func TestExpandCIDR4SamplesAreInsideRange(t *testing.T) {
	prefix := netip.MustParsePrefix("2.144.0.0/14")
	ips, err := expandCIDR(prefix.String(), 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 5 {
		t.Fatalf("got %d addresses, want 5", len(ips))
	}
	seen := map[string]bool{}
	for _, raw := range ips {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !prefix.Contains(addr) {
			t.Fatalf("%s is outside %s", raw, prefix)
		}
		if seen[raw] {
			t.Fatalf("duplicate address %s", raw)
		}
		seen[raw] = true
	}
	if ips[0] == "2.144.0.0" {
		t.Fatal("network address was sampled")
	}
}

func TestExpandCIDR4EveryAddressSkipsEdges(t *testing.T) {
	ips, err := expandCIDR("192.0.2.0/30", 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.1", "192.0.2.2"}
	if len(ips) != len(want) {
		t.Fatalf("got %v, want %v", ips, want)
	}
	for i := range want {
		if ips[i] != want[i] {
			t.Fatalf("got %v, want %v", ips, want)
		}
	}
}

func TestExpandCIDR6Samples(t *testing.T) {
	ips, err := expandCIDR("2001:db8::/126", 2)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2001:db8::1", "2001:db8::2"}
	if len(ips) != len(want) {
		t.Fatalf("got %v, want %v", ips, want)
	}
	for i := range want {
		if ips[i] != want[i] {
			t.Fatalf("got %v, want %v", ips, want)
		}
	}
}

func TestExpandTargetsDeduplicatesAndParsesTokens(t *testing.T) {
	raw := []byte(`
# comment
1.1.1.1, 8.8.8.8; 1.1.1.1
192.0.2.0/30
not-an-ip
[2001:db8::1]
`)
	ips, err := expandTargetsFromBytes(raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"1.1.1.1":     true,
		"8.8.8.8":     true,
		"192.0.2.1":   true,
		"192.0.2.2":   true,
		"2001:db8::1": true,
	}
	if len(ips) != len(want) {
		t.Fatalf("got %v, want %d entries", ips, len(want))
	}
	for _, ip := range ips {
		if !want[ip] {
			t.Fatalf("unexpected address %s", ip)
		}
	}
}
