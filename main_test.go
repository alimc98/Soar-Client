package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/getlantern/soar"
)

func tunnel(t *testing.T, dial dialFunc) (*soar.Client, config) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = pc.Close() })
	go func() { _ = soar.Serve(ctx, pc, soar.ServerConfig{Zone: "t.example.com", PrivateKey: key, Dial: dial}) }()
	cfg := defaults()
	cfg.Zone = "t.example.com"
	cfg.PublicKey = base64.StdEncoding.EncodeToString(pub)
	cfg.Soar.Discovery = false
	cfg.Soar.Transport = "off"
	client, err := soar.NewClient(cfg.clientConfig([]string{pc.LocalAddr().String()}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, cfg
}

func socksListener(t *testing.T, p *proxy) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = p.serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("SOCKS shutdown stalled")
		}
	})
	return ln.Addr().String()
}

func connectSocks(t *testing.T, address, host string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	_, _ = c.Write([]byte{5, 1, 0})
	var reply [2]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil || reply != [2]byte{5, 0} {
		t.Fatalf("SOCKS greeting: %v %v", reply, err)
	}
	request := append([]byte{5, 1, 0, 3, byte(len(host))}, []byte(host)...)
	request = append(request, 1, 187) // 443
	_, _ = c.Write(request)
	var response [10]byte
	if _, err := io.ReadFull(c, response[:]); err != nil || response[1] != 0 {
		t.Fatalf("SOCKS CONNECT: %v %v", response, err)
	}
	return c
}

func TestSOCKSUsesTunnelAndPreservesHostnames(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	var destinations sync.Map
	client, cfg := tunnel(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		destinations.Store(address, true)
		return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
	})
	p := &proxy{cfg: cfg, dial: client.DialContext}
	address := socksListener(t, p)
	for _, host := range []string{"unresolved-one.invalid", "unresolved-two.invalid"} {
		c := connectSocks(t, address, host)
		data := bytes.Repeat([]byte("echo payload "), 3000)
		if _, err := c.Write(data); err != nil {
			t.Fatal(err)
		}
		_ = c.(*net.TCPConn).CloseWrite()
		response, err := io.ReadAll(c)
		_ = c.Close()
		if err != nil || !bytes.Equal(response, data) {
			t.Fatalf("payload / half-close failed: %d %v", len(response), err)
		}
		if _, ok := destinations.Load(host + ":443"); !ok {
			t.Fatal("destination hostname was resolved or changed locally")
		}
	}
	if p.upload.Load() == 0 || p.download.Load() == 0 {
		t.Fatal("traffic counters were not updated")
	}
}

func TestUDPAndMissingAuthenticationAreRejected(t *testing.T) {
	cfg := defaults()
	p := &proxy{cfg: cfg}
	address := socksListener(t, p)
	c, _ := net.Dial("tcp", address)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_, _ = c.Write([]byte{5, 1, 0})
	var greeting [2]byte
	_, _ = io.ReadFull(c, greeting[:])
	_, _ = c.Write([]byte{5, 3, 0, 1})
	var response [10]byte
	if _, err := io.ReadFull(c, response[:]); err != nil || response[1] != 7 {
		t.Fatalf("UDP was not explicitly rejected: %v %v", response, err)
	}
	cfg.Username, cfg.Password = "user", "pass"
	address = socksListener(t, &proxy{cfg: cfg})
	c2, _ := net.Dial("tcp", address)
	defer c2.Close()
	_ = c2.SetDeadline(time.Now().Add(time.Second))
	_, _ = c2.Write([]byte{5, 1, 0})
	_, _ = io.ReadFull(c2, greeting[:])
	if greeting != [2]byte{5, 255} {
		t.Fatal("authentication was bypassed")
	}
}

func TestSOCKSUsernamePassword(t *testing.T) {
	cfg := defaults()
	cfg.Username, cfg.Password = "user", "pass"
	address := socksListener(t, &proxy{cfg: cfg})
	for _, password := range []string{"pass", "wrong"} {
		c, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_, _ = c.Write([]byte{5, 1, 2})
		var reply [2]byte
		if _, err := io.ReadFull(c, reply[:]); err != nil || reply != [2]byte{5, 2} {
			t.Fatal("authentication method not selected")
		}
		request := append([]byte{1, 4}, []byte("user")...)
		request = append(request, byte(len(password)))
		request = append(request, password...)
		_, _ = c.Write(request)
		if _, err := io.ReadFull(c, reply[:]); err != nil {
			t.Fatal(err)
		}
		want := byte(1)
		if password == "pass" {
			want = 0
		}
		if reply != [2]byte{1, want} {
			t.Fatalf("unexpected authentication result: %v", reply)
		}
		_ = c.Close()
	}
}

func TestStartupChecksHTTPSCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer server.Close()
	client, _ := tunnel(t, func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	})
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	if err := startupHTTPS(ctx, client.DialContext, roots); err != nil {
		t.Fatal(err)
	}
	if err := startupHTTPS(ctx, client.DialContext, x509.NewCertPool()); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}

func TestConfigBoundsAndPublicListenerAuth(t *testing.T) {
	cfg := defaults()
	cfg.Zone = "t.example.com"
	cfg.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	cfg.Listen = "0.0.0.0:1080"
	if cfg.validate() == nil {
		t.Fatal("public SOCKS listener without authentication was allowed")
	}
	cfg.Username, cfg.Password = "user", "pass"
	if err := cfg.validate(); err != nil {
		t.Fatalf("authenticated public listener was rejected: %v", err)
	}
	cfg.Listen = "[::]:1080"
	if err := cfg.validate(); err != nil {
		t.Fatalf("authenticated IPv6 wildcard listener was rejected: %v", err)
	}
	cfg.Listen = "0.0.0.0:0"
	if cfg.validate() == nil {
		t.Fatal("port zero was accepted")
	}
	cfg.Listen = "127.0.0.1:1080"
	cfg.Username, cfg.Password = "", ""
	cfg.Soar.SessionIdleSeconds = 120
	if cfg.validate() == nil {
		t.Fatal("idle timeout exceeds server expiry")
	}
	cfg.Soar.SessionIdleSeconds = 90
	cfg.Soar.SafeQName = 253
	cfg.Soar.MaxQName = 101
	if cfg.validate() == nil {
		t.Fatal("invalid name limits accepted")
	}
}

func TestEnvOverridesCanAuthenticatePublicListener(t *testing.T) {
	cfg := defaults()
	cfg.Zone = "t.example.com"
	cfg.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg.Listen = "0.0.0.0:1080"
	if cfg.validate() == nil {
		t.Fatal("public listener without authentication was allowed")
	}

	t.Setenv("SOAR_LISTEN", "0.0.0.0:10999")
	t.Setenv("SOAR_USERNAME", "env-user")
	t.Setenv("SOAR_PASSWORD", "env-pass")
	applyEnvOverrides(&cfg)
	if cfg.Listen != "0.0.0.0:10999" || cfg.Username != "env-user" || cfg.Password != "env-pass" {
		t.Fatalf("environment overrides not applied: %+v", cfg)
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("authenticated public listener was rejected: %v", err)
	}

	t.Setenv("SOAR_USERNAME", "")
	t.Setenv("SOAR_PASSWORD", "")
	applyEnvOverrides(&cfg)
	if cfg.Username != "" || cfg.Password != "" {
		t.Fatal("empty environment values did not clear credentials")
	}
	if cfg.validate() == nil {
		t.Fatal("cleared credentials left a public listener valid")
	}
}

func TestLoadConfigDefersListenerValidation(t *testing.T) {
	cfg := defaults()
	cfg.Zone = "t.example.com"
	cfg.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg.Listen = "0.0.0.0:10998"
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}

	loaded, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig rejected a public listener before overrides: %v", err)
	}
	if loaded.validate() == nil {
		t.Fatal("unauthenticated public listener passed validation")
	}
	if _, err := loadConfigValidated(path); err == nil {
		t.Fatal("validated loader accepted an unauthenticated public listener")
	}

	t.Setenv("SOAR_USERNAME", "u")
	t.Setenv("SOAR_PASSWORD", "p")
	applyEnvOverrides(&loaded)
	if err := loaded.validate(); err != nil {
		t.Fatalf("env overrides did not make the listener valid: %v", err)
	}
}

func TestResolversAreNormalizedAndDeduplicated(t *testing.T) {
	file := filepath.Join(t.TempDir(), "resolvers")
	_ = os.WriteFile(file, []byte("# test\n1.1.1.1\n1.1.1.1:53\n[::1]:5353\n"), 0600)
	list, err := loadResolvers(file)
	if err != nil || len(list) != 2 || list[0] != "1.1.1.1:53" {
		t.Fatalf("%v %v", list, err)
	}
	_ = os.WriteFile(file, []byte("example.com;id"), 0600)
	if _, err := loadResolvers(file); err == nil {
		t.Fatal("invalid resolver accepted")
	}
}
