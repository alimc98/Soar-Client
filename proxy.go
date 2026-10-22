package main

import (
	"context"
	"crypto/hmac"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/soar"
)

type dialFunc func(context.Context, string, string) (net.Conn, error)

// startupHTTPS authenticates the server and verifies real HTTPS before exposing SOCKS.
func startupHTTPS(ctx context.Context, dial dialFunc, roots *x509.CertPool) error {
	transport := &http.Transport{DialContext: dial, DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: 45 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	resp, err := client.Do(req)
	if err != nil {
		var certificateError *tls.CertificateVerificationError
		if errors.As(err, &certificateError) {
			return errors.New("startup HTTPS certificate verification failed; check system certificates and device clock")
		}
		var networkError net.Error
		if ctx.Err() != nil || errors.As(err, &networkError) && networkError.Timeout() {
			return errors.New("startup HTTPS timed out; try another resolver, discovery or the Conservative preset")
		}
		return errors.New("startup HTTPS stream failed; try another resolver or the Conservative preset, and check server outbound HTTPS")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return errors.New("startup HTTPS destination returned an unsuccessful status")
	}
	_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	return err
}

type proxy struct {
	cfg      config
	dial     dialFunc
	upload   atomic.Int64
	download atomic.Int64
}

func (p *proxy) handle(ctx context.Context, local net.Conn) {
	defer local.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = local.Close()
		case <-done:
		}
	}()
	_ = local.SetDeadline(time.Now().Add(15 * time.Second))
	var hello [2]byte
	if _, err := io.ReadFull(local, hello[:]); err != nil || hello[0] != 5 || hello[1] == 0 {
		return
	}
	methods := make([]byte, int(hello[1]))
	if _, err := io.ReadFull(local, methods); err != nil {
		return
	}
	want := byte(0)
	if p.cfg.Username != "" {
		want = 2
	}
	found := false
	for _, method := range methods {
		if method == want {
			found = true
		}
	}
	if !found {
		_, _ = local.Write([]byte{5, 255})
		return
	}
	if _, err := local.Write([]byte{5, want}); err != nil {
		return
	}
	if want == 2 {
		if _, err := io.ReadFull(local, hello[:]); err != nil || hello[0] != 1 || hello[1] == 0 {
			return
		}
		username := make([]byte, int(hello[1]))
		if _, err := io.ReadFull(local, username); err != nil {
			return
		}
		var size [1]byte
		if _, err := io.ReadFull(local, size[:]); err != nil || size[0] == 0 {
			return
		}
		password := make([]byte, int(size[0]))
		if _, err := io.ReadFull(local, password); err != nil {
			return
		}
		if !hmac.Equal(username, []byte(p.cfg.Username)) || !hmac.Equal(password, []byte(p.cfg.Password)) {
			_, _ = local.Write([]byte{1, 1})
			return
		}
		if _, err := local.Write([]byte{1, 0}); err != nil {
			return
		}
	}
	var header [4]byte
	if _, err := io.ReadFull(local, header[:]); err != nil || header[0] != 5 || header[2] != 0 {
		return
	}
	reply := func(code byte) { _, _ = local.Write([]byte{5, code, 0, 1, 127, 0, 0, 1, 0, 0}) }
	if header[1] != 1 {
		reply(7)
		return
	} // BIND and UDP ASSOCIATE are unsupported.
	var host string
	switch header[3] {
	case 1, 4:
		size := 4
		if header[3] == 4 {
			size = 16
		}
		raw := make([]byte, size)
		if _, err := io.ReadFull(local, raw); err != nil {
			return
		}
		host = net.IP(raw).String()
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(local, size[:]); err != nil || size[0] == 0 {
			return
		}
		raw := make([]byte, int(size[0]))
		if _, err := io.ReadFull(local, raw); err != nil {
			return
		}
		host = string(raw)
		if strings.ContainsAny(host, "\x00\r\n") {
			reply(8)
			return
		}
	default:
		reply(8)
		return
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(local, portBytes[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	if port == 0 {
		reply(2)
		return
	}
	// The negotiation deadline must not shorten a slow authenticated tunnel dial.
	_ = local.SetDeadline(time.Time{})
	dialCtx, cancel := context.WithTimeout(ctx, time.Duration(p.cfg.Soar.DialTimeoutSeconds)*time.Second)
	remote, err := p.dial(dialCtx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	cancel()
	if err != nil {
		reply(5)
		return
	}
	defer remote.Close()
	go func() {
		select {
		case <-ctx.Done():
			_ = remote.Close()
		case <-done:
		}
	}()
	reply(0)
	_ = local.SetDeadline(time.Time{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(&countWriter{writer: remote, count: &p.upload}, local)
		if half, ok := remote.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
		if err != nil {
			_ = remote.Close()
			_ = local.Close()
		}
	}()
	_, err = io.Copy(&countWriter{writer: local, count: &p.download}, remote)
	if half, ok := local.(interface{ CloseWrite() error }); ok {
		_ = half.CloseWrite()
	}
	// If the origin ends its response while the app still holds its upload open,
	// close the app connection to avoid retaining the stream forever.
	_ = local.Close()
	if err != nil {
		_ = remote.Close()
	}
	wg.Wait()
}

type countWriter struct {
	writer io.Writer
	count  *atomic.Int64
}

func (w *countWriter) Write(data []byte) (int, error) {
	n, err := w.writer.Write(data)
	w.count.Add(int64(n))
	return n, err
}

func (p *proxy) serve(ctx context.Context, listener net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer listener.Close()
	go func() { <-ctx.Done(); _ = listener.Close() }()
	slots := make(chan struct{}, p.cfg.Soar.MaxStreams)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	for {
		local, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = local.Close()
			continue
		}
		wg.Add(1)
		go func() { defer wg.Done(); defer func() { <-slots }(); p.handle(ctx, local) }()
	}
}

func telemetry(ctx context.Context, p *proxy, client *soar.Client) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var previousUp, previousDown int64
	ticks := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			up, down := p.upload.Load(), p.download.Load()
			fmt.Printf("WD_TRAFFIC %d B/s (Total: %d B) | %d B/s (Total: %d B)\n", up-previousUp, up, down-previousDown, down)
			previousUp, previousDown = up, down
			ticks++
			if ticks%5 == 0 {
				var detail []string
				for _, path := range client.PathStats() {
					if path.Verified && len(detail) < 4 {
						detail = append(detail, fmt.Sprintf("%s/%s rtt=%dms loss=%.0f%% qname=%d answer=%d window=%.1f suspended=%t", path.Resolver, path.Transport, path.RTT.Milliseconds(), path.Loss*100, path.NameLen, path.AnswerLimit, path.Window, path.Suspended))
					}
				}
				if len(detail) > 0 {
					fmt.Println("SOAR_PATHS " + strings.Join(detail, "; "))
				}
			}
			var active, valid []string
			for _, path := range client.PathStats() {
				if path.Verified && len(valid) < 64 {
					valid = append(valid, path.Resolver)
				}
				if path.Verified && !path.Suspended && len(active) < 64 {
					active = append(active, path.Resolver)
				}
			}
			list := func(values []string) string {
				if len(values) == 0 {
					return "-"
				}
				return strings.Join(values, ",")
			}
			fmt.Printf("WD_RESOLVERS active=%s standby=- valid=%s\n", list(active), list(valid))
		}
	}
}
