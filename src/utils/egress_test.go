package utils

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hubproxy/config"
)

type testRoundTripper func(*http.Request) (*http.Response, error)

func (f testRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func clearProxyEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(key, "")
	}
}

func TestOutboundURLPolicy(t *testing.T) {
	clearProxyEnvironment(t)
	p := newEgressPolicy(config.DefaultConfig(), time.Second)
	for _, tc := range []struct {
		url     string
		allowed bool
	}{
		{"https://registry-1.docker.io/v2/", true}, {"https://auth.docker.io/token", true},
		{"https://ghcr.io/v2/", true}, {"https://release-assets.githubusercontent.com/x", true},
		{"https://cdn-lfs.hf.co/model", true}, {"https://huggingface.co/model", true},
		{"https://127.0.0.1/", false}, {"https://[::ffff:127.0.0.1]/", false},
		{"https://169.254.169.254/", false}, {"http://github.com/", false},
		{"https://github.com:8443/", false}, {"https://github.com.evil.test/", false},
		{"https://evilgithub.com/", false}, {"file:///etc/passwd", false},
		{"https://user:password@github.com/", false}, {"https://[fe80::1%25en0]/", false},
	} {
		u, err := url.Parse(tc.url)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.validateURL(u) == nil; got != tc.allowed {
			t.Errorf("%s allowed=%v", tc.url, got)
		}
	}
}

func TestResolvedDestinationsAndPinnedDial(t *testing.T) {
	clearProxyEnvironment(t)
	for _, answer := range [][]string{
		{"127.0.0.1"}, {"::ffff:127.0.0.1"}, {"10.1.2.3"}, {"192.168.1.1"},
		{"169.254.169.254"}, {"100.100.100.200"}, {"fc00::1"}, {"fe80::1"},
		{"::"}, {"224.0.0.1"}, {"2002:7f00:1::1"}, {"64:ff9b::7f00:1"},
		{"8.8.8.8", "127.0.0.1"},
	} {
		p := newEgressPolicy(config.DefaultConfig(), time.Second)
		p.lookup = func(context.Context, string) ([]netip.Addr, error) {
			var values []netip.Addr
			for _, a := range answer {
				values = append(values, netip.MustParseAddr(a))
			}
			return values, nil
		}
		p.dial = func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("unsafe answer reached socket dial", answer)
			return nil, nil
		}
		if _, err := p.dialContext(context.Background(), "tcp", "github.com:443"); err == nil {
			t.Fatal("unsafe DNS accepted", answer)
		}
	}
	p := newEgressPolicy(config.DefaultConfig(), time.Second)
	lookups := 0
	p.lookup = func(context.Context, string) ([]netip.Addr, error) {
		lookups++
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	p.dial = func(_ context.Context, _ string, address string) (net.Conn, error) {
		if address != "8.8.8.8:443" {
			t.Fatal("hostname re-resolved at dial", address)
		}
		return left, nil
	}
	if _, err := p.dialContext(context.Background(), "tcp", "github.com:443"); err != nil {
		t.Fatal(err)
	}
	if lookups != 1 {
		t.Fatalf("unexpected second DNS lookup: %d", lookups)
	}
}

func TestRedirectsRevalidateButAllowPublicCDN(t *testing.T) {
	clearProxyEnvironment(t)
	for _, tc := range []struct {
		location string
		allowed  bool
	}{
		{"https://127.0.0.1/secret", false}, {"https://169.254.169.254/metadata", false},
		{"http://github.com/insecure", false}, {"https://evil.test/", false},
		{"https://release-assets.githubusercontent.com/download", true},
	} {
		p := newEgressPolicy(config.DefaultConfig(), time.Second)
		calls := 0
		next := testRoundTripper(func(r *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{tc.location}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("public download")), Request: r}, nil
		})
		client := &http.Client{Transport: &guardedTransport{policy: p, next: next}}
		resp, err := client.Get("https://github.com/user/repo/releases/download/file")
		if tc.allowed {
			if err != nil || calls != 2 {
				t.Fatalf("CDN redirect rejected: %v", err)
			}
			resp.Body.Close()
		} else if err == nil || calls != 1 {
			t.Fatalf("unsafe redirect reached transport: %v calls=%d", err, calls)
		}
		// A separate client/recursive handler using the shared transport must
		// enforce the same rule even without the parent's CheckRedirect hook.
		u, _ := url.Parse(tc.location)
		_, manualErr := client.Transport.RoundTrip(&http.Request{Method: "GET", URL: u, Header: make(http.Header)})
		if !tc.allowed && !errors.Is(manualErr, ErrOutboundDenied) {
			t.Fatalf("manual redirect bypass: %v", manualErr)
		}
	}
}

func TestConfiguredHTTPProxyReceivesPinnedIP(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	result := make(chan error, 1)
	go func() {
		request := make([]byte, 4096)
		n, err := right.Read(request)
		if err == nil && !strings.HasPrefix(string(request[:n]), "CONNECT 8.8.8.8:443 HTTP/1.1\r\n") {
			err = errors.New("proxy did not receive numeric destination")
		}
		if err == nil {
			_, err = io.WriteString(right, "HTTP/1.1 200 Connection Established\r\n\r\n")
		}
		result <- err
	}()
	dial := configuredProxyDialer("http://127.0.0.1:8080", func(_ context.Context, _ string, address string) (net.Conn, error) {
		if address != "127.0.0.1:8080" {
			t.Fatal(address)
		}
		return left, nil
	})
	conn, err := dial(context.Background(), "tcp", "8.8.8.8:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestEnvironmentAndConfiguredProxiesPreserveRemoteDNS(t *testing.T) {
	for _, mode := range []string{"HTTPS_PROXY", "https_proxy", "config"} {
		t.Run(mode, func(t *testing.T) {
			for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"} {
				t.Setenv(key, "")
			}
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodConnect || r.Host != "8.8.8.8:443" {
					t.Errorf("proxy received unchecked destination: %s %s", r.Method, r.Host)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			cfg := config.DefaultConfig()
			if mode == "config" {
				cfg.Access.Proxy = server.URL
			} else {
				t.Setenv(mode, server.URL)
			}
			p := newEgressPolicy(cfg, time.Second)
			p.lookup = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("local DNS unavailable") }
			fallbacks := 0
			p.proxyLookup = func(_ context.Context, host string, _ func(context.Context, string, string) (net.Conn, error)) ([]netip.Addr, error) {
				fallbacks++
				if host != "github.com" {
					t.Fatal(host)
				}
				return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
			}
			conn, err := p.dialContext(context.Background(), "tcp", "github.com:443")
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			if fallbacks != 1 || calls.Load() != 1 {
				t.Fatalf("proxy DNS path not used: fallback=%d CONNECT=%d", fallbacks, calls.Load())
			}
			p.proxyLookup = func(context.Context, string, func(context.Context, string, string) (net.Conn, error)) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
			if _, err := p.dialContext(context.Background(), "tcp", "github.com:443"); err == nil || calls.Load() != 1 {
				t.Fatal("proxy DNS bypassed private-IP policy")
			}
		})
	}
}

func TestNoProxyRemainsEffective(t *testing.T) {
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(key, "")
	}
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "github.com")
	p := newEgressPolicy(config.DefaultConfig(), time.Second)
	p.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	p.dial = func(_ context.Context, _ string, address string) (net.Conn, error) {
		if address != "8.8.8.8:443" {
			t.Fatal("NO_PROXY ignored", address)
		}
		return left, nil
	}
	conn, err := p.dialContext(context.Background(), "tcp", "github.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}
