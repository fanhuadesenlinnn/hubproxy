package utils

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http/httpproxy"
	"golang.org/x/net/proxy"
	"hubproxy/config"
)

var ErrOutboundDenied = errors.New("outbound destination is not allowed")
var errUpstreamUnavailable = errors.New("upstream request unavailable")

type egressPolicy struct {
	hosts       []string
	lookup      func(context.Context, string) ([]netip.Addr, error)
	dial        func(context.Context, string, string) (net.Conn, error)
	proxyForURL func(*url.URL) (*url.URL, error)
	proxyLookup func(context.Context, string, func(context.Context, string, string) (net.Conn, error)) ([]netip.Addr, error)
}

var defaultEgressHosts = []string{
	"docker.io", "*.docker.io", "*.docker.com", "ghcr.io", "*.ghcr.io",
	"gcr.io", "*.gcr.io", "quay.io", "*.quay.io", "registry.k8s.io", "*.pkg.dev",
	"github.com", "*.github.com", "githubusercontent.com", "*.githubusercontent.com",
	"githubassets.com", "*.githubassets.com", "huggingface.co", "*.huggingface.co", "hf.co", "*.hf.co",
	"*.cloudflarestorage.com", "*.cloudfront.net", "*.amazonaws.com", "*.googleusercontent.com", "*.blob.core.windows.net",
	"storage.googleapis.com", "oauth2.googleapis.com",
}

var deniedNetworks = func() []netip.Prefix {
	var result []netip.Prefix
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001::/32", "2001:db8::/32", "2002::/16", "64:ff9b::/96", "64:ff9b:1::/48"} {
		result = append(result, netip.MustParsePrefix(cidr))
	}
	return result
}()

func publicAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.Zone() != "" || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range deniedNetworks {
		if prefix.Contains(addr) {
			return false
		}
	}
	// Currently allocated public IPv6 unicast space. Other ranges include local
	// translation/tunnelling mechanisms that must not bypass the IPv4 checks.
	return !addr.Is6() || netip.MustParsePrefix("2000::/3").Contains(addr)
}

func newEgressPolicy(cfg *config.AppConfig, timeout time.Duration) *egressPolicy {
	p := &egressPolicy{hosts: append([]string{}, defaultEgressHosts...),
		dial: (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext}
	p.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	p.hosts = append(p.hosts, cfg.Security.AllowedHosts...)
	for _, mapping := range cfg.Registries {
		if !mapping.Enabled {
			continue
		}
		for _, raw := range []string{mapping.Upstream, mapping.AuthHost} {
			if !strings.Contains(raw, "://") {
				raw = "https://" + raw
			}
			if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
				p.hosts = append(p.hosts, strings.ToLower(u.Hostname()))
			}
		}
	}
	proxyConfig := httpproxy.FromEnvironment()
	if cfg.Access.Proxy != "" {
		proxyConfig.HTTPProxy = cfg.Access.Proxy
		proxyConfig.HTTPSProxy = cfg.Access.Proxy
	}
	p.proxyForURL = proxyConfig.ProxyFunc()
	p.proxyLookup = lookupDNSOverProxy
	return p
}

func (p *egressPolicy) allowedHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || strings.Contains(host, "%") {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	for _, pattern := range p.hosts {
		pattern = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
		if strings.HasPrefix(pattern, "*.") {
			if strings.HasSuffix(host, pattern[1:]) && host != pattern[2:] {
				return true
			}
		} else if host == pattern {
			return true
		}
	}
	return false
}

func (p *egressPolicy) validateURL(u *url.URL) error {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || (u.Port() != "" && u.Port() != "443") || !p.allowedHost(u.Hostname()) {
		return ErrOutboundDenied
	}
	return nil
}

func (p *egressPolicy) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" || !p.allowedHost(host) {
		return nil, ErrOutboundDenied
	}
	addresses, err := p.lookup(ctx, host)
	proxyURL, proxyErr := p.proxyForURL(&url.URL{Scheme: "https", Host: host})
	if proxyErr != nil {
		return nil, errUpstreamUnavailable
	}
	dial := p.dial
	if proxyURL != nil {
		dial = configuredProxyDialer(proxyURL.String(), p.dial)
	}
	unsafeLocalAnswer := false
	for _, addr := range addresses {
		if !publicAddress(addr) {
			unsafeLocalAnswer = true
		}
	}
	if (err != nil || len(addresses) == 0 || unsafeLocalAnswer) && proxyURL != nil {
		// Preserve remote-only DNS deployments without delegating an unchecked
		// hostname to the proxy: resolve through a fixed public DoH endpoint,
		// then apply the same address policy and CONNECT only to numeric IPs.
		addresses, err = p.proxyLookup(ctx, host, dial)
	}
	if err != nil || len(addresses) == 0 {
		return nil, errUpstreamUnavailable
	}
	// Reject mixed answers too; never choose a public answer from an unsafe set.
	for _, addr := range addresses {
		if !publicAddress(addr) {
			return nil, ErrOutboundDenied
		}
	}
	for _, addr := range addresses {
		conn, err := dial(ctx, network, net.JoinHostPort(addr.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, errUpstreamUnavailable
}

func lookupDNSOverProxy(ctx context.Context, host string, dial func(context.Context, string, string) (net.Conn, error)) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "cloudflare-dns.com:443" {
			return nil, ErrOutboundDenied
		}
		return dial(ctx, network, "1.1.1.1:443")
	}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrOutboundDenied }}
	var addresses []netip.Addr
	for _, kind := range []string{"A", "AAAA"} {
		u := "https://cloudflare-dns.com/dns-query?" + url.Values{"name": {host}, "type": {kind}}.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, errUpstreamUnavailable
		}
		req.Header.Set("Accept", "application/dns-json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, errUpstreamUnavailable
		}
		var result struct {
			Status int
			Answer []struct {
				Type int
				Data string
			}
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&result)
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK || result.Status != 0 {
			return nil, errUpstreamUnavailable
		}
		for _, answer := range result.Answer {
			if answer.Type != 1 && answer.Type != 28 {
				continue
			}
			addr, err := netip.ParseAddr(answer.Data)
			if err != nil || (answer.Type == 1 && !addr.Is4()) || (answer.Type == 28 && !addr.Is6()) {
				return nil, ErrOutboundDenied
			}
			addresses = append(addresses, addr)
		}
	}
	if len(addresses) == 0 {
		return nil, errUpstreamUnavailable
	}
	return addresses, nil
}

type guardedTransport struct {
	policy *egressPolicy
	next   http.RoundTripper
}

func (t *guardedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.policy.validateURL(req.URL); err != nil {
		return nil, err
	}
	resp, err := t.next.RoundTrip(req)
	if err != nil {
		return nil, errUpstreamUnavailable
	}
	return resp, nil
}

func (t *guardedTransport) CloseIdleConnections() {
	if c, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

func configuredProxyDialer(raw string, direct func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("invalid configured proxy")
		}
	}
	if u.Scheme == "socks5" || u.Scheme == "socks5h" {
		var auth *proxy.Auth
		if u.User != nil {
			password, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: password}
		}
		address := u.Host
		if u.Port() == "" {
			address = net.JoinHostPort(u.Hostname(), "1080")
		}
		d, err := proxy.SOCKS5("tcp", address, auth, &net.Dialer{Timeout: 30 * time.Second})
		if err == nil {
			if cd, ok := d.(proxy.ContextDialer); ok {
				return cd.DialContext
			}
		}
		return func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("invalid configured SOCKS proxy")
		}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unsupported configured proxy")
		}
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		proxyAddress := u.Host
		if u.Port() == "" {
			port := "80"
			if u.Scheme == "https" {
				port = "443"
			}
			proxyAddress = net.JoinHostPort(u.Hostname(), port)
		}
		conn, err := direct(ctx, network, proxyAddress)
		if err != nil {
			return nil, err
		}
		rawConnection := conn
		stopCancellation := context.AfterFunc(ctx, func() { rawConnection.Close() })
		defer stopCancellation()
		ok := false
		defer func() {
			if !ok {
				conn.Close()
			}
		}()
		deadline := time.Now().Add(30 * time.Second)
		if d, has := ctx.Deadline(); has && d.Before(deadline) {
			deadline = d
		}
		conn.SetDeadline(deadline)
		if u.Scheme == "https" {
			tc := tls.Client(conn, &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
			if err := tc.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			conn = tc
		}
		req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: address}, Host: address, Header: make(http.Header)}
		if u.User != nil {
			password, _ := u.User.Password()
			req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+password)))
		}
		if err := req.Write(conn); err != nil {
			return nil, err
		}
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, errors.New("configured proxy refused CONNECT")
		}
		conn.SetDeadline(time.Time{})
		ok = true
		return &bufferedProxyConn{Conn: conn, reader: reader}, nil
	}
}

type bufferedProxyConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedProxyConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
