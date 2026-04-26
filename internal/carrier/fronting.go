// Package carrier implements the client side of the Apps Script transport:
// a long-poll loop that batches outgoing frames, POSTs them through a
// domain-fronted HTTPS connection, and routes the response frames back to
// their sessions.
package carrier

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// FrontingConfig describes how to reach script.google.com without revealing
// the real Host to a passive on-path observer.
//
// Direct port of FlowDriver/internal/httpclient/client.go: dial GoogleIP, do a
// TLS handshake with SNI=SNIHost, then send HTTP requests with Host=HostHeader.
type FrontingConfig struct {
	GoogleIP   string // "ip:443"
	SNIHost    string // e.g. "www.google.com"
	HostHeader string // e.g. "script.google.com"
}

// hostRewriteTransport overrides req.Host on every RoundTrip so the inner HTTP
// request reaches the right Apps Script deployment regardless of what the
// outer URL says.
type hostRewriteTransport struct {
	rt   http.RoundTripper
	host string
}

func (t *hostRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.host != "" {
		req.Host = t.host
	}
	return t.rt.RoundTrip(req)
}

// NewFrontedClient returns an *http.Client that:
//   - Dials cfg.GoogleIP regardless of the URL host.
//   - Presents SNI=cfg.SNIHost in the TLS handshake.
//   - Rewrites the HTTP Host header to cfg.HostHeader.
//
// pollTimeout is the per-request ceiling; it should comfortably exceed the
// server's long-poll window (we use ~25s, default here is 60s).
func NewFrontedClient(cfg FrontingConfig, pollTimeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if cfg.GoogleIP != "" {
				return dialer.DialContext(ctx, "tcp", cfg.GoogleIP)
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName: cfg.SNIHost,
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	var rt http.RoundTripper = transport
	if cfg.HostHeader != "" {
		rt = &hostRewriteTransport{rt: transport, host: cfg.HostHeader}
	}

	return &http.Client{Transport: rt, Timeout: pollTimeout}
}
