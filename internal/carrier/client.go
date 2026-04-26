package carrier

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kianmhz/relay-tunnel/internal/frame"
	"github.com/kianmhz/relay-tunnel/internal/session"
)

const (
	// MaxFramePayload caps the bytes per frame; larger writes are chunked.
	// Kept small so a single Apps Script POST stays well under any limit.
	MaxFramePayload = 128 * 1024

	// pollIdleSleep is the breather between polls when nothing is happening,
	// to avoid busy-looping if the server returns instantly with empty bodies.
	pollIdleSleep = 50 * time.Millisecond

	// pollTimeout is the per-request HTTP ceiling; should comfortably exceed
	// the server's long-poll window (~25s).
	pollTimeout = 120 * time.Second

	// maxDrainFramesPerSession keeps one busy session from monopolizing a poll
	// cycle when many short-lived sessions are active (e.g., chat apps).
	maxDrainFramesPerSession = 8

	// maxDrainFramesPerBatch bounds total frames sent in one poll request so
	// very high session fan-out does not create oversized POST bodies.
	maxDrainFramesPerBatch = 48

	// Under high fan-out (mobile apps opening many parallel connections), allow
	// a larger but still bounded batch to reduce queueing delay.
	busySessionThreshold       = 24
	maxDrainFramesPerBatchBusy = 144

	// Hard cap for one relay response body to avoid spending CPU/memory on
	// unexpectedly huge non-frame payloads (HTML error pages, quota pages, etc).
	maxRelayResponseBodyBytes = 32 * 1024 * 1024

	// Endpoint failure backoff to shed unhealthy deployments during quota spikes
	// or tail-latency events without changing protocol behavior.
	endpointBlacklistBaseTTL = 3 * time.Second
	endpointBlacklistMaxTTL  = 48 * time.Second
	endpointBlacklistMaxStep = 4
)

// Config bundles everything the carrier needs to talk to the relay.
type Config struct {
	ScriptURLs []string // one or more full https://script.google.com/macros/s/.../exec URLs
	Fronting   FrontingConfig
	AESKeyHex  string // 64-char hex, must match server
}

type relayEndpoint struct {
	url             string
	blacklistedTill time.Time
	failCount       int
}

// Client owns the session map and the long-poll loop.
type Client struct {
	cfg  Config
	aead *frame.Crypto
	http *http.Client

	mu       sync.Mutex
	sessions map[[frame.SessionIDLen]byte]*session.Session

	endpointMu   sync.Mutex
	endpoints    []relayEndpoint
	nextEndpoint int

	kickCh chan struct{} // buffered len 1; coalesces OnTx wake-ups
}

// New constructs a Client. The HTTP client is preconfigured for domain
// fronting per cfg.Fronting.
func New(cfg Config) (*Client, error) {
	aead, err := frame.NewCryptoFromHexKey(cfg.AESKeyHex)
	if err != nil {
		return nil, err
	}

	endpoints := make([]relayEndpoint, 0, len(cfg.ScriptURLs))
	seen := make(map[string]struct{}, len(cfg.ScriptURLs))
	for _, raw := range cfg.ScriptURLs {
		url := strings.TrimSpace(raw)
		if url == "" {
			continue
		}
		if _, ok := seen[url]; ok {
			continue
		}
		seen[url] = struct{}{}
		endpoints = append(endpoints, relayEndpoint{url: url})
	}
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("at least one script URL is required")
	}

	return &Client{
		cfg:       cfg,
		aead:      aead,
		http:      NewFrontedClient(cfg.Fronting, pollTimeout),
		sessions:  make(map[[frame.SessionIDLen]byte]*session.Session),
		endpoints: endpoints,
		kickCh:    make(chan struct{}, 1),
	}, nil
}

// NewSession creates a tunneled session for target ("host:port") and registers
// it with the long-poll loop. Returns the session for the caller (typically
// the SOCKS adapter) to wrap in a VirtualConn.
func (c *Client) NewSession(target string) *session.Session {
	var id [frame.SessionIDLen]byte
	if _, err := rand.Read(id[:]); err != nil {
		// crypto/rand failure is unrecoverable; panic so the process exits
		// rather than emitting an all-zero ID.
		panic(fmt.Errorf("crypto/rand: %w", err))
	}
	s := session.New(id, target, true)
	s.OnTx = c.kick
	c.mu.Lock()
	c.sessions[id] = s
	c.mu.Unlock()
	c.kick()
	return s
}

// Run drives the poll loop until ctx is canceled.
func (c *Client) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		didWork := c.pollOnce(ctx)
		c.gcDoneSessions()
		if !didWork {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-c.kickCh:
				// woken by EnqueueTx
			case <-time.After(pollIdleSleep):
			}
		}
	}
}

// pollOnce drains pending tx frames, POSTs them as a batch, and routes any
// response frames back to their sessions. Returns true if any work was done
// (frames sent or received) so the Run loop can decide whether to sleep.
func (c *Client) pollOnce(ctx context.Context) bool {
	frames := c.drainAll()

	body, err := frame.EncodeBatch(c.aead, frames)
	if err != nil {
		log.Printf("[carrier] failed to prepare encrypted request batch: %v", err)
		return false
	}

	maxAttempts := 1
	if len(c.endpoints) > 1 {
		// One same-poll failover attempt keeps drained TX payload from being lost
		// when one deployment intermittently fails under quota pressure.
		maxAttempts = 2
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		endpointIdx, scriptURL := c.pickRelayEndpoint()
		if endpointIdx < 0 || scriptURL == "" {
			log.Printf("[carrier] no relay script URLs are configured")
			return false
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, scriptURL, bytes.NewReader(body))
		if err != nil {
			log.Printf("[carrier] failed to build relay request: %v", err)
			return false
		}
		req.Header.Set("Content-Type", "text/plain")

		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return false
			}
			c.markEndpointFailure(endpointIdx)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay request failed via %s (attempt %d/%d): %v; retrying alternate script", shortScriptKey(scriptURL), attempt, maxAttempts, err)
				continue
			}
			log.Printf("[carrier] relay request failed via %s: %v (check internet access, script_key/script_keys, and google_host)", shortScriptKey(scriptURL), err)
			time.Sleep(time.Second) // back off on transport errors
			return false
		}

		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			c.markEndpointFailure(endpointIdx)
			if attempt < maxAttempts {
				log.Printf("[carrier] failed to read relay response via %s (attempt %d/%d): %v; retrying alternate script", shortScriptKey(scriptURL), attempt, maxAttempts, readErr)
				continue
			}
			log.Printf("[carrier] failed to read relay response: %v", readErr)
			return false
		}

		if resp.StatusCode == http.StatusNoContent || len(respBody) == 0 {
			c.markEndpointSuccess(endpointIdx)
			return len(frames) > 0
		}
		if resp.StatusCode != http.StatusOK {
			c.markEndpointFailure(endpointIdx)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay returned HTTP %d via %s (attempt %d/%d); retrying alternate script", resp.StatusCode, shortScriptKey(scriptURL), attempt, maxAttempts)
				continue
			}
			log.Printf("[carrier] relay returned HTTP %d via %s (verify Apps Script deployment is live and access is set to Anyone)", resp.StatusCode, shortScriptKey(scriptURL))
			return false
		}
		if len(respBody) > maxRelayResponseBodyBytes {
			c.markEndpointFailure(endpointIdx)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay response too large via %s (attempt %d/%d); retrying alternate script", shortScriptKey(scriptURL), attempt, maxAttempts)
				continue
			}
			log.Printf("[carrier] relay response too large via %s (%d bytes > %d); dropping batch to protect stability", shortScriptKey(scriptURL), len(respBody), maxRelayResponseBodyBytes)
			return len(frames) > 0
		}
		if isLikelyNonBatchRelayPayload(respBody) {
			c.markEndpointFailure(endpointIdx)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay returned non-batch payload via %s (attempt %d/%d); retrying alternate script", shortScriptKey(scriptURL), attempt, maxAttempts)
				continue
			}
			log.Printf("[carrier] relay returned non-batch payload via %s (likely HTML/JSON error page), dropping response", shortScriptKey(scriptURL))
			return len(frames) > 0
		}

		rxFrames, decodeErr := frame.DecodeBatch(c.aead, respBody)
		if decodeErr != nil {
			c.markEndpointFailure(endpointIdx)
			if attempt < maxAttempts {
				log.Printf("[carrier] relay response was invalid via %s (attempt %d/%d): %v; retrying alternate script", shortScriptKey(scriptURL), attempt, maxAttempts, decodeErr)
				continue
			}
			log.Printf("[carrier] relay response was invalid via %s (possibly HTML/error page instead of encrypted data): %v", shortScriptKey(scriptURL), decodeErr)
			return len(frames) > 0
		}

		for _, f := range rxFrames {
			c.routeRx(f)
		}
		c.markEndpointSuccess(endpointIdx)
		return len(frames) > 0 || len(rxFrames) > 0
	}

	return false
}

func (c *Client) pickRelayEndpoint() (int, string) {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()

	n := len(c.endpoints)
	if n == 0 {
		return -1, ""
	}
	now := time.Now()
	start := c.nextEndpoint % n
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		ep := c.endpoints[idx]
		if !ep.blacklistedTill.After(now) {
			c.nextEndpoint = (idx + 1) % n
			return idx, ep.url
		}
	}

	chosen := 0
	soonest := c.endpoints[0].blacklistedTill
	for i := 1; i < n; i++ {
		if c.endpoints[i].blacklistedTill.Before(soonest) {
			chosen = i
			soonest = c.endpoints[i].blacklistedTill
		}
	}
	c.nextEndpoint = (chosen + 1) % n
	return chosen, c.endpoints[chosen].url
}

func (c *Client) markEndpointSuccess(endpointIdx int) {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if endpointIdx < 0 || endpointIdx >= len(c.endpoints) {
		return
	}
	c.endpoints[endpointIdx].failCount = 0
	c.endpoints[endpointIdx].blacklistedTill = time.Time{}
}

func (c *Client) markEndpointFailure(endpointIdx int) {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if endpointIdx < 0 || endpointIdx >= len(c.endpoints) {
		return
	}
	ep := &c.endpoints[endpointIdx]
	ep.failCount++
	step := ep.failCount - 1
	if step > endpointBlacklistMaxStep {
		step = endpointBlacklistMaxStep
	}
	ttl := endpointBlacklistBaseTTL << step
	if ttl > endpointBlacklistMaxTTL {
		ttl = endpointBlacklistMaxTTL
	}
	ep.blacklistedTill = time.Now().Add(ttl)
}

func (c *Client) drainAll() []*frame.Frame {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*frame.Frame
	batchCap := maxDrainFramesPerBatch
	if len(c.sessions) >= busySessionThreshold {
		batchCap = maxDrainFramesPerBatchBusy
	}
	remaining := batchCap
	for _, s := range c.sessions {
		if remaining <= 0 {
			break
		}
		perSessionCap := maxDrainFramesPerSession
		if remaining < perSessionCap {
			perSessionCap = remaining
		}
		frames := s.DrainTxLimited(MaxFramePayload, perSessionCap)
		out = append(out, frames...)
		remaining -= len(frames)
	}
	return out
}

func (c *Client) routeRx(f *frame.Frame) {
	c.mu.Lock()
	s, ok := c.sessions[f.SessionID]
	c.mu.Unlock()
	if !ok {
		return // unknown session - drop
	}
	s.ProcessRx(f)
}

func (c *Client) gcDoneSessions() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, s := range c.sessions {
		if s.IsDone() {
			delete(c.sessions, id)
		}
	}
}

// kick wakes the poll loop. Safe to call from any goroutine; coalesces.
func (c *Client) kick() {
	select {
	case c.kickCh <- struct{}{}:
	default:
	}
}

func isLikelyNonBatchRelayPayload(body []byte) bool {
	t := bytes.TrimSpace(body)
	if len(t) == 0 {
		return false
	}
	l := bytes.ToLower(t)
	if bytes.HasPrefix(l, []byte("<!doctype")) || bytes.HasPrefix(l, []byte("<html")) {
		return true
	}
	// Base64 batches never begin with JSON object/array delimiters or raw HTTP.
	if t[0] == '{' || t[0] == '[' || bytes.HasPrefix(t, []byte("HTTP/")) {
		return true
	}
	return false
}

func shortScriptKey(scriptURL string) string {
	parts := strings.Split(strings.Trim(scriptURL, "/"), "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "s" {
			id := parts[i+1]
			if len(id) > 14 {
				return id[:6] + "..." + id[len(id)-6:]
			}
			return id
		}
	}
	return "(unknown)"
}
