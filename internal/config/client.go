// Package config defines the JSON config structures for the client and server
// binaries.
package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Client is the relay-tunnel client config.
type Client struct {
	ListenAddr string
	GoogleIP   string   // "ip:port"
	SNIHost    string   // e.g. "www.google.com"
	ScriptURLs []string // one or more https://script.google.com/macros/s/.../exec URLs
	AESKeyHex  string   // 64-char hex
}

// clientFile is the user-friendly client config format.
type clientFile struct {
	// Local SOCKS listener.
	SocksHost string `json:"socks_host"`
	SocksPort int    `json:"socks_port"`

	// Google front endpoint.
	GoogleHost string `json:"google_host"`

	// TLS SNI.
	SNI string `json:"sni"`

	// Apps Script deployment key only.
	ScriptKey  string   `json:"script_key"`
	ScriptKeys []string `json:"script_keys"`

	// Shared AES key (64-char hex).
	TunnelKey string `json:"tunnel_key"`
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}

func firstPositive(values ...int) int {
	for _, v := range values {
		if v > 0 {
			return v
		}
	}
	return 0
}

func normalizeDeploymentID(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	// Accept plain deployment key and tolerate pasting the full /exec URL.
	v = strings.TrimSuffix(v, "/exec")
	v = strings.Trim(v, "/")
	parts := strings.Split(v, "/")
	if len(parts) >= 2 {
		for i := 0; i < len(parts)-1; i++ {
			if parts[i] == "s" {
				return parts[i+1]
			}
		}
	}
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return v
}

func buildScriptURL(deploymentID string) string {
	return fmt.Sprintf("https://script.google.com/macros/s/%s/exec", deploymentID)
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// LoadClient reads and validates a client config file.
func LoadClient(path string) (*Client, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	var f clientFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	listenHost := firstNonEmpty(f.SocksHost, "127.0.0.1")
	listenPort := firstPositive(f.SocksPort)
	if listenPort == 0 {
		listenPort = 1080
	}
	if listenPort < 1 || listenPort > 65535 {
		return nil, fmt.Errorf("config: socks_port out of range (got %d)", listenPort)
	}

	googleHost := firstNonEmpty(f.GoogleHost, "216.239.38.120")
	googlePort := 443

	deploymentIDs := make([]string, 0, 1+len(f.ScriptKeys))
	if deploymentID := normalizeDeploymentID(f.ScriptKey); deploymentID != "" {
		deploymentIDs = append(deploymentIDs, deploymentID)
	}
	for _, raw := range f.ScriptKeys {
		if deploymentID := normalizeDeploymentID(raw); deploymentID != "" {
			deploymentIDs = append(deploymentIDs, deploymentID)
		}
	}
	deploymentIDs = dedupeStrings(deploymentIDs)
	if len(deploymentIDs) == 0 {
		return nil, fmt.Errorf("config: script_key or script_keys is required")
	}

	key := strings.TrimSpace(f.TunnelKey)
	if len(key) != 64 {
		return nil, fmt.Errorf("config: tunnel_key must be 64 hex chars (got %d)", len(key))
	}
	raw, err := hex.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("config: tunnel_key must be valid 64-char hex AES-256 key")
	}

	scriptURLs := make([]string, 0, len(deploymentIDs))
	for _, deploymentID := range deploymentIDs {
		scriptURLs = append(scriptURLs, buildScriptURL(deploymentID))
	}

	c := Client{
		ListenAddr: net.JoinHostPort(listenHost, strconv.Itoa(listenPort)),
		GoogleIP:   net.JoinHostPort(googleHost, strconv.Itoa(googlePort)),
		SNIHost:    firstNonEmpty(f.SNI, "www.google.com"),
		ScriptURLs: scriptURLs,
		AESKeyHex:  key,
	}
	return &c, nil
}
