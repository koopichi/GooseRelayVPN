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

// Server is the DO exit server config.
type Server struct {
	ListenAddr string
	AESKeyHex  string
}

type serverFile struct {
	// New user-friendly keys.
	ServerHost string `json:"server_host"`
	ServerPort int    `json:"server_port"`
	TunnelKey  string `json:"tunnel_key"`

	// Legacy keys kept as fallback for existing deployments.
	ListenAddr string `json:"listen_addr"`
	AESKeyHex  string `json:"aes_key_hex"`
}

func parseLegacyListenAddr(addr string) (string, int) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", 0
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0
	}
	return strings.TrimSpace(host), port
}

// LoadServer reads and validates a server config file.
func LoadServer(path string) (*Server, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var f serverFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	legacyHost, legacyPort := parseLegacyListenAddr(f.ListenAddr)
	listenHost := firstNonEmpty(f.ServerHost, legacyHost, "0.0.0.0")
	listenPort := firstPositive(f.ServerPort, legacyPort)
	if listenPort == 0 {
		listenPort = 8443
	}
	if listenPort < 1 || listenPort > 65535 {
		return nil, fmt.Errorf("config: server_port out of range (got %d)", listenPort)
	}

	key := strings.TrimSpace(firstNonEmpty(f.TunnelKey, f.AESKeyHex))
	if len(key) != 64 {
		return nil, fmt.Errorf("config: tunnel_key must be 64 hex chars (got %d)", len(key))
	}
	raw, err := hex.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("config: tunnel_key must be valid 64-char hex AES-256 key")
	}

	c := Server{
		ListenAddr: net.JoinHostPort(listenHost, strconv.Itoa(listenPort)),
		AESKeyHex:  key,
	}
	return &c, nil
}
