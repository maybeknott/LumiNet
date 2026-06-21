package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// nipoProfile represents the JSON structure inside a nipovpn:// base64 payload.
type nipoProfile struct {
	Name   string     `json:"name"`
	Config nipoConfig `json:"config"`
}

type nipoConfig struct {
	Token           string `json:"token"`
	Protocol        string `json:"protocol"`
	FakeUrls        string `json:"fakeUrls"`
	Methods         string `json:"methods"`
	EndPoints       string `json:"endPoints"`
	Timeout         string `json:"timeout"`
	PullTimeout     string `json:"pullTimeout"`
	TunnelEnable    bool   `json:"tunnelEnable"`
	ConnectionReuse bool   `json:"connectionReuse"`
	TlsEnable       bool   `json:"tlsEnable"`
	TlsVerifyPeer   bool   `json:"tlsVerifyPeer"`
	TlsCertFile     string `json:"tlsCertFile"`
	TlsKeyFile      string `json:"tlsKeyFile"`
	TlsCaFile       string `json:"tlsCaFile"`
	LogLevel        string `json:"logLevel"`
	ServerIp        string `json:"serverIp"`
	ServerPort      string `json:"serverPort"`
	HttpVersion     string `json:"httpVersion"`
	UserAgent       string `json:"userAgent"`
}

// parseNipo parses a nipovpn:// link into a ProxyConfig.
func parseNipo(uri string) (*ProxyConfig, error) {
	if !strings.HasPrefix(strings.ToLower(uri), "nipovpn://") {
		return nil, fmt.Errorf("invalid nipovpn scheme")
	}

	payload := uri[10:]
	payload = strings.TrimSpace(payload)

	// Strip remarks if any (Nipo link shouldn't have them in theory, but support it anyway)
	if idx := strings.Index(payload, "#"); idx != -1 {
		payload = payload[:idx]
	}

	// Base64 decode (try standard then URL-safe)
	padLen := (4 - (len(payload) % 4)) % 4
	padded := payload + strings.Repeat("=", padLen)

	var decoded []byte
	var err error
	decoded, err = base64.StdEncoding.DecodeString(padded)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(padded)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(payload)
			if err != nil {
				decoded, err = base64.RawURLEncoding.DecodeString(payload)
				if err != nil {
					return nil, fmt.Errorf("failed to decode base64 nipo payload: %w", err)
				}
			}
		}
	}

	var profile nipoProfile
	if err := json.Unmarshal(decoded, &profile); err != nil {
		return nil, fmt.Errorf("failed to parse Nipo profile JSON: %w", err)
	}

	cfg := profile.Config
	if cfg.ServerIp == "" {
		return nil, fmt.Errorf("missing serverIp in Nipo config")
	}

	var port int = 443
	if cfg.ServerPort != "" {
		fmt.Sscanf(cfg.ServerPort, "%d", &port)
	}

	// Extract primary Host/SNI from comma/newline separated fakeUrls list
	var sni, host string
	if cfg.FakeUrls != "" {
		urls := strings.FieldsFunc(cfg.FakeUrls, func(r rune) bool {
			return r == '\n' || r == ',' || r == ';'
		})
		if len(urls) > 0 {
			host = strings.TrimSpace(urls[0])
			sni = host
		}
	}

	// Extract path from endPoints
	var path string
	if cfg.EndPoints != "" {
		endpoints := strings.FieldsFunc(cfg.EndPoints, func(r rune) bool {
			return r == '\n' || r == ',' || r == ';'
		})
		if len(endpoints) > 0 {
			path = "/" + strings.TrimSpace(endpoints[0])
		}
	}

	name := profile.Name
	if name == "" {
		name = "NipoVPN Profile"
	}

	return &ProxyConfig{
		Protocol:  ProtocolNipo,
		Name:      name,
		Address:   cfg.ServerIp,
		Port:      port,
		Password:  cfg.Token,
		TLS:       cfg.TlsEnable,
		SNI:       sni,
		Host:      host,
		Path:      path,
		Transport: cfg.Protocol, // socks5 or http
	}, nil
}
