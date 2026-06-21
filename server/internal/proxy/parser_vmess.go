package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// parseVMess parses a vmess:// URI into a ProxyConfig.
func parseVMess(uri string) (*ProxyConfig, error) {
	b64 := uri[8:]
	b64 = strings.TrimSpace(b64)
	var remark string
	if idx := strings.Index(b64, "#"); idx != -1 {
		remark = b64[idx+1:]
		b64 = b64[:idx]
	}

	padLen := (4 - (len(b64) % 4)) % 4
	padded := b64 + strings.Repeat("=", padLen)

	var decoded []byte
	var err error

	decoded, err = base64.StdEncoding.DecodeString(padded)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(padded)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(b64)
			if err != nil {
				decoded, err = base64.RawURLEncoding.DecodeString(b64)
				if err != nil {
					return nil, fmt.Errorf("failed to decode base64 VMess: %w", err)
				}
			}
		}
	}

	var vmess struct {
		V    interface{} `json:"v"`
		Ps   string      `json:"ps"`
		Add  string      `json:"add"`
		Port interface{} `json:"port"`
		Id   string      `json:"id"`
		Aid  interface{} `json:"aid"`
		Scy  string      `json:"scy"`
		Net  string      `json:"net"`
		Type string      `json:"type"`
		Host string      `json:"host"`
		Path string      `json:"path"`
		Tls  string      `json:"tls"`
		Sni  string      `json:"sni"`
	}

	if err := json.Unmarshal(decoded, &vmess); err != nil {
		return nil, fmt.Errorf("failed to parse VMess JSON: %w", err)
	}

	port := 443
	switch p := vmess.Port.(type) {
	case float64:
		port = int(p)
	case string:
		fmt.Sscanf(p, "%d", &port)
	}

	alterID := 0
	switch a := vmess.Aid.(type) {
	case float64:
		alterID = int(a)
	case string:
		fmt.Sscanf(a, "%d", &alterID)
	}

	if vmess.Add == "" {
		return nil, fmt.Errorf("missing server address")
	}
	if vmess.Id == "" {
		return nil, fmt.Errorf("missing user ID (uuid)")
	}

	name := vmess.Ps
	if name == "" {
		name = remark
	}

	return &ProxyConfig{
		Protocol:  ProtocolVMess,
		Name:      name,
		Address:   vmess.Add,
		Port:      port,
		UUID:      vmess.Id,
		AlterID:   alterID,
		Security:  vmess.Scy,
		Transport: vmess.Net,
		Host:      vmess.Host,
		Path:      vmess.Path,
		TLS:       vmess.Tls == "tls",
		SNI:       vmess.Sni,
	}, nil
}
