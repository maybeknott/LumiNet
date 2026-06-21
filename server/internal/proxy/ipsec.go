package proxy

import "fmt"

// IpsecOutbound represents the structure for configuring an L2TP/IPSec VPN connection.
type IpsecOutbound struct {
	Server   string `json:"server"`
	Username string `json:"username"`
	Password string `json:"password"`
	Secret   string `json:"psk"`
}

// GenerateIpsecConfig returns a standard outbound configuration map for IPSec.
func GenerateIpsecConfig(cfg IpsecOutbound) (map[string]interface{}, error) {
	if cfg.Server == "" {
		return nil, fmt.Errorf("missing server IP or domain")
	}
	if cfg.Username == "" || cfg.Password == "" {
		return nil, fmt.Errorf("missing authentication credentials")
	}

	return map[string]interface{}{
		"type":       "ipsec",
		"server":     cfg.Server,
		"username":   cfg.Username,
		"password":   cfg.Password,
		"ipsec_psk":  cfg.Secret,
		"tag":        "vpn-outbound",
	}, nil
}
