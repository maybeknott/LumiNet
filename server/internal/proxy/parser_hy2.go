package proxy

import (
	"fmt"
	"net/url"
	"strings"
)

// parseHysteria2 parses a hysteria2:// or hy2:// URI into a ProxyConfig.
func parseHysteria2(uri string) (*ProxyConfig, error) {
	// Standardize schema
	normalized := uri
	if strings.HasPrefix(strings.ToLower(uri), "hy2://") {
		normalized = "hysteria2" + uri[3:]
	}

	parsed, err := url.Parse(normalized)
	if err != nil {
		return nil, err
	}

	password := parsed.User.Username()
	if password == "" {
		if parsed.User != nil {
			password = parsed.User.String()
		}
	}

	port := 443
	if parsed.Port() != "" {
		fmt.Sscanf(parsed.Port(), "%d", &port)
	}

	q := parsed.Query()
	remark, _ := url.PathUnescape(parsed.Fragment)

	upMbps := 0
	downMbps := 0
	fmt.Sscanf(q.Get("up"), "%d", &upMbps)
	fmt.Sscanf(q.Get("down"), "%d", &downMbps)

	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing server address")
	}
	if password == "" {
		return nil, fmt.Errorf("missing password")
	}

	return &ProxyConfig{
		Protocol:    ProtocolHysteria2,
		Name:        remark,
		Address:     host,
		Port:        port,
		Password:    password,
		TLS:         true,
		SNI:         q.Get("sni"),
		Obfuscation: q.Get("obfs-password"),
		UpMbps:      upMbps,
		DownMbps:    downMbps,
	}, nil
}
