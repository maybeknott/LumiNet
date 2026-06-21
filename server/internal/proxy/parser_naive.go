package proxy

import (
	"fmt"
	"net/url"
	"strings"
)

// parseNaive parses a naive:// or naive+https:// URI into a ProxyConfig.
func parseNaive(uri string) (*ProxyConfig, error) {
	normalized := uri
	if strings.HasPrefix(strings.ToLower(uri), "naive+https://") {
		normalized = "naive" + uri[11:]
	}

	parsed, err := url.Parse(normalized)
	if err != nil {
		return nil, err
	}

	username := parsed.User.Username()
	var password string
	if parsed.User != nil {
		password, _ = parsed.User.Password()
		if username == "" {
			username = parsed.User.String()
		}
	}

	port := 443
	if parsed.Port() != "" {
		fmt.Sscanf(parsed.Port(), "%d", &port)
	}

	q := parsed.Query()
	remark, _ := url.PathUnescape(parsed.Fragment)

	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing server address")
	}
	if username == "" || password == "" {
		return nil, fmt.Errorf("missing username or password")
	}

	return &ProxyConfig{
		Protocol: ProtocolNaive,
		Name:     remark,
		Address:  host,
		Port:     port,
		UUID:     username, // Store username in UUID field
		Password: password,
		TLS:      true,
		SNI:      q.Get("sni"),
	}, nil
}
