package proxy

import (
	"fmt"
	"net/url"
)

// parseTrojan parses a trojan:// URI into a ProxyConfig.
// Format: trojan://<password>@<host>:<port>?sni=<sni>&type=<transport>#<name>
func parseTrojan(uri string) (*ProxyConfig, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	password := parsed.User.Username()
	if password == "" && parsed.User != nil {
		password = parsed.User.String()
	}

	port := 443
	if parsed.Port() != "" {
		fmt.Sscanf(parsed.Port(), "%d", &port)
	}

	q := parsed.Query()
	transport := q.Get("type")
	if transport == "" {
		transport = "tcp"
	}

	remark, _ := url.PathUnescape(parsed.Fragment)

	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing server address")
	}
	if password == "" {
		return nil, fmt.Errorf("missing password")
	}

	return &ProxyConfig{
		Protocol:  ProtocolTrojan,
		Name:      remark,
		Address:   host,
		Port:      port,
		Password:  password,
		Transport: transport,
		TLS:       true, // Trojan always TLS/SSL in standard formats
		SNI:       q.Get("sni"),
		Path:      q.Get("path"),
		Host:      q.Get("host"),
	}, nil
}
