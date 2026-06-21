package proxy

import (
	"fmt"
	"net/url"
)

// parseTUIC parses a tuic:// URI into a ProxyConfig.
func parseTUIC(uri string) (*ProxyConfig, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	uuidStr := parsed.User.Username()
	var password string
	if parsed.User != nil {
		password, _ = parsed.User.Password()
		if uuidStr == "" {
			uuidStr = parsed.User.String()
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
	if uuidStr == "" || password == "" {
		return nil, fmt.Errorf("missing UUID or password")
	}

	return &ProxyConfig{
		Protocol:          ProtocolTUIC,
		Name:              remark,
		Address:           host,
		Port:              port,
		UUID:              uuidStr,
		Password:          password,
		TLS:               true,
		SNI:               q.Get("sni"),
		CongestionControl: q.Get("congestion_control"),
		UDPRelayMode:      q.Get("udp_relay_mode"),
	}, nil
}
