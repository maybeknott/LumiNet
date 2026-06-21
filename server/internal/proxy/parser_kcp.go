package proxy

import (
	"fmt"
	"net/url"
	"strconv"
)

// parseKCP parses a kcp:// URI into a ProxyConfig.
func parseKCP(uri string) (*ProxyConfig, error) {
	parsed, err := url.Parse(uri)
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

	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing server address")
	}
	if password == "" {
		return nil, fmt.Errorf("missing password")
	}

	config := &ProxyConfig{
		Protocol:   ProtocolKCP,
		Name:       remark,
		Address:    host,
		Port:       port,
		Password:   password,
		Method:     q.Get("crypt"),
		KCPProfile: q.Get("profile"),
	}

	if q.Get("nodelay") != "" {
		config.KCPNoDelay, _ = strconv.Atoi(q.Get("nodelay"))
	}
	if q.Get("interval") != "" {
		config.KCPInterval, _ = strconv.Atoi(q.Get("interval"))
	}
	if q.Get("resend") != "" {
		config.KCPResend, _ = strconv.Atoi(q.Get("resend"))
	}
	if q.Get("nc") != "" {
		config.KCPNoCongestion, _ = strconv.Atoi(q.Get("nc"))
	}
	if q.Get("sndwnd") != "" {
		config.KCPSendWindow, _ = strconv.Atoi(q.Get("sndwnd"))
	}
	if q.Get("rcvwnd") != "" {
		config.KCPReceiveWindow, _ = strconv.Atoi(q.Get("rcvwnd"))
	}
	if q.Get("mtu") != "" {
		config.KCPMTU, _ = strconv.Atoi(q.Get("mtu"))
	}
	if q.Get("compression") != "" {
		config.KCPCompression = q.Get("compression")
	}
	if q.Get("jitter") == "true" || q.Get("jitter") == "1" {
		config.KCPJitter = true
	}
	if q.Get("jitter_min") != "" {
		config.KCPJitterMin, _ = strconv.Atoi(q.Get("jitter_min"))
	}
	if q.Get("jitter_max") != "" {
		config.KCPJitterMax, _ = strconv.Atoi(q.Get("jitter_max"))
	}

	return config, nil
}
