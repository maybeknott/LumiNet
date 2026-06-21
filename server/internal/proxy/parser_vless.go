package proxy

import (
	"fmt"
	"net/url"
	"strings"
)

// parseVLESS parses a vless:// URI into a ProxyConfig.
// Format: vless://<uuid>@<host>:<port>?type=<transport>&security=<tls>&sni=<sni>&flow=<flow>#<name>
func parseVLESS(uri string) (*ProxyConfig, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	uuidStr := parsed.User.Username()
	if uuidStr == "" {
		// Fallback to parse from userinfo manually if user was nil
		if parsed.User != nil {
			uuidStr = parsed.User.String()
		} else {
			parts := strings.Split(parsed.Opaque, "@")
			if len(parts) > 0 {
				uuidStr = parts[0]
			}
		}
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

	security := strings.ToLower(q.Get("security"))
	if security == "" {
		security = "none"
	}

	alpnStr := q.Get("alpn")
	var alpn []string
	if alpnStr != "" {
		alpn = strings.Split(alpnStr, ",")
	}

	remark, _ := url.PathUnescape(parsed.Fragment)

	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing server address")
	}
	if uuidStr == "" {
		return nil, fmt.Errorf("missing user ID (uuid)")
	}

	serviceName := q.Get("serviceName")
	if serviceName == "" {
		serviceName = q.Get("service_name")
	}

	fragmentVal := q.Get("fragment")
	var fragPackets, fragLength, fragInterval string
	if fragmentVal != "" {
		parts := strings.Split(fragmentVal, ",")
		if len(parts) > 0 {
			fragLength = parts[0]
		}
		if len(parts) > 1 {
			fragInterval = parts[1]
		}
		if len(parts) > 2 {
			fragPackets = parts[2]
		}
	}
	if q.Get("fragment_length") != "" {
		fragLength = q.Get("fragment_length")
	}
	if q.Get("fragment_interval") != "" {
		fragInterval = q.Get("fragment_interval")
	}
	if q.Get("fragment_packets") != "" {
		fragPackets = q.Get("fragment_packets")
	}

	return &ProxyConfig{
		Protocol:         ProtocolVLESS,
		Name:             remark,
		Address:          host,
		Port:             port,
		UUID:             uuidStr,
		Transport:        transport,
		TLS:              security == "tls" || security == "reality",
		Security:         security, // reality or tls
		SNI:              q.Get("sni"),
		Path:             q.Get("path"),
		Host:             q.Get("host"),
		ServiceName:      serviceName,
		Authority:        q.Get("authority"),
		MultiMode:        q.Get("multiMode") == "true" || q.Get("multimode") == "true",
		Flow:             q.Get("flow"),
		Fingerprint:      q.Get("fp"),
		PublicKey:        q.Get("pbk"),
		ShortID:          q.Get("sid"),
		ALPN:             alpn,
		SkipCertVerify:   q.Get("allowinsecure") == "1" || q.Get("allowinsecure") == "true",
		FragmentPackets:  fragPackets,
		FragmentLength:   fragLength,
		FragmentInterval: fragInterval,
	}, nil
}

// ExtractRealityParams extracts XTLS Reality configuration options from a parsed VLESS URL.
func ExtractRealityParams(u *url.URL, config map[string]interface{}) {
	q := u.Query()
	if q.Get("security") == "reality" {
		tlsConfig := map[string]interface{}{
			"enabled":     true,
			"server_name": q.Get("sni"),
			"reality": map[string]interface{}{
				"enabled":    true,
				"public_key": q.Get("pbk"),
				"short_id":   q.Get("sid"),
			},
		}
		config["tls"] = tlsConfig
	}
}

