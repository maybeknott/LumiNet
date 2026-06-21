package proxy

import (
	"fmt"
	"net/url"
	"strings"
)

// parseDNSTT parses a dnstt:// URI into a ProxyConfig.
func parseDNSTT(uri string) (*ProxyConfig, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	q := parsed.Query()
	publicKey := q.Get("publicKey")
	if publicKey == "" {
		publicKey = q.Get("public_key")
	}

	domain := q.Get("domain")
	if domain == "" {
		domain = parsed.Host
	}

	var resolvers []string
	// Support multiple resolver query params
	for _, val := range q["resolver"] {
		resolvers = append(resolvers, val)
	}
	if len(resolvers) == 0 {
		for _, val := range q["resolvers"] {
			resolvers = append(resolvers, strings.Split(val, ",")...)
		}
	}

	tunnelPerResolver := 4
	if val := q.Get("tunnel_per_resolver"); val != "" {
		fmt.Sscanf(val, "%d", &tunnelPerResolver)
	}

	udpOverTCP := true
	if val := q.Get("udp_over_tcp"); val != "" {
		udpOverTCP = val == "true" || val == "1"
	}

	remark, _ := url.PathUnescape(parsed.Fragment)

	return &ProxyConfig{
		Protocol:          ProtocolDNSTT,
		Name:              remark,
		Address:           domain,
		Port:              53,
		PublicKey:         publicKey,
		Resolvers:         resolvers,
		TunnelPerResolver: tunnelPerResolver,
		UDPOverTCP:        udpOverTCP,
	}, nil
}
