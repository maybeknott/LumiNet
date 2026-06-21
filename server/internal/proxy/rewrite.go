package proxy

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// RewriteProxyURI swaps the address (server) and optionally the port/name of a proxy URI.
// It preserves critical attributes like TLS SNI and WebSocket Host headers by setting
// them to the original server domain name if they were empty.
func RewriteProxyURI(rawURI, newHost string, newPort int, newName string) (string, error) {
	cfg, err := ParseProxyURI(rawURI)
	if err != nil {
		return "", err
	}

	// If the original address is a domain name (not an IP literal), and SNI/Host are empty,
	// preserve the domain name in SNI/Host before changing the Address to the clean IP.
	originalAddressIsDomain := net.ParseIP(cfg.Address) == nil
	if originalAddressIsDomain {
		if cfg.TLS && cfg.SNI == "" {
			cfg.SNI = cfg.Address
		}
		if cfg.Host == "" {
			cfg.Host = cfg.Address
		}
	}

	cfg.Address = newHost
	if newPort > 0 {
		cfg.Port = newPort
	}

	if newName != "" {
		cfg.Name = newName
	}

	return cfg.ToURI(), nil
}

// RewriteSubscriptionContent parses a block of subscription URIs (newline-separated)
// and rewrites each URI with each of the provided clean IPs.
func RewriteSubscriptionContent(content string, cleanIPs []string, newPort int, newNameTpl string) ([]string, error) {
	configs, err := ParseSubscriptionContent(content)
	if err != nil {
		return nil, err
	}

	var rewritten []string
	for _, cfg := range configs {
		for i, ip := range cleanIPs {
			name := cfg.Name
			if newNameTpl != "" {
				// Support simple template replacements, e.g. "{name} | {ip}" or "{name} [{idx}]"
				r := strings.NewReplacer(
					"{name}", cfg.Name,
					"{ip}", ip,
					"{idx}", strconv.Itoa(i+1),
				)
				name = r.Replace(newNameTpl)
			}

			// Generate the rewritten URI
			cfgCopy := *cfg
			originalAddressIsDomain := net.ParseIP(cfgCopy.Address) == nil
			if originalAddressIsDomain {
				if cfgCopy.TLS && cfgCopy.SNI == "" {
					cfgCopy.SNI = cfgCopy.Address
				}
				if cfgCopy.Host == "" {
					cfgCopy.Host = cfgCopy.Address
				}
			}

			cfgCopy.Address = ip
			if newPort > 0 {
				cfgCopy.Port = newPort
			}
			cfgCopy.Name = name

			rewritten = append(rewritten, cfgCopy.ToURI())
		}
	}

	return rewritten, nil
}

// Helper to check if a string is a valid IP address.
func isIP(s string) bool {
	return net.ParseIP(strings.TrimSpace(s)) != nil
}

// parseURL parses a raw URI string.
func parseURL(raw string) (*url.URL, error) {
	return url.Parse(raw)
}
