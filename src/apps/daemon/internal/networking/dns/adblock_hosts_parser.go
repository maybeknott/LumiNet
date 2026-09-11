package dns

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

var (
	domainRegex   = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)
	wildcardRegex = regexp.MustCompile(`[*?]`)
	ipv4Regex     = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}$`)
)

var hostsPrefixes = map[string]bool{
	"0.0.0.0":   true,
	"127.0.0.1": true,
	"::1":       true,
	"::0":       true,
}

var skipNames = map[string]bool{
	"localhost":             true,
	"local":                 true,
	"broadcasthost":         true,
	"localhost.localdomain": true,
	"ip6-localhost":         true,
	"ip6-loopback":          true,
}

// ParseHostsText parses hosts file content into a slice of unique blocked domain names.
func ParseHostsText(text string) []string {
	return ParseHostsReader(strings.NewReader(text))
}

// ParseHostsReader streams lines from an io.Reader, extracting valid blocked domains.
func ParseHostsReader(r io.Reader) []string {
	scanner := bufio.NewScanner(r)
	seen := make(map[string]bool)
	var domains []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle inline comments: "127.0.0.1 bad.com # tracker"
		if idx := strings.Index(line, " #"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		} else if idx := strings.Index(line, "\t#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		fields := strings.Fields(line)
		var domain string

		switch len(fields) {
		case 1:
			// Plain domain per line format
			domain = strings.TrimSuffix(strings.ToLower(fields[0]), ".")
		case 2:
			// Standard hosts entry format: <ip> <domain>
			if hostsPrefixes[fields[0]] {
				domain = strings.TrimSuffix(strings.ToLower(fields[1]), ".")
			} else {
				continue
			}
		default:
			// If line is: 0.0.0.0 domain1 domain2 domain3
			if len(fields) > 2 && hostsPrefixes[fields[0]] {
				for _, f := range fields[1:] {
					d := strings.TrimSuffix(strings.ToLower(f), ".")
					if isValidAdblockDomain(d) && !seen[d] {
						seen[d] = true
						domains = append(domains, d)
					}
				}
				continue
			}
			continue
		}

		if isValidAdblockDomain(domain) && !seen[domain] {
			seen[domain] = true
			domains = append(domains, domain)
		}
	}

	return domains
}

func isValidAdblockDomain(d string) bool {
	if d == "" || wildcardRegex.MatchString(d) || skipNames[d] {
		return false
	}
	if ipv4Regex.MatchString(d) || strings.Contains(d, ":") {
		return false
	}
	return domainRegex.MatchString(d)
}

// MergeHostsBlocklists aggregates multiple domain lists and deduplicates them preserving order.
func MergeHostsBlocklists(lists ...[]string) []string {
	seen := make(map[string]bool)
	var merged []string
	for _, list := range lists {
		for _, domain := range list {
			norm := strings.ToLower(strings.TrimSpace(domain))
			if norm != "" && !seen[norm] {
				seen[norm] = true
				merged = append(merged, norm)
			}
		}
	}
	return merged
}
