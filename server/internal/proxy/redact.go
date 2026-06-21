package proxy

import (
	"fmt"
	"net/url"
	"strings"
)

// URITransportPreview returns a single-line proxy preview without credentials,
// full opaque payloads, or long subscription fragments.
func URITransportPreview(raw string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 72
	}
	value := strings.TrimSpace(raw)
	if value == "" {
		return "(empty)"
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "sb://") || strings.HasPrefix(lower, "vmess://") || strings.HasPrefix(lower, "ssr://") {
		return shortSuffix(fmt.Sprintf("%s...(%d chars)", value[:strings.Index(value, "://")+3], len(value)), maxLen)
	}
	if !strings.Contains(value, "://") {
		return shortSuffix(value, maxLen)
	}

	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" {
		return shortSuffix(value, maxLen)
	}
	host := parsed.Host
	if host == "" && parsed.Opaque != "" {
		host = strings.SplitN(parsed.Opaque, "/", 2)[0]
	}
	if host == "" {
		return shortSuffix(parsed.Scheme+"://...", maxLen)
	}

	prefix := parsed.Scheme + "://"
	if parsed.User != nil {
		prefix += "***@"
	}
	tag := ""
	if parsed.Fragment != "" {
		tag = "#" + shortSuffix(parsed.Fragment, 24)
	}
	return shortSuffix(prefix+host+tag, maxLen)
}

func shortSuffix(value string, maxLen int) string {
	if len(value) <= maxLen {
		return value
	}
	if maxLen <= 3 {
		return value[:maxLen]
	}
	return value[:maxLen-3] + "..."
}
