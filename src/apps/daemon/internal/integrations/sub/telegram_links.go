package sub

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func FetchLinksFromTelegramChannel(ctx context.Context, channel string) ([]string, error) {
	if channel == "" {
		return nil, fmt.Errorf("channel username cannot be empty")
	}
	var targetURL string
	if strings.HasPrefix(channel, "http://") || strings.HasPrefix(channel, "https://") {
		targetURL = channel
	} else {
		channel = strings.TrimPrefix(channel, "@")
		targetURL = fmt.Sprintf("https://t.me/s/%s", channel)
	}

	// Normalize the legacy plain-http spelling of the public channel
	// preview endpoint to HTTPS; every other non-HTTPS URL is rejected by
	// the egress boundary below.
	if parsed, parseErr := url.Parse(targetURL); parseErr == nil && parsed.Scheme == "http" && parsed.Hostname() == "t.me" {
		parsed.Scheme = "https"
		targetURL = parsed.String()
	}

	// Route the fetch through the SSRF-safe egress boundary: HTTPS-only,
	// no user info, no environment proxies, public-address resolution
	// gate, redirect budget, and bounded response bodies. A caller-supplied
	// URL must never reach loopback, link-local, or metadata endpoints.
	egress := NewEgress(EgressConfig{
		Enabled:   true,
		Timeout:   10 * time.Second,
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	})
	resp, err := egress.Fetch(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch telegram page: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("telegram returned status %d", resp.StatusCode)
	}
	body := string(resp.Body)

	// Clean HTML
	body = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(body, " ")

	var rawLinks []string

	// Define Shin-TG patterns for extraction
	patterns := []string{
		`(?:tg://proxy|t\.me/proxy)\?[^\s"'<>]+`,
		`ss://[^\s"'<>]+`,
		`ss2022://[^\s"'<>]+`,
		`socks5://[^\s"'<>]+`,
		`socks://[^\s"'<>]+`,
		`wg://[^\s"'<>]+`,
		`wireguard://[^\s"'<>]+`,
		`trojan://[^\s"'<>]+`,
		`vmess://[^\s"'<>]+`,
		`vless://[^\s"'<>]+`,
		`tuic://[^\s"'<>]+`,
		`hysteria://[^\s"'<>]+`,
		`hy2://[^\s"'<>]+`,
		`juicity://[^\s"'<>]+`,
		`dnst://[^\s"'<>]+`,
		`dnstt://[^\s"'<>]+`,
		`vaydns://[^\s"'<>]+`,
		`slipstream://[^\s"'<>]+`,
		`stormdns://[^\s"'<>]+`,
		`masterdns://[^\s"'<>]+`,
		`masterdnsvpn://[^\s"'<>]+`,
		`noizdns://[^\s"'<>]+`,
		`slowdns://[^\s"'<>]+`,
		`ssh-dns://[^\s"'<>]+`,
		`dns-ssh://[^\s"'<>]+`,
		`ssh-over-dns://[^\s"'<>]+`,
	}

	seen := make(map[string]bool)

	for _, p := range patterns {
		re := regexp.MustCompile(p)
		matches := re.FindAllString(body, -1)
		for _, match := range matches {
			match = strings.ReplaceAll(match, "&amp;", "&")
			// Remove common ellipses truncation artifacts
			if strings.Contains(match, "…") {
				continue
			}
			// Trim trailing punctuation and brackets (including Farsi characters)
			match = regexp.MustCompile(`[),.!؟?؛\]}\s]+$`).ReplaceAllString(match, "")
			if !seen[match] {
				seen[match] = true
				rawLinks = append(rawLinks, match)
			}
		}
	}

	if len(rawLinks) == 0 {
		return nil, fmt.Errorf("no proxy links found in channel")
	}

	return rawLinks, nil
}
