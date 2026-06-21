package proxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PreviewCollector struct {
	Channels       []string
	Concurrency    int
	PingTimeout    time.Duration
	FilterIranian  bool
	HTTPClient     *http.Client
}

func NewPreviewCollector(channels []string, concurrency int, pingTimeout time.Duration, filterIranian bool) *PreviewCollector {
	if concurrency <= 0 {
		concurrency = 20
	}
	if pingTimeout <= 0 {
		pingTimeout = 1000 * time.Millisecond
	}
	return &PreviewCollector{
		Channels:      channels,
		Concurrency:   concurrency,
		PingTimeout:   pingTimeout,
		FilterIranian: filterIranian,
		HTTPClient:    &http.Client{Timeout: 10 * time.Second},
	}
}

// CollectAndTest retrieves configs from channels, dedupes, pings them, filters out Iranian nodes, and returns working configs.
func (pc *PreviewCollector) CollectAndTest(ctx context.Context) ([]string, error) {
	var allConfigs []string
	seen := make(map[string]bool)

	for _, ch := range pc.Channels {
		configs, err := pc.fetchChannelConfigs(ctx, ch)
		if err != nil {
			continue
		}
		for _, cfg := range configs {
			if !seen[cfg] {
				seen[cfg] = true
				allConfigs = append(allConfigs, cfg)
			}
		}
	}

	if len(allConfigs) == 0 {
		return nil, fmt.Errorf("no configurations collected")
	}

	return pc.testAndFilter(ctx, allConfigs), nil
}

func (pc *PreviewCollector) fetchChannelConfigs(ctx context.Context, channel string) ([]string, error) {
	var targetURL string
	if strings.HasPrefix(channel, "http://") || strings.HasPrefix(channel, "https://") {
		targetURL = channel
	} else {
		channel = strings.TrimPrefix(channel, "@")
		targetURL = fmt.Sprintf("https://t.me/s/%s", channel)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := pc.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status error: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	body := string(bodyBytes)

	// Strip HTML tags to extract raw content
	body = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(body, " ")
	// Clean HTML entities
	body = strings.ReplaceAll(body, "&amp;", "&")

	patterns := []string{
		`\bvmess://[^\s"'<>]+`,
		`\bvless://[^\s"'<>]+`,
		`\btrojan://[^\s"'<>]+`,
		`\bss://[^\s"'<>]+`,
		`\btuic://[^\s"'<>]+`,
		`\bhysteria2://[^\s"'<>]+`,
		`\bhy2://[^\s"'<>]+`,
	}

	var parsedConfigs []string
	seen := make(map[string]bool)

	for _, p := range patterns {
		re := regexp.MustCompile(p)
		matches := re.FindAllString(body, -1)
		for _, match := range matches {
			if strings.Contains(match, "…") {
				continue // Skip truncated links
			}
			// Trim trailing punctuation marks common in telegram text
			match = regexp.MustCompile(`[),.!؟?؛\]}\s]+$`).ReplaceAllString(match, "")
			if !seen[match] {
				seen[match] = true
				parsedConfigs = append(parsedConfigs, match)
			}
		}
	}

	return parsedConfigs, nil
}

func (pc *PreviewCollector) testAndFilter(ctx context.Context, configs []string) []string {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var workingConfigs []string

	sem := make(chan struct{}, pc.Concurrency)

	for _, cfgStr := range configs {
		// Filter out Iranian intranet configs if enabled
		if pc.FilterIranian && pc.isIranianIntranet(cfgStr) {
			continue
		}

		wg.Add(1)
		go func(cfg string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			// Parse Config Address and Port using the unified parser
			parsed, err := ParseProxyURI(cfg)
			if err != nil {
				return
			}
			host := parsed.Address
			port := parsed.Port

			// Resolve host securely
			ips, err := net.LookupIP(host)
			if err != nil || len(ips) == 0 {
				return
			}

			// TCP Hand-dial verification
			addr := net.JoinHostPort(ips[0].String(), strconv.Itoa(port))
			d := net.Dialer{Timeout: pc.PingTimeout}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err == nil {
				conn.Close()
				mu.Lock()
				workingConfigs = append(workingConfigs, cfg)
				mu.Unlock()
			}
		}(cfgStr)
	}

	wg.Wait()
	return workingConfigs
}

func (pc *PreviewCollector) isIranianIntranet(configStr string) bool {
	// Try parsing config to extract real address
	var host string
	if cfg, err := ParseProxyURI(configStr); err == nil {
		host = cfg.Address
	} else {
		// Fallback to simple string check
		host = configStr
	}

	// Block lists for Iranian domains
	irDomains := []string{".ir", "samanehha.co", "webramz.co", "arman19.space"}
	for _, domain := range irDomains {
		if strings.Contains(strings.ToLower(host), domain) || strings.Contains(strings.ToLower(configStr), domain) {
			return true
		}
	}

	// Block lists for Farsi comments / marks in URI remarks
	decodedRemarks := ""
	if strings.Contains(configStr, "#") {
		parts := strings.SplitN(configStr, "#", 2)
		if len(parts) == 2 {
			decodedRemarks, _ = url.QueryUnescape(parts[1])
		}
	}

	farsiTerms := []string{"با ", "- IR", "ایران", "همراه", "ایرانسل", "همراه اول", "شاتل", "پارس آنلاین", "مخابرات", "رایتل"}
	for _, term := range farsiTerms {
		if strings.Contains(strings.ToLower(decodedRemarks), term) {
			return true
		}
	}

	return false
}

// CompileSubscription compiling clean configurations list to base64 format.
func CompileSubscription(configs []string) string {
	unified := strings.Join(configs, "\n")
	return base64.StdEncoding.EncodeToString([]byte(unified))
}
