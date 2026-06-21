package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type MTProtoProxy struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Secret string `json:"secret"`
	PingMs int    `json:"ping_ms"`
}

var mtprotoMirrors = []string{
	"https://fastly.jsdelivr.net/gh/hookzof/socks5_list@master/tg/mtproto.json",
	"https://raw.gitmirror.com/hookzof/socks5_list/master/tg/mtproto.json",
	"https://ghproxy.net/https://raw.githubusercontent.com/hookzof/socks5_list/master/tg/mtproto.json",
}

func FetchAndTestMTProto(ctx context.Context) ([]MTProtoProxy, error) {
	var rawProxies []MTProtoProxy
	client := &http.Client{Timeout: 10 * time.Second}
	var fetchErr error

	for _, url := range mtprotoMirrors {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			fetchErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			err = json.NewDecoder(resp.Body).Decode(&rawProxies)
			if err == nil && len(rawProxies) > 0 {
				fetchErr = nil
				break
			}
		}
	}

	if fetchErr != nil {
		return nil, fmt.Errorf("failed to fetch from mirrors: %w", fetchErr)
	}

	if len(rawProxies) == 0 {
		return nil, fmt.Errorf("no proxies found")
	}

	return testAndFilterProxies(ctx, rawProxies), nil
}

// FetchMultiProtocolFromChannel scrapes a Telegram channel for various proxy links (VMess, VLESS, Trojan, SS, MTProto).
func FetchMultiProtocolFromChannel(ctx context.Context, channel string) ([]string, error) {
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

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch telegram page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("telegram returned status %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	body := string(bodyBytes)
	
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

func FetchAndTestMTProtoFromChannel(ctx context.Context, channel string) ([]MTProtoProxy, error) {
	links, err := FetchMultiProtocolFromChannel(ctx, channel)
	if err != nil {
		return nil, err
	}

	var rawProxies []MTProtoProxy
	seenProxy := make(map[string]bool)
	for _, match := range links {
		if !strings.HasPrefix(match, "tg://") && !strings.HasPrefix(match, "t.me/proxy") && !strings.HasPrefix(match, "https://t.me/proxy") {
			continue // skip non-MTProto
		}
		var u *url.URL
		if strings.HasPrefix(match, "tg://") {
			match = "https://t.me/" + strings.TrimPrefix(match, "tg://")
		} else if !strings.HasPrefix(match, "http") {
			match = "https://" + match
		}

		var parseErr error
		u, parseErr = url.Parse(match)
		if parseErr != nil {
			continue
		}

		q := u.Query()
		server := q.Get("server")
		portStr := q.Get("port")
		secret := q.Get("secret")

		if server == "" || portStr == "" || secret == "" {
			continue
		}

		port, parseErr := strconv.Atoi(portStr)
		if parseErr != nil {
			continue
		}

		key := fmt.Sprintf("%s:%d", server, port)
		if seenProxy[key] {
			continue
		}
		seenProxy[key] = true

		rawProxies = append(rawProxies, MTProtoProxy{
			Host:   server,
			Port:   port,
			Secret: secret,
		})
	}

	if len(rawProxies) == 0 {
		return nil, fmt.Errorf("no MTProto proxy links found in channel")
	}

	return testAndFilterProxies(ctx, rawProxies), nil
}

func testAndFilterProxies(ctx context.Context, rawProxies []MTProtoProxy) []MTProtoProxy {
	// Shuffle and limit to 40 proxies to test quickly
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(rawProxies), func(i, j int) {
		rawProxies[i], rawProxies[j] = rawProxies[j], rawProxies[i]
	})

	testLimit := 40
	if len(rawProxies) < testLimit {
		testLimit = len(rawProxies)
	}
	proxiesToTest := rawProxies[:testLimit]

	var wg sync.WaitGroup
	var mu sync.Mutex
	tested := make([]MTProtoProxy, 0, len(proxiesToTest))

	sem := make(chan struct{}, 15) // limit concurrency to 15 workers

	for _, p := range proxiesToTest {
		wg.Add(1)
		go func(proxy MTProtoProxy) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			addr := net.JoinHostPort(proxy.Host, fmt.Sprintf("%d", proxy.Port))
			start := time.Now()
			d := net.Dialer{Timeout: 2 * time.Second}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err == nil {
				conn.Close()
				proxy.PingMs = int(time.Since(start).Milliseconds())
				mu.Lock()
				tested = append(tested, proxy)
				mu.Unlock()
			}
		}(p)
	}

	wg.Wait()

	sort.Slice(tested, func(i, j int) bool {
		return tested[i].PingMs < tested[j].PingMs
	})

	return tested
}
