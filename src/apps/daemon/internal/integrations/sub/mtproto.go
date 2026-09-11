package sub

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
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

type mtprotoProbe func(context.Context, MTProtoProxy) (time.Duration, error)

func FetchAndTestMTProto(ctx context.Context) ([]MTProtoProxy, error) {
	egress := NewEgress(EgressConfig{Enabled: true, Timeout: 10 * time.Second})
	rawProxies, err := fetchMTProtoMirrors(ctx, egress, mtprotoMirrors)
	if err != nil {
		return nil, err
	}
	return testAndFilterProxiesWithProbe(ctx, rawProxies, publicMTProtoProbe), nil
}

func fetchMTProtoMirrors(ctx context.Context, egress *Egress, mirrors []string) ([]MTProtoProxy, error) {
	var lastErr error
	for _, mirror := range mirrors {
		resp, err := egress.Fetch(ctx, mirror)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("mirror %s returned HTTP %d", redactRemoteURL(mirror), resp.StatusCode)
			continue
		}
		var rawProxies []MTProtoProxy
		if err := json.Unmarshal(resp.Body, &rawProxies); err != nil {
			lastErr = fmt.Errorf("decode mirror %s: %w", redactRemoteURL(mirror), err)
			continue
		}
		if len(rawProxies) == 0 {
			lastErr = fmt.Errorf("mirror %s returned no proxies", redactRemoteURL(mirror))
			continue
		}
		return rawProxies, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no MTProto mirrors configured")
	}
	return nil, fmt.Errorf("failed to fetch MTProto mirrors: %w", lastErr)
}

func redactRemoteURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "<invalid-url>"
	}
	return parsed.Redacted()
}

func FetchAndTestMTProtoFromChannel(ctx context.Context, channel string) ([]MTProtoProxy, error) {
	links, err := FetchLinksFromTelegramChannel(ctx, channel)
	if err != nil {
		return nil, err
	}

	rawProxies := parseMTProtoLinks(links)
	if len(rawProxies) == 0 {
		return nil, fmt.Errorf("no MTProto proxy links found in channel")
	}
	return testAndFilterProxiesWithProbe(ctx, rawProxies, publicMTProtoProbe), nil
}

func parseMTProtoLinks(links []string) []MTProtoProxy {
	rawProxies := make([]MTProtoProxy, 0, len(links))
	seenProxy := make(map[string]bool)
	for _, match := range links {
		if !strings.HasPrefix(match, "tg://") && !strings.HasPrefix(match, "t.me/proxy") && !strings.HasPrefix(match, "https://t.me/proxy") {
			continue
		}
		if strings.HasPrefix(match, "tg://") {
			match = "https://t.me/" + strings.TrimPrefix(match, "tg://")
		} else if !strings.HasPrefix(match, "http") {
			match = "https://" + match
		}

		u, err := url.Parse(match)
		if err != nil {
			continue
		}
		q := u.Query()
		server := strings.TrimSpace(q.Get("server"))
		portStr := q.Get("port")
		secret := strings.TrimSpace(q.Get("secret"))
		if server == "" || portStr == "" || secret == "" {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			continue
		}

		key := net.JoinHostPort(strings.ToLower(server), strconv.Itoa(port))
		if seenProxy[key] {
			continue
		}
		seenProxy[key] = true
		rawProxies = append(rawProxies, MTProtoProxy{Host: server, Port: port, Secret: secret})
	}
	return rawProxies
}

func publicMTProtoProbe(ctx context.Context, proxy MTProtoProxy) (time.Duration, error) {
	if proxy.Port < 1 || proxy.Port > 65535 {
		return 0, fmt.Errorf("invalid MTProto proxy port %d", proxy.Port)
	}
	egress := NewEgress(EgressConfig{Enabled: true, Timeout: 2 * time.Second})
	addresses, err := egress.resolvePublic(ctx, strings.TrimSpace(proxy.Host))
	if err != nil {
		return 0, fmt.Errorf("reject MTProto proxy host: %w", err)
	}
	if len(addresses) == 0 {
		return 0, fmt.Errorf("MTProto proxy host resolved to no public addresses")
	}

	// Resolve once through the public-address policy and dial the vetted IP
	// directly. This avoids a second hostname lookup and closes the DNS-rebinding
	// window between validation and connection establishment.
	addr := net.JoinHostPort(addresses[0].String(), strconv.Itoa(proxy.Port))
	start := time.Now()
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return time.Since(start), nil
}

func testAndFilterProxies(ctx context.Context, rawProxies []MTProtoProxy) []MTProtoProxy {
	return testAndFilterProxiesWithProbe(ctx, rawProxies, publicMTProtoProbe)
}

func testAndFilterProxiesWithProbe(ctx context.Context, rawProxies []MTProtoProxy, probe mtprotoProbe) []MTProtoProxy {
	if len(rawProxies) == 0 || probe == nil {
		return nil
	}

	proxies := append([]MTProtoProxy(nil), rawProxies...)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	rng.Shuffle(len(proxies), func(i, j int) { proxies[i], proxies[j] = proxies[j], proxies[i] })

	testLimit := 40
	if len(proxies) < testLimit {
		testLimit = len(proxies)
	}
	proxiesToTest := proxies[:testLimit]

	var wg sync.WaitGroup
	var mu sync.Mutex
	tested := make([]MTProtoProxy, 0, len(proxiesToTest))
	sem := make(chan struct{}, 15)

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

			duration, err := probe(ctx, proxy)
			if err != nil {
				return
			}
			proxy.PingMs = int(duration.Milliseconds())
			mu.Lock()
			tested = append(tested, proxy)
			mu.Unlock()
		}(p)
	}

	wg.Wait()
	sort.Slice(tested, func(i, j int) bool { return tested[i].PingMs < tested[j].PingMs })
	return tested
}
