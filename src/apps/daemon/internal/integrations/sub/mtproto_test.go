package sub

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestParseMTProtoLinks(t *testing.T) {
	links := []string{
		"tg://proxy?server=203.0.113.10&port=443&secret=dd00112233445566778899aabbccddeeff",
		"https://t.me/proxy?server=203.0.113.10&port=443&secret=duplicate",
		"t.me/proxy?server=198.51.100.7&port=8443&secret=ee00112233445566778899aabbccddeeff",
		"https://example.com/not-a-proxy",
		"tg://proxy?server=203.0.113.8&port=0&secret=bad",
		"tg://proxy?server=203.0.113.9&port=70000&secret=bad",
		"tg://proxy?server=203.0.113.11&port=443",
	}

	got := parseMTProtoLinks(links)
	if len(got) != 2 {
		t.Fatalf("parseMTProtoLinks() returned %d proxies, want 2: %+v", len(got), got)
	}
	if got[0].Host != "203.0.113.10" || got[0].Port != 443 {
		t.Fatalf("first proxy = %+v", got[0])
	}
	if got[1].Host != "198.51.100.7" || got[1].Port != 8443 {
		t.Fatalf("second proxy = %+v", got[1])
	}
}

func TestTestAndFilterProxiesUsesInjectedProbe(t *testing.T) {
	raw := []MTProtoProxy{
		{Host: "203.0.113.1", Port: 443, Secret: "first"},
		{Host: "203.0.113.2", Port: 443, Secret: "second"},
	}
	probe := func(_ context.Context, proxy MTProtoProxy) (time.Duration, error) {
		if proxy.Host == "203.0.113.1" {
			return 25 * time.Millisecond, nil
		}
		return 0, errors.New("unreachable")
	}

	got := testAndFilterProxiesWithProbe(context.Background(), raw, probe)
	if len(got) != 1 {
		t.Fatalf("tested proxies = %d, want 1: %+v", len(got), got)
	}
	if got[0].Host != "203.0.113.1" || got[0].PingMs != 25 {
		t.Fatalf("tested proxy = %+v, want first proxy with 25ms", got[0])
	}
}

func TestTestAndFilterProxiesDoesNotMutateInputOrder(t *testing.T) {
	raw := []MTProtoProxy{
		{Host: "203.0.113.1", Port: 443},
		{Host: "203.0.113.2", Port: 443},
		{Host: "203.0.113.3", Port: 443},
	}
	before := append([]MTProtoProxy(nil), raw...)
	probe := func(_ context.Context, _ MTProtoProxy) (time.Duration, error) {
		return time.Millisecond, nil
	}
	_ = testAndFilterProxiesWithProbe(context.Background(), raw, probe)
	for i := range raw {
		if raw[i] != before[i] {
			t.Fatalf("input mutated at %d: got %+v want %+v", i, raw[i], before[i])
		}
	}
}

func TestPublicMTProtoProbeRejectsNonPublicTargets(t *testing.T) {
	t.Parallel()
	for _, host := range []string{"127.0.0.1", "0.0.0.0", "169.254.169.254", "::1"} {
		_, err := publicMTProtoProbe(context.Background(), MTProtoProxy{Host: host, Port: 443})
		if err == nil {
			t.Fatalf("publicMTProtoProbe(%q) accepted a non-public target", host)
		}
		if !errors.Is(err, ErrUnsafeRemoteTarget) {
			t.Fatalf("publicMTProtoProbe(%q) error = %v, want ErrUnsafeRemoteTarget", host, err)
		}
	}
}

func TestPublicMTProtoProbeRejectsInvalidPortsBeforeNetwork(t *testing.T) {
	t.Parallel()
	for _, port := range []int{-1, 0, 65536} {
		_, err := publicMTProtoProbe(context.Background(), MTProtoProxy{Host: "8.8.8.8", Port: port})
		if err == nil {
			t.Fatalf("port %d unexpectedly accepted", port)
		}
	}
}
