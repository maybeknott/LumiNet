package multipath

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestFallbackRouterProgression(t *testing.T) {
	router := NewFallbackRouter()

	// Tier 1: always fails
	router.AddTier(TierDirect, 1, func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("direct dial blocked by firewall")
	})

	// Tier 2: succeeds
	router.AddTier(TierDomainFronted, 2, func(ctx context.Context, network, addr string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	})

	conn, tier, err := router.DialWithFallback(context.Background(), "tcp", "blocked.domain:443")
	if err != nil {
		t.Fatalf("expected fallback success, got %v", err)
	}
	defer conn.Close()

	if tier != TierDomainFronted {
		t.Errorf("expected TierDomainFronted, got %v", tier)
	}
}
