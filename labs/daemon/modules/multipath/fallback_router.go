package multipath

import (
	"context"
	"errors"
	"net"
	"sync"
)

type TierType int

const (
	TierDirect TierType = iota
	TierDomainFronted
	TierEncryptedTunnel
	TierQuicFallback
)

type FallbackTier struct {
	Type        TierType
	ConsecutiveFailures int
	MaxFailures int
	DialFunc    func(ctx context.Context, network, address string) (net.Conn, error)
}

type FallbackRouter struct {
	mu    sync.RWMutex
	tiers []*FallbackTier
}

func NewFallbackRouter() *FallbackRouter {
	return &FallbackRouter{
		tiers: make([]*FallbackTier, 0),
	}
}

func (r *FallbackRouter) AddTier(t TierType, maxFailures int, dialer func(ctx context.Context, network, addr string) (net.Conn, error)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tiers = append(r.tiers, &FallbackTier{
		Type:        t,
		MaxFailures: maxFailures,
		DialFunc:    dialer,
	})
}

func (r *FallbackRouter) DialWithFallback(ctx context.Context, network, addr string) (net.Conn, TierType, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, tier := range r.tiers {
		if tier.ConsecutiveFailures >= tier.MaxFailures {
			continue
		}
		conn, err := tier.DialFunc(ctx, network, addr)
		if err == nil {
			tier.ConsecutiveFailures = 0
			return conn, tier.Type, nil
		}
		tier.ConsecutiveFailures++
	}

	return nil, -1, errors.New("all fallback tiers exhausted")
}

func (r *FallbackRouter) ResetCircuitBreakers() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, tier := range r.tiers {
		tier.ConsecutiveFailures = 0
	}
}
