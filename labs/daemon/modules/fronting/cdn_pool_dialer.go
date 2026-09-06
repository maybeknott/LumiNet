package fronting

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

type CdnCandidate struct {
	IP             net.IP        `json:"ip"`
	SNI            string        `json:"sni"`
	Port           uint16        `json:"port"`
	RttEmaMs       float64       `json:"rtt_ema_ms"`
	SuccessCount   uint64        `json:"success_count"`
	FailureCount   uint64        `json:"failure_count"`
	LastProbe      time.Time     `json:"last_probe"`
	QuarantinedTil time.Time     `json:"quarantined_until"`
}

func (c *CdnCandidate) IsQuarantined(now time.Time) bool {
	return now.Before(c.QuarantinedTil)
}

func (c *CdnCandidate) RecordSuccess(rtt time.Duration) {
	c.SuccessCount++
	rttMs := float64(rtt.Microseconds()) / 1000.0
	if c.RttEmaMs == 0.0 {
		c.RttEmaMs = rttMs
	} else {
		c.RttEmaMs = 0.8*c.RttEmaMs + 0.2*rttMs
	}
	c.LastProbe = time.Now()
}

func (c *CdnCandidate) RecordFailure(quarantineDuration time.Duration) {
	c.FailureCount++
	c.LastProbe = time.Now()
	if c.FailureCount%3 == 0 {
		c.QuarantinedTil = c.LastProbe.Add(quarantineDuration)
	}
}

type CdnFrontPool struct {
	mu                 sync.RWMutex
	candidates         []*CdnCandidate
	quarantineDuration time.Duration
	maxPoolSize        int
}

func NewCdnFrontPool(quarantineDuration time.Duration, maxPoolSize int) *CdnFrontPool {
	return &CdnFrontPool{
		candidates:         make([]*CdnCandidate, 0),
		quarantineDuration: quarantineDuration,
		maxPoolSize:        maxPoolSize,
	}
}

func (p *CdnFrontPool) AddCandidate(ip net.IP, sni string, port uint16) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, c := range p.candidates {
		if c.IP.Equal(ip) && c.SNI == sni && c.Port == port {
			return nil
		}
	}
	if len(p.candidates) >= p.maxPoolSize {
		return errors.New("cdn front pool at max capacity")
	}
	p.candidates = append(p.candidates, &CdnCandidate{
		IP:             ip,
		SNI:            sni,
		Port:           port,
		RttEmaMs:       0.0,
		SuccessCount:   0,
		FailureCount:   0,
		LastProbe:      time.Time{},
		QuarantinedTil: time.Time{},
	})
	return nil
}

func (p *CdnFrontPool) SelectBest() (*CdnCandidate, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	now := time.Now()
	var best *CdnCandidate
	minRtt := 1e9

	for _, c := range p.candidates {
		if c.IsQuarantined(now) {
			continue
		}
		score := c.RttEmaMs
		if score == 0.0 {
			score = 50.0 // unprobed baseline optimistic score
		}
		if score < minRtt {
			minRtt = score
			best = c
		}
	}

	if best == nil {
		return nil, errors.New("no healthy unquarantined cdn front candidate available")
	}
	return best, nil
}

func (p *CdnFrontPool) DialFrontedTLS(ctx context.Context, hostHeader string) (net.Conn, error) {
	cand, err := p.SelectBest()
	if err != nil {
		return nil, err
	}

	addr := fmt.Sprintf("%s:%d", cand.IP.String(), cand.Port)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	start := time.Now()
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		p.mu.Lock()
		cand.RecordFailure(p.quarantineDuration)
		p.mu.Unlock()
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}

	tlsConfig := &tls.Config{
		ServerName:         cand.SNI,
		InsecureSkipVerify: false,
	}
	tlsConn := tls.Client(rawConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		p.mu.Lock()
		cand.RecordFailure(p.quarantineDuration)
		p.mu.Unlock()
		return nil, fmt.Errorf("tls handshake failed: %w", err)
	}

	p.mu.Lock()
	cand.RecordSuccess(time.Since(start))
	p.mu.Unlock()
	return tlsConn, nil
}
