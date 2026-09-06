package firewall

import (
	"strings"
	"sync"
)

type TunRouteSynchronizer struct {
	mu             sync.RWMutex
	BypassPrefixes []string
	TunMtu         uint16
}

func NewTunRouteSynchronizer(tunMtu uint16) *TunRouteSynchronizer {
	return &TunRouteSynchronizer{
		BypassPrefixes: []string{
			"10.",
			"127.",
			"169.254.",
			"172.16.",
			"192.168.",
			"224.",
			"fe80:",
			"::1",
		},
		TunMtu: tunMtu,
	}
}

func (s *TunRouteSynchronizer) AddBypassPrefix(prefix string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.BypassPrefixes {
		if p == prefix {
			return
		}
	}
	s.BypassPrefixes = append(s.BypassPrefixes, prefix)
}

func (s *TunRouteSynchronizer) ShouldBypass(ip string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	trimmed := strings.TrimSpace(ip)
	for _, prefix := range s.BypassPrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	return false
}

func (s *TunRouteSynchronizer) CalculateClampedMSS(isIPv6 bool) uint16 {
	overhead := uint16(40)
	if isIPv6 {
		overhead = 60
	}
	if s.TunMtu > overhead {
		return s.TunMtu - overhead
	}
	return 1200
}
