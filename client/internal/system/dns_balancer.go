package system

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ResolverStats tracks latency and health for a single DNS resolver upstream.
type ResolverStats struct {
	Addr                string
	Latency             time.Duration
	SuccessCount        uint64
	FailureCount        uint64
	ConsecutiveFailures uint32
	Disabled            bool
	LastCheck           time.Time
}

// DNSBalancer manages a pool of DNS resolvers, tracking their health and routing queries.
type DNSBalancer struct {
	mu        sync.RWMutex
	resolvers []*ResolverStats
	strategy  string // "lowest_latency" or "round_robin"
	rrIndex   uint32
}

// NewDNSBalancer initializes a balancer with the given list of resolver addresses.
func NewDNSBalancer(addrs []string, strategy string) *DNSBalancer {
	b := &DNSBalancer{
		resolvers: make([]*ResolverStats, 0, len(addrs)),
		strategy:  strategy,
	}
	for _, addr := range addrs {
		b.resolvers = append(b.resolvers, &ResolverStats{
			Addr: addr,
		})
	}
	if b.strategy == "" {
		b.strategy = "lowest_latency"
	}
	return b
}

// SelectResolver selects the best resolver according to health and strategy.
func (b *DNSBalancer) SelectResolver() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.resolvers) == 0 {
		return ""
	}

	var active []*ResolverStats
	for _, r := range b.resolvers {
		if !r.Disabled {
			active = append(active, r)
		}
	}

	// Fallback to all if all are disabled (safety)
	if len(active) == 0 {
		active = b.resolvers
	}

	if b.strategy == "round_robin" {
		idx := atomic.AddUint32(&b.rrIndex, 1) % uint32(len(active))
		return active[idx].Addr
	}

	// Lowest Latency Strategy (with some random exploration for high latencies)
	bestIdx := 0
	bestLatency := active[0].Latency
	for i, r := range active {
		// Unmeasured resolvers get priority for bootstrapping
		if r.Latency == 0 {
			return r.Addr
		}
		if r.Latency < bestLatency {
			bestLatency = r.Latency
			bestIdx = i
		}
	}

	// 10% chance of random exploration to avoid local minima
	if rand.Float64() < 0.1 {
		return active[rand.Intn(len(active))].Addr
	}

	return active[bestIdx].Addr
}

// ReportSuccess updates resolver stats on a successful query.
func (b *DNSBalancer) ReportSuccess(addr string, rtt time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, r := range b.resolvers {
		if r.Addr == addr {
			r.SuccessCount++
			r.ConsecutiveFailures = 0
			r.Disabled = false
			if r.Latency == 0 {
				r.Latency = rtt
			} else {
				// Moving average: 80% old, 20% new
				r.Latency = (r.Latency * 4 / 5) + (rtt / 5)
			}
			break
		}
	}
}

// ReportFailure updates resolver stats when a query times out or fails.
func (b *DNSBalancer) ReportFailure(addr string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, r := range b.resolvers {
		if r.Addr == addr {
			r.FailureCount++
			r.ConsecutiveFailures++
			// Temporarily disable resolver if 5 consecutive failures occur
			if r.ConsecutiveFailures >= 5 {
				r.Disabled = true
				r.LastCheck = time.Now()
				r.Latency = 5 * time.Second
			}
			break
		}
	}
}

// PeriodicReenable checks if any disabled resolvers can be re-enabled after cooldown.
func (b *DNSBalancer) PeriodicReenable() {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	for _, r := range b.resolvers {
		if r.Disabled && now.Sub(r.LastCheck) > 30*time.Second {
			r.Disabled = false
			r.ConsecutiveFailures = 0
			r.Latency = 1 * time.Second
		}
	}
}

// buildScannerDNSQuery builds a standard DNS query packet for A record query.
func buildScannerDNSQuery(domain string) []byte {
	txID := uint16(rand.Intn(65535))
	
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], txID)
	binary.BigEndian.PutUint16(header[2:4], 0x0100) // Flags: Standard Query, Recursion Desired
	binary.BigEndian.PutUint16(header[4:6], 0x0001) // QCount: 1

	var body []byte
	parts := strings.Split(domain, ".")
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		body = append(body, byte(len(p)))
		body = append(body, []byte(p)...)
	}
	body = append(body, 0x00) // Null byte terminator

	qtype := make([]byte, 2)
	binary.BigEndian.PutUint16(qtype, 0x0001) // Type A
	body = append(body, qtype...)

	qclass := make([]byte, 2)
	binary.BigEndian.PutUint16(qclass, 0x0001) // Class IN
	body = append(body, qclass...)

	return append(header, body...)
}

// ScanResolverForTunnel checks if a target DNS resolver IP can recursively query and resolve our tunnel domain.
// It generates a random subdomain prefix to bypass caching, sends a raw DNS query over UDP,
// and measures the response time.
func ScanResolverForTunnel(resolverAddr string, tunnelDomain string, timeout time.Duration) (bool, time.Duration, error) {
	if !strings.Contains(resolverAddr, ":") {
		resolverAddr = resolverAddr + ":53"
	}

	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	var sb strings.Builder
	for i := 0; i < 6; i++ {
		sb.WriteByte(chars[rand.Intn(len(chars))])
	}
	targetDomain := sb.String() + "." + tunnelDomain

	packet := buildScannerDNSQuery(targetDomain)

	conn, err := net.DialTimeout("udp", resolverAddr, timeout)
	if err != nil {
		return false, 0, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	t0 := time.Now()
	_, err = conn.Write(packet)
	if err != nil {
		return false, 0, err
	}

	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		return false, 0, err
	}
	rtt := time.Since(t0)

	if n < 12 {
		return false, rtt, fmt.Errorf("response too short: %d bytes", n)
	}

	txID := binary.BigEndian.Uint16(packet[0:2])
	respTxID := binary.BigEndian.Uint16(resp[0:2])
	if txID != respTxID {
		return false, rtt, fmt.Errorf("transaction ID mismatch: sent 0x%x, got 0x%x", txID, respTxID)
	}

	flags := binary.BigEndian.Uint16(resp[2:4])
	rcode := flags & 0x000F

	if rcode != 0 {
		return false, rtt, fmt.Errorf("DNS error code: %d", rcode)
	}

	return true, rtt, nil
}

