package proxy

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ShapeProxyConfig takes a template proxy configuration and generates a list of reshaped proxy configurations
// by mapping it across a list of clean IPs.
// originalAddress is correctly assigned to Host/SNI properties for CDN fronting where appropriate.
func ShapeProxyConfig(template *ProxyConfig, cleanIPs []string, nameTemplate string) ([]*ProxyConfig, error) {
	var reshaped []*ProxyConfig

	originalAddr := template.Address

	for _, ip := range cleanIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}

		// Deep copy or field copy the template
		cfg := &ProxyConfig{
			Protocol:          template.Protocol,
			Port:              template.Port,
			UUID:              template.UUID,
			Password:          template.Password,
			Method:            template.Method,
			Security:          template.Security,
			AlterID:           template.AlterID,
			Transport:         template.Transport,
			TLS:               template.TLS,
			Path:              template.Path,
			ServiceName:       template.ServiceName,
			Flow:              template.Flow,
			Fingerprint:       template.Fingerprint,
			ALPN:              template.ALPN,
			SkipCertVerify:    template.SkipCertVerify,
			Plugin:            template.Plugin,
			PluginOpts:        template.PluginOpts,
			Protocol_:         template.Protocol_,
			ProtocolParam:     template.ProtocolParam,
			Obfs:              template.Obfs,
			ObfsParam:         template.ObfsParam,
			PrivateKey:        template.PrivateKey,
			PublicKey:         template.PublicKey,
			ShortID:           template.ShortID,
			PreSharedKey:      template.PreSharedKey,
			LocalAddress:      template.LocalAddress,
			MTU:               template.MTU,
			Reserved:          template.Reserved,
			Jc:                template.Jc,
			Jmin:              template.Jmin,
			Jmax:              template.Jmax,
			S1:                template.S1,
			S2:                template.S2,
			S3:                template.S3,
			S4:                template.S4,
			H1:                template.H1,
			H2:                template.H2,
			H3:                template.H3,
			H4:                template.H4,
			UpMbps:            template.UpMbps,
			DownMbps:          template.DownMbps,
			Obfuscation:       template.Obfuscation,
			CongestionControl: template.CongestionControl,
			UDPRelayMode:      template.UDPRelayMode,
		}

		// Set the address to the clean IP
		cfg.Address = ip

		// For CDN fronting, set Host/SNI.
		// If Host/SNI were not set on the template, we use originalAddr.
		// If they were already set, we keep them or fallback to originalAddr if they are empty.
		cfg.SNI = template.SNI
		if cfg.SNI == "" && template.TLS {
			cfg.SNI = originalAddr
		}

		cfg.Host = template.Host
		if cfg.Host == "" && (template.Transport == "ws" || template.Transport == "h2" || template.Transport == "httpupgrade" || template.Transport == "http") {
			cfg.Host = originalAddr
		}

		// Generate the name using the nameTemplate
		name := template.Name
		if nameTemplate != "" {
			// Replace {name} with original template name, {ip} with clean IP
			r := strings.NewReplacer("{name}", name, "{ip}", ip)
			cfg.Name = r.Replace(nameTemplate)
		} else {
			cfg.Name = fmt.Sprintf("%s - %s", name, ip)
		}

		reshaped = append(reshaped, cfg)
	}

	return reshaped, nil
}

// TokenBucket represents a thread-safe token bucket rate limiter for bandwidth pacing.
type TokenBucket struct {
	rate       int64 // bytes per second
	capacity   int64 // max burst
	tokens     int64
	lastUpdate time.Time
	mu         sync.Mutex
}

// NewTokenBucket creates a new TokenBucket rate limiter.
func NewTokenBucket(rateBps, capacity int64) *TokenBucket {
	return &TokenBucket{
		rate:       rateBps,
		capacity:   capacity,
		tokens:     capacity,
		lastUpdate: time.Now(),
	}
}

// Limit checks and waits for tokens to enforce the rate limit.
func (tb *TokenBucket) Limit(n int) {
	if tb.rate <= 0 {
		return
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()
	tb.lastUpdate = now

	tb.tokens += int64(elapsed * float64(tb.rate))
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}

	needed := int64(n)
	if tb.tokens >= needed {
		tb.tokens -= needed
		return
	}

	// Calculate wait time
	missing := needed - tb.tokens
	waitDuration := time.Duration(float64(missing) / float64(tb.rate) * float64(time.Second))
	tb.tokens = 0
	tb.lastUpdate = now.Add(waitDuration)

	tb.mu.Unlock()
	time.Sleep(waitDuration)
	tb.mu.Lock()
}

// PacedConn wraps a net.Conn with TokenBucket rate limiting for uploads and downloads.
type PacedConn struct {
	net.Conn
	readLimiter  *TokenBucket
	writeLimiter *TokenBucket
}

// NewPacedConn wraps the given net.Conn with read and write rate limiters.
func NewPacedConn(conn net.Conn, readRateBps, writeRateBps int64) net.Conn {
	var readLim *TokenBucket
	var writeLim *TokenBucket
	if readRateBps > 0 {
		readLim = NewTokenBucket(readRateBps, readRateBps/10) // 100ms burst capacity
	}
	if writeRateBps > 0 {
		writeLim = NewTokenBucket(writeRateBps, writeRateBps/10)
	}
	return &PacedConn{
		Conn:         conn,
		readLimiter:  readLim,
		writeLimiter: writeLim,
	}
}

func (pc *PacedConn) Read(b []byte) (int, error) {
	n, err := pc.Conn.Read(b)
	if n > 0 && pc.readLimiter != nil {
		pc.readLimiter.Limit(n)
	}
	return n, err
}

func (pc *PacedConn) Write(b []byte) (int, error) {
	if pc.writeLimiter == nil {
		return pc.Conn.Write(b)
	}
	// Split large writes to enforce pacing smoothly
	written := 0
	chunkSize := 16384 // 16KB chunks
	for written < len(b) {
		end := written + chunkSize
		if end > len(b) {
			end = len(b)
		}
		n, err := pc.Conn.Write(b[written:end])
		if n > 0 {
			pc.writeLimiter.Limit(n)
			written += n
		}
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// LocalIPPool manages a range of source IPs (IP aliases) to distribute outbound TCP connections.
type LocalIPPool struct {
	mu   sync.RWMutex
	ips  []net.IP
	next int
}

// NewLocalIPPool parses a CIDR string and returns a LocalIPPool containing matching IPs.
func NewLocalIPPool(cidr string) (*LocalIPPool, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// Generate IPs within the CIDR (limit to a reasonable number, e.g. 256)
	var ips []net.IP
	ip := make(net.IP, len(ipNet.IP))
	copy(ip, ipNet.IP)

	for ipNet.Contains(ip) {
		temp := make(net.IP, len(ip))
		copy(temp, ip)
		ips = append(ips, temp)

		// Increment IP
		for j := len(ip) - 1; j >= 0; j-- {
			ip[j]++
			if ip[j] > 0 {
				break
			}
		}
		if len(ips) >= 256 { // Avoid generating millions of IPs
			break
		}
	}

	if len(ips) == 0 {
		return nil, errors.New("no IPs found in CIDR")
	}

	return &LocalIPPool{
		ips: ips,
	}, nil
}

// SelectIP selects an IP in a round-robin fashion from the pool.
func (p *LocalIPPool) SelectIP() net.IP {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.ips) == 0 {
		return nil
	}
	ip := p.ips[p.next]
	p.next = (p.next + 1) % len(p.ips)
	return ip
}

// LossRateMonitor implements a closed loop rate adapter that adjusts rate limits based on connection checks.
type LossRateMonitor struct {
	mu           sync.Mutex
	successCount int
	failureCount int
	currentRate  int64
	minRate      int64
	maxRate      int64
}

// NewLossRateMonitor creates a new connection quality loss rate monitor.
func NewLossRateMonitor(initialRate, minRate, maxRate int64) *LossRateMonitor {
	return &LossRateMonitor{
		currentRate: initialRate,
		minRate:     minRate,
		maxRate:     maxRate,
	}
}

// RecordSuccess registers a successful cycle and scales up the rate if the loss ratio remains under 5%.
func (m *LossRateMonitor) RecordSuccess() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.successCount++

	if m.successCount >= 10 {
		total := m.successCount + m.failureCount
		lossRatio := float64(m.failureCount) / float64(total)
		if lossRatio < 0.05 { // <5% loss, scale up
			m.currentRate = int64(float64(m.currentRate) * 1.1)
			if m.currentRate > m.maxRate {
				m.currentRate = m.maxRate
			}
		}
		m.successCount = 0
		m.failureCount = 0
	}
}

// RecordFailure registers a failed cycle and immediately drops the rate by 20%.
func (m *LossRateMonitor) RecordFailure() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failureCount++

	m.currentRate = int64(float64(m.currentRate) * 0.8)
	if m.currentRate < m.minRate {
		m.currentRate = m.minRate
	}
}

// GetRate returns the current computed rate limit.
func (m *LossRateMonitor) GetRate() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.currentRate
}

