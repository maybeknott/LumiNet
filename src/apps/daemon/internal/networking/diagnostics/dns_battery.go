// Copyright 2024 LumiNet. Use of this source code is governed by the MIT license.
// PYDNS-Scanner battery: a suite of diagnostic checks run against a DNS resolver
// to characterise its capabilities and detect common configuration issues.
// Tests cover DNSSEC validation, DNS hijacking, and EDNS0 support.

package diagnostics

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// DNSScanner runs the diagnostic battery against a target resolver.
type DNSScanner struct {
	ResolverIP   string   // IP:port of the resolver to test.
	Timeout      time.Duration
	KnownGoodIPs []string // IPs considered legitimate for hijack detection.
	// TestTargets is the set of domains to probe.
	TestTargets []string
}

// NewDNSScanner builds a scanner with sensible defaults.
func NewDNSScanner(resolverIP string) *DNSScanner {
	return &DNSScanner{
		ResolverIP:   resolverIP,
		Timeout:      8 * time.Second,
		KnownGoodIPs: []string{},
		TestTargets: []string{
			"cloudflare.com",
			"google.com",
			"github.com",
		},
	}
}

// SetTimeout overrides the query timeout.
func (s *DNSScanner) SetTimeout(d time.Duration) { s.Timeout = d }

// AddKnownGoodIP adds an IP to the trusted-IP allowlist used for hijack checks.
func (s *DNSScanner) AddKnownGoodIP(ip string) {
	s.KnownGoodIPs = append(s.KnownGoodIPs, ip)
}

// BatteryResult is the aggregated output of RunBattery.
type BatteryResult struct {
	DNSSEC DNSSECTestResult
	EDNS0  EDNSTestResult
	Hijack HijackTestResult
	Meta   BatteryMeta
}

// BatteryMeta contains metadata about the battery run itself.
type BatteryMeta struct {
	ResolverIP   string
	Duration     time.Duration
	TargetsCount int
	Errors       []string
}

// RunBattery executes all diagnostic tests concurrently and returns the combined result.
func (s *DNSScanner) RunBattery(ctx context.Context) BatteryResult {
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	var wg sync.WaitGroup
	var dnssecRes DNSSECTestResult
	var edns0Res EDNSTestResult
	var hijackRes HijackTestResult
	var mu sync.Mutex

	start := time.Now()

	wg.Add(3)
	go func() {
		defer wg.Done()
		r := s.runDNSSECCheck(ctx)
		mu.Lock()
		dnssecRes = r
		mu.Unlock()
	}()
	go func() {
		defer wg.Done()
		r := s.runEDNS0Check(ctx)
		mu.Lock()
		edns0Res = r
		mu.Unlock()
	}()
	go func() {
		defer wg.Done()
		r := s.runHijackCheck(ctx)
		mu.Lock()
		hijackRes = r
		mu.Unlock()
	}()

	wg.Wait()

	var errs []string
	for _, failure := range dnssecRes.Failures {
		errs = append(errs, "dnssec: "+failure)
	}
	for _, failure := range edns0Res.Failures {
		errs = append(errs, "edns0: "+failure)
	}
	for _, failure := range hijackRes.Failures {
		errs = append(errs, "hijack: "+failure)
	}

	return BatteryResult{
		DNSSEC: dnssecRes,
		EDNS0:  edns0Res,
		Hijack: hijackRes,
		Meta: BatteryMeta{
			ResolverIP:   s.ResolverIP,
			Duration:     time.Since(start),
			TargetsCount: len(s.TestTargets),
			Errors:       errs,
		},
	}
}

// ---------------------------------------------------------------------------
// DNSSEC test
// ---------------------------------------------------------------------------

// DNSSECTestResult holds the outcome of the DNSSEC capability check.
type DNSSECTestResult struct {
	Secure     bool     // resolver performed DNSSEC validation.
	AD         bool     // AD (authentic data) bit was set in responses.
	CD         bool     // CD (checking disabled) bit observed.
	CDPSkipped bool     // resolver stripped CD (DNSSEC checking disabled) requests.
	Failures   []string // domains that failed validation when expected secure.
}

// DNSSECTestDomain is a well-known domain with known DNSSEC status.
var DNSSECTestDomain = "cloudflare.com"

// runDNSSECCheck queries a known-signed domain and inspects the AD bit.
func (s *DNSScanner) runDNSSECCheck(ctx context.Context) DNSSECTestResult {
	// cloudflare.com has a valid DNSSEC chain. Query with DO=1 (DNSSEC OK).
	resp, rtt, err := s.queryDNS(ctx, DNSSECTestDomain, 1, true) // TYPE_A=1, DO=1
	res := DNSSECTestResult{}
	if err != nil {
		res.Failures = append(res.Failures, fmt.Sprintf("DNSSEC query failed: %v", err))
		return res
	}
	_ = rtt // available for future per-test RTT reporting

	if len(resp) < 12 {
		res.Failures = append(res.Failures, "response too short for DNSSEC analysis")
		return res
	}
	// Flags are at bytes 2-3.
	flags := binary.BigEndian.Uint16(resp[2:4])
	res.AD = flags&0x0020 != 0
	res.CD = flags&0x0010 != 0
	res.Secure = res.AD

	// Check a deliberately bogus DNSSEC name. A validating resolver normally
	// rejects it with SERVFAIL or returns it without the AD bit.
	_, _, err = s.queryDNS(ctx, "valid-secp256k1.nil.dnssec.works.", 1, true)
	if err != nil {
		res.Failures = append(res.Failures, fmt.Sprintf("DNSSEC validation query returned error (expected): %v", err))
	}
	return res
}

// ---------------------------------------------------------------------------
// EDNS0 test
// ---------------------------------------------------------------------------

// EDNSTestResult holds the outcome of the EDNS0 support check.
type EDNSTestResult struct {
	Supported    bool // resolver preserves EDNS0 OPT record in response.
	ResponseSize int  // maximum UDP payload size advertised by the resolver.
	ECS          bool // resolver honoured EDNS0 Client Subnet (ECS).
	Failures     []string
}

// runEDNS0Check sends a query with an EDNS0 OPT record and verifies the response
// carries one back, indicating the resolver understands EDNS0.
func (s *DNSScanner) runEDNS0Check(ctx context.Context) EDNSTestResult {
	res := EDNSTestResult{}
	resp, _, err := s.queryDNS(ctx, DNSSECTestDomain, 1, true)
	if err != nil {
		res.Failures = append(res.Failures, fmt.Sprintf("EDNS0 query failed: %v", err))
		return res
	}
	if size, ok := parseEDNS0PayloadSize(resp); ok {
		res.Supported = true
		res.ResponseSize = int(size)
	}

	// Also test with a large UDP bufsize request (RFC 6891 section 7).
	q := s.buildQueryWithEDNS0(DNSSECTestDomain, 4096)
	rawResp, _, err := s.rawQuery(ctx, q)
	if err == nil {
		if size, ok := parseEDNS0PayloadSize(rawResp); ok {
			res.Supported = true
			res.ResponseSize = int(size)
		}
	}
	return res
}

// ---------------------------------------------------------------------------
// Hijack test
// ---------------------------------------------------------------------------

// HijackTestResult holds the outcome of the DNS hijack check.
type HijackTestResult struct {
	Hijacked          bool
	HijackedDomains   []string
	SuspiciousDomains []string
	Failures          []string
}

// runHijackCheck queries each target domain and checks whether the resolved IPs
// belong to a known-good set or a recognised sinkhole/filtering range.
func (s *DNSScanner) runHijackCheck(ctx context.Context) HijackTestResult {
	res := HijackTestResult{}
	for _, domain := range s.TestTargets {
		ips, err := s.resolveA(ctx, domain)
		if err != nil {
			res.Failures = append(res.Failures, fmt.Sprintf("hijack check for %s: %v", domain, err))
			continue
		}
		if len(ips) == 0 {
			res.SuspiciousDomains = append(res.SuspiciousDomains, domain)
			continue
		}
		hijacked := false
		for _, ip := range ips {
			if s.isKnownGoodIP(ip) {
				continue
			}
			if isKnownHijackIP(ip) {
				hijacked = true
				break
			}
		}
		if hijacked {
			res.Hijacked = true
			res.HijackedDomains = append(res.HijackedDomains, domain)
		}
	}
	return res
}

func (s *DNSScanner) isKnownGoodIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, good := range s.KnownGoodIPs {
		goodIP := net.ParseIP(good)
		if goodIP != nil && parsed.Equal(goodIP) {
			return true
		}
	}
	return false
}

// isKnownHijackIP heuristically flags IPs commonly returned by captive portals
// or DNS-level ad filtering.
func isKnownHijackIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, exact := range []string{"0.0.0.0", "127.0.0.1"} {
		if parsed.Equal(net.ParseIP(exact)) {
			return true
		}
	}
	for _, cidr := range []string{
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24", // TEST-NET-3
	} {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil && ipnet.Contains(parsed) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Low-level DNS helpers
// ---------------------------------------------------------------------------

// queryDNS performs a single DNS A-query and returns the wire-format response.
func (s *DNSScanner) queryDNS(ctx context.Context, name string, qtype uint16, dnssecOK bool) ([]byte, time.Duration, error) {
	q := s.buildQuery(name, qtype, dnssecOK)
	if q == nil {
		return nil, 0, fmt.Errorf("invalid DNS query name %q", name)
	}
	return s.rawQuery(ctx, q)
}

func encodeDNSName(name string) ([]byte, bool) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}, true
	}
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, false
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	if len(out) > 255 {
		return nil, false
	}
	return out, true
}

func appendOPT(buf []byte, bufsize uint16, dnssecOK bool) []byte {
	buf = append(buf, 0x00)       // NAME=root
	buf = append(buf, 0x00, 0x29) // TYPE=OPT
	buf = append(buf, byte(bufsize>>8), byte(bufsize))
	// TTL: extended RCODE, EDNS version, flags. DO is bit 15 of flags.
	flags := uint16(0)
	if dnssecOK {
		flags = 0x8000
	}
	buf = append(buf, 0x00, 0x00, byte(flags>>8), byte(flags))
	buf = append(buf, 0x00, 0x00) // RDLENGTH=0
	return buf
}

func (s *DNSScanner) buildQuery(name string, qtype uint16, dnssecOK bool) []byte {
	encodedName, ok := encodeDNSName(name)
	if !ok {
		return nil
	}
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], 1)      // TXID
	binary.BigEndian.PutUint16(buf[2:4], 0x0100) // RD=1
	binary.BigEndian.PutUint16(buf[4:6], 1)      // QDCOUNT=1
	if dnssecOK {
		binary.BigEndian.PutUint16(buf[10:12], 1) // ARCOUNT=1
	}
	buf = append(buf, encodedName...)
	buf = append(buf, byte(qtype>>8), byte(qtype), 0x00, 0x01) // QTYPE, QCLASS=IN
	if dnssecOK {
		buf = appendOPT(buf, 4096, true)
	}
	return buf
}

func (s *DNSScanner) buildQueryWithEDNS0(name string, bufsize uint16) []byte {
	q := s.buildQuery(name, 1, false)
	if q == nil {
		return nil
	}
	binary.BigEndian.PutUint16(q[10:12], 1)
	return appendOPT(q, bufsize, false)
}

func resolverAddress(resolver string) (string, error) {
	resolver = strings.TrimSpace(resolver)
	if resolver == "" {
		return "", fmt.Errorf("resolver address is required")
	}
	if host, port, err := net.SplitHostPort(resolver); err == nil {
		if host == "" || port == "" {
			return "", fmt.Errorf("invalid resolver address %q", resolver)
		}
		return resolver, nil
	}
	if net.ParseIP(resolver) != nil || (!strings.Contains(resolver, ":") && resolver != "") {
		return net.JoinHostPort(resolver, "53"), nil
	}
	return "", fmt.Errorf("invalid resolver address %q", resolver)
}

func (s *DNSScanner) rawQuery(ctx context.Context, wire []byte) ([]byte, time.Duration, error) {
	if len(wire) < 12 {
		return nil, 0, fmt.Errorf("DNS query is shorter than the 12-byte header")
	}
	addr, err := resolverAddress(s.ResolverIP)
	if err != nil {
		return nil, 0, err
	}
	dialer := net.Dialer{}
	if s.Timeout > 0 {
		dialer.Timeout = s.Timeout
	}
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, 0, err
		}
	} else if s.Timeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(s.Timeout)); err != nil {
			return nil, 0, err
		}
	}
	start := time.Now()
	if _, err := conn.Write(wire); err != nil {
		return nil, 0, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, 0, err
	}
	if n < 12 {
		return nil, time.Since(start), fmt.Errorf("DNS response is shorter than the 12-byte header")
	}
	if !equalDNSID(wire, buf[:n]) {
		return nil, time.Since(start), fmt.Errorf("DNS response transaction ID does not match query")
	}
	return buf[:n], time.Since(start), nil
}

func equalDNSID(query, response []byte) bool {
	return len(query) >= 2 && len(response) >= 2 && query[0] == response[0] && query[1] == response[1]
}

func (s *DNSScanner) resolveA(ctx context.Context, name string) ([]string, error) {
	resp, _, err := s.queryDNS(ctx, name, 1, false)
	if err != nil {
		return nil, err
	}
	return parseARecords(resp), nil
}

// skipDNSName advances the offset past an encoded or compressed DNS name.
// It does not dereference compression pointers because callers only need the
// number of bytes consumed at the current position.
func skipDNSName(msg []byte, offset int) int {
	for offset < len(msg) {
		length := msg[offset]
		if length == 0 {
			return offset + 1
		}
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(msg) {
				return len(msg)
			}
			return offset + 2
		}
		if length&0xC0 != 0 || length > 63 || offset+1+int(length) > len(msg) {
			return len(msg)
		}
		offset += int(length) + 1
	}
	return offset
}

func skipDNSRecord(msg []byte, offset int) (int, bool) {
	offset = skipDNSName(msg, offset)
	if offset+10 > len(msg) {
		return len(msg), false
	}
	rdlen := int(binary.BigEndian.Uint16(msg[offset+8 : offset+10]))
	next := offset + 10 + rdlen
	if next > len(msg) {
		return len(msg), false
	}
	return next, true
}

func parseEDNS0PayloadSize(msg []byte) (uint16, bool) {
	if len(msg) < 12 {
		return 0, false
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	nsCount := int(binary.BigEndian.Uint16(msg[8:10]))
	arCount := int(binary.BigEndian.Uint16(msg[10:12]))
	offset := 12
	for i := 0; i < qdCount; i++ {
		offset = skipDNSName(msg, offset)
		if offset+4 > len(msg) {
			return 0, false
		}
		offset += 4
	}
	for i := 0; i < anCount+nsCount; i++ {
		var ok bool
		offset, ok = skipDNSRecord(msg, offset)
		if !ok {
			return 0, false
		}
	}
	for i := 0; i < arCount; i++ {
		nameEnd := skipDNSName(msg, offset)
		if nameEnd+10 > len(msg) {
			return 0, false
		}
		rtype := binary.BigEndian.Uint16(msg[nameEnd : nameEnd+2])
		payloadSize := binary.BigEndian.Uint16(msg[nameEnd+2 : nameEnd+4])
		rdlen := int(binary.BigEndian.Uint16(msg[nameEnd+8 : nameEnd+10]))
		next := nameEnd + 10 + rdlen
		if next > len(msg) {
			return 0, false
		}
		if rtype == 41 {
			return payloadSize, true
		}
		offset = next
	}
	return 0, false
}

// parseARecords walks a DNS wire-format response and returns every A record
// (QTYPE=1) answer as a dotted-quad string.
func parseARecords(resp []byte) []string {
	if len(resp) < 12 {
		return nil
	}
	qdCount := int(binary.BigEndian.Uint16(resp[4:6]))
	anCount := int(binary.BigEndian.Uint16(resp[6:8]))
	offset := 12
	for i := 0; i < qdCount; i++ {
		offset = skipDNSName(resp, offset)
		if offset+4 > len(resp) {
			return nil
		}
		offset += 4
	}
	var out []string
	for i := 0; i < anCount; i++ {
		offset = skipDNSName(resp, offset)
		if offset+10 > len(resp) {
			return out
		}
		rtype := binary.BigEndian.Uint16(resp[offset : offset+2])
		rdlen := int(binary.BigEndian.Uint16(resp[offset+8 : offset+10]))
		offset += 10
		if offset+rdlen > len(resp) {
			return out
		}
		if rtype == 1 && rdlen == net.IPv4len {
			out = append(out, net.IP(resp[offset:offset+rdlen]).String())
		}
		offset += rdlen
	}
	return out
}
