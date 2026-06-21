package system

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
)

// DNSMapper maps hostnames to fake IPs in the 198.18.0.0/16 range.
type DNSMapper struct {
	mu           sync.RWMutex
	hostnameToIP map[string]string
	ipToHostname map[string]string
	counter      uint32
}

// NewDNSMapper creates an instance of DNSMapper.
func NewDNSMapper() *DNSMapper {
	return &DNSMapper{
		hostnameToIP: make(map[string]string),
		ipToHostname: make(map[string]string),
		counter:      1,
	}
}

// GetFakeIP returns a fake IP in the 198.18.x.x range for the given hostname.
func (m *DNSMapper) GetFakeIP(hostname string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if ip, ok := m.hostnameToIP[hostname]; ok {
		return ip
	}

	// Generate next fake IP
	counter := atomic.AddUint32(&m.counter, 1)
	if counter > 65535 {
		atomic.StoreUint32(&m.counter, 1)
		counter = 1
	}

	octet3 := byte(counter >> 8)
	octet4 := byte(counter & 0xFF)
	fakeIP := fmt.Sprintf("198.18.%d.%d", octet3, octet4)

	m.hostnameToIP[hostname] = fakeIP
	m.ipToHostname[fakeIP] = hostname
	return fakeIP
}

// GetHostname looks up the original hostname mapped to the given fake IP.
func (m *DNSMapper) GetHostname(fakeIP string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	hostname, ok := m.ipToHostname[fakeIP]
	return hostname, ok
}

// ResolveAddr Intercepts any address containing a fake IP and returns the mapped hostname.
// If not mapped or not a fake IP, it returns the original address.
func (m *DNSMapper) ResolveAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = ""
	}

	if name, ok := m.GetHostname(host); ok {
		if port != "" {
			return net.JoinHostPort(name, port)
		}
		return name
	}
	return addr
}

// BuildMockDNSResponse parses a DNS A-record query and builds a response pointing to the fake IP.
func (m *DNSMapper) BuildMockDNSResponse(query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, fmt.Errorf("dns query too short")
	}

	// Read query headers
	_ = binary.BigEndian.Uint16(query[0:2])
	flags := binary.BigEndian.Uint16(query[2:4])
	qdcount := binary.BigEndian.Uint16(query[4:6])

	// Verify QR flag = 0 (query)
	if flags&0x8000 != 0 {
		return nil, fmt.Errorf("dns packet is not a query")
	}

	if qdcount != 1 {
		return nil, fmt.Errorf("only single question queries are supported")
	}

	// Parse query name
	offset := 12
	labels := []string{}
	for offset < len(query) {
		length := int(query[offset])
		if length == 0 {
			offset++
			break
		}
		if length > 63 || offset+1+length > len(query) {
			return nil, fmt.Errorf("malformed labels")
		}
		labels = append(labels, string(query[offset+1:offset+1+length]))
		offset += 1 + length
	}

	if offset+4 > len(query) {
		return nil, fmt.Errorf("truncated qtype/qclass")
	}

	_ = binary.BigEndian.Uint16(query[offset : offset+2])
	_ = binary.BigEndian.Uint16(query[offset+2 : offset+4])
	offset += 4

	hostname := strings.Join(labels, ".")
	fakeIPStr := m.GetFakeIP(hostname)
	fakeIP := net.ParseIP(fakeIPStr).To4()

	// Build DNS response
	var resp []byte
	resp = append(resp, query[:offset]...) // Copy header and question section

	// Modify Flags in copy (bytes 2-3 of resp)
	// QR=1, AA=1, RD=1, RA=1 (0x8580)
	binary.BigEndian.PutUint16(resp[2:4], uint16(0x8580))
	// Set ANCOUNT = 1 (bytes 6-7)
	binary.BigEndian.PutUint16(resp[6:8], uint16(1))

	// Answer Section RR
	// Pointer to question name: 0xc00c
	resp = append(resp, 0xc0, 0x0c)
	// Type: A (1)
	resp = append(resp, 0x00, 0x01)
	// Class: IN (1)
	resp = append(resp, 0x00, 0x01)
	// TTL: 60 seconds (0x0000003c)
	resp = append(resp, 0x00, 0x00, 0x00, 0x3c)
	// RDLENGTH: 4 bytes (IPv4)
	resp = append(resp, 0x00, 0x04)
	// RDATA: fake IP bytes
	resp = append(resp, fakeIP...)

	return resp, nil
}

// BuildICMPPortUnreachable builds a Destination Port Unreachable ICMP packet.
// It wraps the original IP header + first 8 bytes of UDP payload as the ICMP error context.
func BuildICMPPortUnreachable(origIPPacket []byte) ([]byte, error) {
	if len(origIPPacket) < 20 {
		return nil, fmt.Errorf("ip packet too short")
	}

	ipVersion := origIPPacket[0] >> 4
	if ipVersion != 4 {
		return nil, fmt.Errorf("only IPv4 unsupported error reports supported")
	}

	headerLen := int(origIPPacket[0]&0x0F) * 4
	if len(origIPPacket) < headerLen+8 {
		return nil, fmt.Errorf("ip packet payload too short to extract UDP context")
	}

	origSrcIP := origIPPacket[12:16]
	origDstIP := origIPPacket[16:20]

	// Extract original IP header + first 8 bytes of UDP payload (total error context)
	errContext := origIPPacket[:headerLen+8]

	icmpPayloadLen := 8 + len(errContext)
	totalLen := 20 + icmpPayloadLen

	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45 // Version 4, IHL 5
	ipHeader[1] = 0x00 // TOS
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ipHeader[4:6], uint16(54321)) // Random ID
	binary.BigEndian.PutUint16(ipHeader[6:8], uint16(0))     // Flags & Fragment Offset
	ipHeader[8] = 64                                         // TTL
	ipHeader[9] = 1                                          // Protocol: ICMP
	// Header Checksum at 10:12 calculated later
	copy(ipHeader[12:16], origDstIP) // Source is now the unreachable port resolver IP
	copy(ipHeader[16:20], origSrcIP) // Destination is original sender

	// Calculate IP Header checksum
	checksumIP := calculateChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], checksumIP)

	icmpPacket := make([]byte, icmpPayloadLen)
	icmpPacket[0] = 3 // Type: Destination Unreachable
	icmpPacket[1] = 3 // Code: Port Unreachable
	// Checksum at 2:4 calculated later
	// Bytes 4:8 are unused (zeros)
	copy(icmpPacket[8:], errContext)

	checksumICMP := calculateChecksum(icmpPacket)
	binary.BigEndian.PutUint16(icmpPacket[2:4], checksumICMP)

	return append(ipHeader, icmpPacket...), nil
}

func calculateChecksum(data []byte) uint16 {
	var sum uint32
	length := len(data)
	for i := 0; i < length-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if length%2 != 0 {
		sum += uint32(data[length-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
