package proxy

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// PacketInjector defines the interface for raw TCP packet capture and wrong-sequence injection.
type PacketInjector interface {
	Start(ctx context.Context, listenPort int) error
	Stop() error
	IsRunning() bool
}

// MutateIPv4Source spoof-rewrites the source IP of an IPv4 packet, recalculating checksums.
func MutateIPv4Source(packet []byte, decoyIP net.IP) []byte {
	if len(packet) < 20 {
		return packet
	}

	// Check IPv4 version
	version := packet[0] >> 4
	if version != 4 {
		return packet
	}

	ihl := int(packet[0]&0x0F) * 4
	if len(packet) < ihl {
		return packet
	}

	// Rewrite source IP (bytes 12-15)
	decoyBytes := decoyIP.To4()
	if decoyBytes == nil {
		return packet
	}
	copy(packet[12:16], decoyBytes)

	// Recompute IPv4 Header Checksum (bytes 10-11)
	packet[10] = 0
	packet[11] = 0
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:ihl]))

	// Recompute TCP/UDP Checksum if applicable
	proto := packet[9]
	if proto == 6 && len(packet) >= ihl+20 { // TCP
		tcpLen := len(packet) - ihl
		tcpSegment := packet[ihl:]
		// Zero the checksum field before recomputing
		tcpSegment[16] = 0
		tcpSegment[17] = 0

		srcIP := packet[12:16]
		dstIP := packet[16:20]

		// Build pseudo-header + TCP segment for checksum
		pseudo := make([]byte, 12+tcpLen)
		copy(pseudo[0:4], srcIP)
		copy(pseudo[4:8], dstIP)
		pseudo[8] = 0
		pseudo[9] = 6
		binary.BigEndian.PutUint16(pseudo[10:], uint16(tcpLen))
		copy(pseudo[12:], tcpSegment)

		binary.BigEndian.PutUint16(tcpSegment[16:18], internetChecksum(pseudo))
	} else if proto == 17 && len(packet) >= ihl+8 { // UDP
		udpLen := len(packet) - ihl
		udpSegment := packet[ihl:]
		udpSegment[6] = 0
		udpSegment[7] = 0

		srcIP := packet[12:16]
		dstIP := packet[16:20]

		pseudo := make([]byte, 12+udpLen)
		copy(pseudo[0:4], srcIP)
		copy(pseudo[4:8], dstIP)
		pseudo[8] = 0
		pseudo[9] = 17
		binary.BigEndian.PutUint16(pseudo[10:], uint16(udpLen))
		copy(pseudo[12:], udpSegment)

		binary.BigEndian.PutUint16(udpSegment[6:8], internetChecksum(pseudo))
	}

	return packet
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

var (
	connSeqRegistry = make(map[string]uint32)
	connSeqMu       sync.Mutex
)

// RegisterConnSeq registers a TCP SYN sequence number for a source-destination port pair.
func RegisterConnSeq(srcPort, dstPort uint16, seq uint32) {
	connSeqMu.Lock()
	defer connSeqMu.Unlock()
	key := fmt.Sprintf("%d->%d", srcPort, dstPort)
	connSeqRegistry[key] = seq
}

// GetConnSeq looks up a registered TCP SYN sequence number for a port pair.
func GetConnSeq(srcPort, dstPort uint16) (uint32, bool) {
	connSeqMu.Lock()
	defer connSeqMu.Unlock()
	key := fmt.Sprintf("%d->%d", srcPort, dstPort)
	seq, found := connSeqRegistry[key]
	return seq, found
}

// ClearConnSeq removes a registered TCP SYN sequence number from the registry.
func ClearConnSeq(srcPort, dstPort uint16) {
	connSeqMu.Lock()
	defer connSeqMu.Unlock()
	key := fmt.Sprintf("%d->%d", srcPort, dstPort)
	delete(connSeqRegistry, key)
}

// parseTCPHandshake parses a raw IPv4/TCP packet, extracting srcPort, dstPort, TCP sequence number, and whether it is a SYN packet.
func parseTCPHandshake(packet []byte) (srcPort, dstPort uint16, seq uint32, isSyn bool) {
	if len(packet) < 20 {
		return 0, 0, 0, false
	}
	version := packet[0] >> 4
	if version != 4 {
		return 0, 0, 0, false
	}
	ihl := int(packet[0]&0x0F) * 4
	if len(packet) < ihl+20 {
		return 0, 0, 0, false
	}
	proto := packet[9]
	if proto != 6 { // Not TCP
		return 0, 0, 0, false
	}
	tcpSegment := packet[ihl:]
	srcPort = binary.BigEndian.Uint16(tcpSegment[0:2])
	dstPort = binary.BigEndian.Uint16(tcpSegment[2:4])
	seq = binary.BigEndian.Uint32(tcpSegment[4:8])
	flags := tcpSegment[13]

	// TCP flags: SYN is 0x02, ACK is 0x10. We check for a SYN handshake packet (SYN set, ACK not set).
	isSyn = (flags&0x02 != 0) && (flags&0x10 == 0)
	return srcPort, dstPort, seq, isSyn
}

// CraftTCPPacketIPv4 compiles raw IPv4 and TCP header buffers, computes checksums, and returns a unified packet slice.
func CraftTCPPacketIPv4(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte, ttl uint32) []byte {
	// IP header (20 bytes)
	ip := make([]byte, 20)
	ip[0] = 0x45 // Version 4, IHL 5
	ip[1] = 0x00 // TOS
	totalLen := 20 + 20 + len(payload)
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	
	nBig, _ := rand.Int(rand.Reader, big.NewInt(65535))
	binary.BigEndian.PutUint16(ip[4:6], uint16(nBig.Int64()))
	ip[6] = 0x40 // Flags: Don't Fragment (DF)
	ip[7] = 0x00
	ip[8] = uint8(ttl)
	ip[9] = 6 // Protocol: TCP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())

	// IP Checksum
	binary.BigEndian.PutUint16(ip[10:12], internetChecksum(ip))

	// TCP Header (20 bytes)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 0x50 // Data offset: 5 (20 bytes)
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 64240) // Window size

	// TCP Checksum pseudo-header calculation
	pseudo := make([]byte, 12+20+len(payload))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[8] = 0
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(20+len(payload)))
	copy(pseudo[12:32], tcp)
	copy(pseudo[32:], payload)

	binary.BigEndian.PutUint16(tcp[16:18], internetChecksum(pseudo))

	// Assemble final packet
	packet := append(ip, tcp...)
	packet = append(packet, payload...)
	return packet
}

// CraftTCPPacketIPv6 compiles raw IPv6 and TCP header buffers, computes checksums, and returns a unified packet slice.
func CraftTCPPacketIPv6(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte, hopLimit uint32) []byte {
	// IPv6 Header (40 bytes)
	ip := make([]byte, 40)
	ip[0] = 0x60 // Version 6
	// Payload length (TCP header 20 bytes + payload)
	binary.BigEndian.PutUint16(ip[4:6], uint16(20+len(payload)))
	ip[6] = 6 // Next Header: TCP
	ip[7] = uint8(hopLimit)
	copy(ip[8:24], srcIP.To16())
	copy(ip[24:40], dstIP.To16())

	// TCP Header (20 bytes)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 0x50 // Data offset: 5 (20 bytes)
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 64240) // Window size

	// TCP Checksum pseudo-header calculation for IPv6
	pseudo := make([]byte, 40+20+len(payload))
	copy(pseudo[0:16], srcIP.To16())
	copy(pseudo[16:32], dstIP.To16())
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(20+len(payload)))
	pseudo[39] = 6 // Next Header: TCP
	copy(pseudo[40:60], tcp)
	copy(pseudo[60:], payload)

	binary.BigEndian.PutUint16(tcp[16:18], internetChecksum(pseudo))

	// Assemble final packet
	packet := append(ip, tcp...)
	packet = append(packet, payload...)
	return packet
}

// CraftTCPPacket compiles raw IP and TCP header buffers, computes checksums, and returns a unified packet slice.
func CraftTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte, ttl uint32) []byte {
	if srcIP.To4() != nil && dstIP.To4() != nil {
		return CraftTCPPacketIPv4(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload, ttl)
	}
	return CraftTCPPacketIPv6(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload, ttl)
}

// rawBypassConn implements net.Conn for the GFW Raw Handshake Bypass (paqet mechanics)
type rawBypassConn struct {
	localIP      net.IP
	remoteIP     net.IP
	localPort    uint16
	remotePort   uint16
	seq          uint32
	ack          uint32
	readChan     chan []byte
	closed       chan struct{}
	closeOnce    sync.Once
	readDeadline time.Time
	readBuf      []byte
}

func (c *rawBypassConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: c.localIP, Port: int(c.localPort)}
}

func (c *rawBypassConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: c.remoteIP, Port: int(c.remotePort)}
}

func (c *rawBypassConn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *rawBypassConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *rawBypassConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *rawBypassConn) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, fmt.Errorf("connection closed")
	default:
	}

	// Craft and inject PSH-ACK packet (flags = 0x18)
	err := InjectWindowsDivertPacket(c.localIP, c.remoteIP, c.localPort, c.remotePort, 64, 0x18, c.seq, c.ack, b)
	if err != nil {
		return 0, err
	}

	// Update seq number
	c.seq = (c.seq + uint32(len(b))) & 0xFFFFFFFF
	return len(b), nil
}

func (c *rawBypassConn) Read(b []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	var timeoutChan <-chan time.Time
	if !c.readDeadline.IsZero() {
		duration := time.Until(c.readDeadline)
		if duration <= 0 {
			return 0, context.DeadlineExceeded
		}
		timeoutChan = time.After(duration)
	}

	select {
	case <-c.closed:
		return 0, fmt.Errorf("connection closed")
	case payload := <-c.readChan:
		n := copy(b, payload)
		if n < len(payload) {
			c.readBuf = payload[n:]
		}
		return n, nil
	case <-timeoutChan:
		return 0, context.DeadlineExceeded
	}
}

func (c *rawBypassConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = RemoveRstDropRule(c.remoteIP.String())
	})
	return nil
}

func getLocalIPForDst(dst net.IP) (net.IP, error) {
	conn, err := net.Dial("udp", dst.String()+":80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP, nil
}

func findFreeLocalPort() (uint16, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port), nil
}

// DialRawBypass connects to the remote host using GFW Raw Handshake Bypass (paqet)
func DialRawBypass(ctx context.Context, host string, port uint16) (net.Conn, error) {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("failed to resolve host %s: %w", host, err)
	}
	remoteIP := ips[0].To4()
	if remoteIP == nil {
		return nil, fmt.Errorf("IPv6 raw bypass connection not supported yet")
	}

	localIP, err := getLocalIPForDst(remoteIP)
	if err != nil {
		return nil, fmt.Errorf("failed to determine local interface IP: %w", err)
	}

	localPort, err := findFreeLocalPort()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate local port: %w", err)
	}

	var seqVal uint32
	nBig, randErr := rand.Int(rand.Reader, big.NewInt(4294967295))
	if randErr == nil {
		seqVal = uint32(nBig.Uint64())
	} else {
		seqVal = 1000
	}

	conn := &rawBypassConn{
		localIP:    localIP,
		remoteIP:   remoteIP,
		localPort:  localPort,
		remotePort: port,
		seq:        seqVal,
		ack:        0,
		readChan:   make(chan []byte, 100),
		closed:     make(chan struct{}),
	}

	// Install the RST drop rule first
	_ = InstallRstDropRule(remoteIP.String())

	// Start the platform-specific sniffer
	StartBypassSniffer(conn)

	return conn, nil
}

