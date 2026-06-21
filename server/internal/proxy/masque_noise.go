package proxy

import (
	"crypto/rand"
	"encoding/binary"
	mathrand "math/rand"
	"net"
	"sync"
	"time"
)

var rng = mathrand.New(mathrand.NewSource(time.Now().UnixNano()))

// NoizeConfig defines configuration parameters for MASQUE protocol mimicry and padding.
type NoizeConfig struct {
	I1               string        // Main signature packet (mimics STUN, DNS, HTTP, etc.)
	I2               string        // Secondary signature packet
	I3               string        // Tertiary signature packet
	I4               string        // Additional signature packet
	I5               string        // Additional signature packet
	FragmentSize     int           // Fragment size for Initial packets
	FragmentInitial  bool          // Fragment initial packets
	FragmentDelay    time.Duration // Delay between sending fragments
	PaddingMin       int           // Minimum padding size
	PaddingMax       int           // Maximum padding size
	RandomPadding    bool          // Enable random padding size
	Jc               int           // Total junk packets
	Jmin             int           // Minimum junk packet size
	Jmax             int           // Maximum junk packet size
	JcBeforeHS       int           // Junk packets before handshake
	JcAfterI1        int           // Junk packets after I1 signature
	JcDuringHS       int           // Junk packets during handshake
	JcAfterHS        int           // Junk packets after handshake
	JunkInterval     time.Duration // Delay between junk packets
	JunkRandom       bool          // Randomize junk sizes
	HandshakeDelay   time.Duration // Delay before starting handshake
	MimicProtocol    string        // Protocol to mimic: "dns", "https", "stun"
	RandomDelay      bool          // Enable random delays
	DelayMin         time.Duration // Minimum random delay
	DelayMax         time.Duration // Maximum random delay
	SNIFragmentation bool          // Enable SNI segment fragmentation
	SNIFragment      int           // SNI fragment size
	UseTimestamp     bool          // Add timestamp to signatures
	UseNonce         bool          // Add nonce to signatures
	RandomizeInitial bool          // Randomize initial packet
	AllowZeroSize    bool          // Allow 0-byte junk packets
	DuplicatePackets bool          // Duplicate packets to bypass firewalls
	FakeLoss         float64       // Simulate packet loss
}

// DefaultNoizeConfig returns a configured default set of obfuscation parameters.
func DefaultNoizeConfig() *NoizeConfig {
	return &NoizeConfig{
		I1:            "<b 00010008><r 12>", // Default STUN mimicry preflight signature
		FragmentSize:  512,
		FragmentDelay: 2 * time.Millisecond,
		PaddingMin:    16,
		PaddingMax:    64,
		Jc:            4,
		Jmin:          32,
		Jmax:          128,
		JcBeforeHS:    2,
		JcAfterI1:     1,
		JunkInterval:  5 * time.Millisecond,
		MimicProtocol: "stun",
	}
}

// MinimalObfuscationConfig returns very light obfuscation, least likely to break handshake.
func MinimalObfuscationConfig() *NoizeConfig {
	return &NoizeConfig{
		I1:               "<b 474554202f20485454502f312e31><r 8>", // HTTP GET signature
		FragmentSize:     1280,
		FragmentInitial:  true,
		FragmentDelay:    3 * time.Millisecond,
		PaddingMin:       1,
		PaddingMax:       0,
		RandomPadding:    false,
		Jc:               8,
		JcBeforeHS:       3,
		JcAfterI1:        2,
		JcDuringHS:       3,
		JcAfterHS:        4,
		Jmin:             40,
		Jmax:             1285,
		JunkInterval:     5 * time.Millisecond,
		JunkRandom:       true,
		HandshakeDelay:   5 * time.Millisecond,
		MimicProtocol:    "",
		RandomDelay:      true,
		DelayMin:         5 * time.Millisecond,
		DelayMax:         15 * time.Millisecond,
		SNIFragmentation: true,
		UseTimestamp:     true,
		UseNonce:         true,
		RandomizeInitial: true,
		AllowZeroSize:    true,
	}
}

// LightObfuscationConfig returns minimal obfuscation with junk packets to bypass DPI.
func LightObfuscationConfig() *NoizeConfig {
	return &NoizeConfig{
		I1:               "<b 474554202f20485454502f312e31><r 8>", // HTTP GET signature
		FragmentInitial:  false,
		PaddingMin:       0,
		PaddingMax:       0,
		RandomPadding:    false,
		Jc:               8,
		JcBeforeHS:       2,
		JcAfterI1:        1,
		JcDuringHS:       2,
		JcAfterHS:        3,
		Jmin:             40,
		Jmax:             120,
		JunkInterval:     3 * time.Millisecond,
		JunkRandom:       true,
		HandshakeDelay:   5 * time.Millisecond,
		MimicProtocol:    "",
		RandomDelay:      true,
		DelayMin:         1 * time.Millisecond,
		DelayMax:         5 * time.Millisecond,
		SNIFragmentation: true,
		UseTimestamp:     false,
		UseNonce:         true,
		RandomizeInitial: true,
		AllowZeroSize:    false,
	}
}

// MediumObfuscationConfig returns balanced obfuscation config.
func MediumObfuscationConfig() *NoizeConfig {
	return DefaultNoizeConfig()
}

// HeavyObfuscationConfig returns maximum obfuscation with higher overhead.
func HeavyObfuscationConfig() *NoizeConfig {
	return &NoizeConfig{
		I1:               "<b 0d0a0d0a><t><r 32>",
		I2:               "<b 474554202f20485454502f312e31><r 16>",
		I3:               "<r 64>",
		FragmentSize:     1280,
		FragmentInitial:  true,
		FragmentDelay:    3 * time.Millisecond,
		PaddingMin:       3,
		PaddingMax:       12,
		RandomPadding:    true,
		Jc:               10,
		Jmin:             128,
		Jmax:             512,
		JcBeforeHS:       3,
		JcAfterI1:        2,
		JcDuringHS:       2,
		JcAfterHS:        3,
		JunkInterval:     8 * time.Millisecond,
		JunkRandom:       true,
		MimicProtocol:    "",
		HandshakeDelay:   20 * time.Millisecond,
		RandomDelay:      true,
		DelayMin:         2 * time.Millisecond,
		DelayMax:         15 * time.Millisecond,
		SNIFragmentation: true,
		SNIFragment:      16,
		UseTimestamp:     true,
		UseNonce:         true,
		RandomizeInitial: true,
	}
}

// StealthObfuscationConfig looks like regular HTTPS traffic.
func StealthObfuscationConfig() *NoizeConfig {
	return &NoizeConfig{
		I1:               "<b 160301><r 2><b 0100>", // TLS ClientHello start
		MimicProtocol:    "",
		PaddingMin:       16,
		PaddingMax:       18,
		RandomPadding:    false,
		Jc:               3,
		Jmin:             40,
		Jmax:             200,
		JcBeforeHS:       1,
		JcAfterI1:        1,
		JcAfterHS:        1,
		JunkInterval:     10 * time.Millisecond,
		HandshakeDelay:   15 * time.Millisecond,
		RandomDelay:      true,
		DelayMin:         5 * time.Millisecond,
		DelayMax:         25 * time.Millisecond,
		UseTimestamp:     false,
		RandomizeInitial: false,
	}
}

// GFWBypassConfig is specifically designed to bypass the Great Firewall.
func GFWBypassConfig() *NoizeConfig {
	return &NoizeConfig{
		I1:               "<b 0d0a0d0a><t><r 24>",
		I2:               "<r 48>",
		FragmentSize:     1200,
		FragmentInitial:  false,
		FragmentDelay:    3 * time.Millisecond,
		PaddingMin:       8,
		PaddingMax:       12,
		RandomPadding:    true,
		Jc:               8,
		Jmin:             64,
		Jmax:             384,
		JcBeforeHS:       3,
		JcAfterI1:        2,
		JcDuringHS:       2,
		JcAfterHS:        1,
		JunkInterval:     3 * time.Millisecond,
		JunkRandom:       true,
		MimicProtocol:    "",
		HandshakeDelay:   25 * time.Millisecond,
		RandomDelay:      true,
		DelayMin:         1 * time.Millisecond,
		DelayMax:         20 * time.Millisecond,
		SNIFragmentation: true,
		SNIFragment:      8,
		UseTimestamp:     true,
		UseNonce:         true,
		RandomizeInitial: true,
		DuplicatePackets: false,
		FakeLoss:         0.02,
	}
}

// FirewallBypassConfig is a working firewall circumvention configuration.
func FirewallBypassConfig() *NoizeConfig {
	return &NoizeConfig{
		I1:               "<b 0d0a0d0a><t><r 24>",
		I2:               "<r 48>",
		FragmentSize:     1200,
		FragmentInitial:  false,
		FragmentDelay:    2 * time.Millisecond,
		PaddingMin:       2,
		PaddingMax:       6,
		RandomPadding:    false,
		Jc:               6,
		Jmin:             48,
		Jmax:             190,
		JcBeforeHS:       2,
		JcAfterI1:        2,
		JcDuringHS:       2,
		JcAfterHS:        2,
		JunkInterval:     4 * time.Millisecond,
		JunkRandom:       true,
		MimicProtocol:    "",
		HandshakeDelay:   5 * time.Millisecond,
		RandomDelay:      true,
		DelayMin:         2 * time.Millisecond,
		DelayMax:         12 * time.Millisecond,
		SNIFragmentation: false,
		SNIFragment:      12,
		UseTimestamp:     false,
		UseNonce:         true,
		RandomizeInitial: false,
		DuplicatePackets: false,
		FakeLoss:         0.01,
	}
}

// NoObfuscationConfig disables all obfuscation.
func NoObfuscationConfig() *NoizeConfig {
	return &NoizeConfig{
		Jc:              0,
		FragmentInitial: false,
		PaddingMin:      0,
		PaddingMax:      0,
		HandshakeDelay:  0,
	}
}

// NoizeUDPConn wraps a net.PacketConn to apply active preflight pacing and obfuscation.
type NoizeUDPConn struct {
	net.PacketConn
	config       *NoizeConfig
	mu           sync.Mutex
	preflightRun map[string]bool // Rates limits preflights to once per destination
}

// NewNoizeUDPConn wraps a packet connection with QUIC obfuscation filters.
func NewNoizeUDPConn(conn net.PacketConn, config *NoizeConfig) *NoizeUDPConn {
	if config == nil {
		config = DefaultNoizeConfig()
	}
	return &NoizeUDPConn{
		PacketConn:   conn,
		config:       config,
		preflightRun: make(map[string]bool),
	}
}

// WriteTo filters and obfuscates outgoing packets, running preflight sequences on handshakes.
func (c *NoizeUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if len(b) == 0 {
		return c.PacketConn.WriteTo(b, addr)
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return c.PacketConn.WriteTo(b, addr)
	}

	addrKey := udpAddr.String()
	c.mu.Lock()
	alreadyRun := c.preflightRun[addrKey]
	if !alreadyRun {
		c.preflightRun[addrKey] = true
		c.mu.Unlock()

		// Execute pre-handshake obfuscation sequence synchronously/asynchronously
		c.executePreHandshake(udpAddr)
	} else {
		c.mu.Unlock()
	}

	// Fragment Initial QUIC packets if configured
	if c.config.FragmentSize > 0 && len(b) > c.config.FragmentSize && detectQUICInitial(b) {
		return c.fragmentInitialWrite(b, udpAddr)
	}

	// Apply padding
	payload := c.addPadding(b)

	// Apply protocol wrappers
	payload = c.wrapProtocol(payload)

	return c.PacketConn.WriteTo(payload, addr)
}

func detectQUICInitial(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	// Check if QUIC long header with Initial type (0x00)
	headerByte := b[0]
	return (headerByte&0x80 != 0) && (((headerByte >> 4) & 0x03) == 0x00)
}

func (c *NoizeUDPConn) executePreHandshake(addr *net.UDPAddr) {
	// 1. Send JcBeforeHS junk packets
	if c.config.JcBeforeHS > 0 {
		for i := 0; i < c.config.JcBeforeHS; i++ {
			junk := c.generateJunkPacket()
			if len(junk) > 0 {
				_, _ = c.PacketConn.WriteTo(junk, addr)
			}
			time.Sleep(c.config.JunkInterval)
		}
	}

	// 2. Send I1 Signature
	if c.config.I1 != "" {
		i1Packet, err := parseCPSPacket(c.config.I1)
		if err == nil && len(i1Packet) > 0 {
			_, _ = c.PacketConn.WriteTo(i1Packet, addr)
			time.Sleep(2 * time.Millisecond)
		}
	}

	// 3. Send JcAfterI1 junk packets
	if c.config.JcAfterI1 > 0 {
		for i := 0; i < c.config.JcAfterI1; i++ {
			junk := c.generateJunkPacket()
			if len(junk) > 0 {
				_, _ = c.PacketConn.WriteTo(junk, addr)
			}
			time.Sleep(c.config.JunkInterval)
		}
	}

	// 4. Send signatures I2-I5
	signatures := []string{c.config.I2, c.config.I3, c.config.I4, c.config.I5}
	for _, sig := range signatures {
		if sig == "" {
			continue
		}
		packet, err := parseCPSPacket(sig)
		if err == nil && len(packet) > 0 {
			_, _ = c.PacketConn.WriteTo(packet, addr)
			time.Sleep(1 * time.Millisecond)
		}
	}
}

func (c *NoizeUDPConn) fragmentInitialWrite(b []byte, addr *net.UDPAddr) (int, error) {
	fragmentSize := c.config.FragmentSize
	firstFragment := b[:fragmentSize]

	// Send remaining fragments asynchronously to maintain pipeline speeds
	go func() {
		for offset := fragmentSize; offset < len(b); offset += fragmentSize {
			end := offset + fragmentSize
			if end > len(b) {
				end = len(b)
			}
			fragment := b[offset:end]
			_, _ = c.PacketConn.WriteTo(fragment, addr)
			if c.config.FragmentDelay > 0 {
				time.Sleep(c.config.FragmentDelay)
			}
		}
	}()

	return c.PacketConn.WriteTo(firstFragment, addr)
}

func (c *NoizeUDPConn) addPadding(b []byte) []byte {
	if c.config.PaddingMax <= 0 {
		return b
	}

	paddingSize := c.config.PaddingMin
	if c.config.PaddingMax > c.config.PaddingMin {
		paddingSize = c.config.PaddingMin + rng.Intn(c.config.PaddingMax-c.config.PaddingMin+1)
	}

	if paddingSize <= 0 {
		return b
	}

	// Cap payload sizes to fit inside MTU bounds (e.g. 1200 bytes)
	if len(b)+paddingSize > 1200 {
		paddingSize = 1200 - len(b)
		if paddingSize <= 0 {
			return b
		}
	}

	padding := make([]byte, paddingSize)
	_, _ = rand.Read(padding)
	return append(b, padding...)
}

func (c *NoizeUDPConn) wrapProtocol(b []byte) []byte {
	switch c.config.MimicProtocol {
	case "dns":
		header := make([]byte, 12)
		binary.BigEndian.PutUint16(header[0:2], uint16(rng.Intn(65536))) // Transaction ID
		binary.BigEndian.PutUint16(header[2:4], 0x0100)                  // Flags: Standard query
		binary.BigEndian.PutUint16(header[4:6], 1)                       // Questions: 1
		return append(header, b...)
	case "https":
		header := make([]byte, 5)
		header[0] = 0x17 // Application Data
		header[1] = 0x03 // TLS 1.2
		header[2] = 0x03
		binary.BigEndian.PutUint16(header[3:5], uint16(len(b)))
		return append(header, b...)
	case "stun":
		header := make([]byte, 20)
		binary.BigEndian.PutUint16(header[0:2], 0x0001)          // Binding Request
		binary.BigEndian.PutUint16(header[2:4], uint16(len(b))) // Length
		binary.BigEndian.PutUint32(header[4:8], 0x2112A442)      // Magic Cookie
		_, _ = rand.Read(header[8:20])                           // Transaction ID
		return append(header, b...)
	}
	return b
}

func (c *NoizeUDPConn) generateJunkPacket() []byte {
	min := c.config.Jmin
	max := c.config.Jmax

	if min == 0 && max == 0 {
		if c.config.AllowZeroSize {
			return []byte{}
		}
		min = 32
		max = 64
	}

	size := min
	if max > min {
		size = min + rng.Intn(max-min+1)
	}

	junk := make([]byte, size)
	_, _ = rand.Read(junk)
	return junk
}

// AtomicNoizeWireGuardConn wraps outbound WireGuard traffic to apply decoy framing and junk streams.
type AtomicNoizeWireGuardConn struct {
	net.PacketConn
	config *NoizeConfig
	mu     sync.Mutex
	sent   map[string]bool
}

// NewAtomicNoizeWireGuardConn creates a new obfuscator for WireGuard endpoints.
func NewAtomicNoizeWireGuardConn(conn net.PacketConn, config *NoizeConfig) *AtomicNoizeWireGuardConn {
	return &AtomicNoizeWireGuardConn{
		PacketConn: conn,
		config:     config,
		sent:       make(map[string]bool),
	}
}

// WriteTo intercepts WireGuard packets to inject preflights and frame handshakes.
func (w *AtomicNoizeWireGuardConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if len(b) == 0 {
		return w.PacketConn.WriteTo(b, addr)
	}

	// Detect if it is a WireGuard Handshake Initiation packet (Message Type 1, Size >= 148)
	if len(b) >= 148 && b[0] == 1 {
		addrKey := addr.String()
		w.mu.Lock()
		alreadySent := w.sent[addrKey]
		if !alreadySent {
			w.sent[addrKey] = true
			w.mu.Unlock()

			// Pre-handshake sequence: I1 signature + junk
			w.sendPreflightSequence(addr)
		} else {
			w.mu.Unlock()
		}

		// Warp compatibility constraint: Do NOT prefix standard payload blocks.
		// Re-routing directly prevents Cloudflare rejects.
	}

	return w.PacketConn.WriteTo(b, addr)
}

func (w *AtomicNoizeWireGuardConn) sendPreflightSequence(addr net.Addr) {
	// 1. Send I1 packet with IKEv2 framing
	if w.config.I1 != "" {
		i1Payload, err := parseCPSPacket(w.config.I1)
		if err == nil && len(i1Payload) > 0 {
			framed := wrapInIKEv2Header(i1Payload)
			_, _ = w.PacketConn.WriteTo(framed, addr)
			time.Sleep(2 * time.Millisecond)
		}
	}

	// 2. Send JcBeforeHS junk packets
	if w.config.JcBeforeHS > 0 {
		for i := 0; i < w.config.JcBeforeHS; i++ {
			size := w.config.Jmin
			if w.config.Jmax > w.config.Jmin {
				size = w.config.Jmin + rng.Intn(w.config.Jmax-w.config.Jmin+1)
			}
			junk := make([]byte, size)
			_, _ = rand.Read(junk)
			_, _ = w.PacketConn.WriteTo(junk, addr)
			time.Sleep(w.config.JunkInterval)
		}
	}
}

func wrapInIKEv2Header(payload []byte) []byte {
	// Generate 52 bytes of IKEv2/IPsec SA Init framing
	initiatorSPI := make([]byte, 8)
	_, _ = rand.Read(initiatorSPI)
	responderSPI := make([]byte, 8)
	_, _ = rand.Read(responderSPI)

	totalLength := uint32(28 + 24 + len(payload))
	header := make([]byte, 0, int(totalLength))

	// IKEv2 Header (28 bytes)
	header = append(header, initiatorSPI...)
	header = append(header, responderSPI...)
	header = append(header, 0x21) // Security Association
	header = append(header, 0x20) // Version 2.0
	header = append(header, 0x22) // Exchange Type (IKE_SA_INIT)
	header = append(header, 0x08) // Flags (Initiator)
	header = append(header, 0x00, 0x00, 0x00, 0x00)
	header = append(header, byte(totalLength>>24), byte(totalLength>>16), byte(totalLength>>8), byte(totalLength))

	// Security Association (24 bytes SA + payload)
	saLen := uint16(24 + len(payload))
	header = append(header, 0x00)
	header = append(header, 0x00)
	header = append(header, byte(saLen>>8), byte(saLen))
	header = append(header, 0x00, 0x00, 0x00, 0x14, 0x01, 0x01, 0x00, 0x04)
	header = append(header, 0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x0c)
	header = append(header, 0x00, 0x00, 0x00, 0x00)

	return append(header, payload...)
}
