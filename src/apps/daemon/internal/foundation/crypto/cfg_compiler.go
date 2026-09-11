package crypto

import (
	"bufio"
	"bytes"
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
)

const maxCFGFrameSize = int(^uint16(0))

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
	// The payload and outer frame lengths are both encoded as uint16. Reject
	// oversize input before any narrowing conversion so the wire length can never
	// wrap and cause peers to parse a truncated or desynchronized frame.
	if len(payload) > maxCFGFrameSize {
		return nil, fmt.Errorf("CFG payload too large: %d > %d", len(payload), maxCFGFrameSize)
	}

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

	// Calculate and write padding based on mimicry/entropy-shaping strategy.
	padding := cfg.generateMimicPadding(prng, mimicType)
	frameLen := len(salt) + headerBuf.Len() + len(padding) + len(payload)
	if frameLen > maxCFGFrameSize {
		return nil, fmt.Errorf("CFG frame too large: %d > %d", frameLen, maxCFGFrameSize)
	}

	// Construct overall packet: [Salt (8)] [Header (5)] [Padding (Var)] [Payload (Var)]
	packet := bytes.NewBuffer(make([]byte, 0, frameLen))
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
	if len(packet) > maxCFGFrameSize {
		return nil, fmt.Errorf("CFG frame too large: %d > %d", len(packet), maxCFGFrameSize)
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

	if parsedMagic != expectedMagic {
		return nil, fmt.Errorf("invalid dynamic magic bytes: expected 0x%04x, got 0x%04x", expectedMagic, parsedMagic)
	}
	if parsedFlags != expectedFlags {
		return nil, fmt.Errorf("invalid dynamic flags: expected 0x%02x, got 0x%02x", expectedFlags, parsedFlags)
	}

	totalHeaderLen := 8 + 5
	paddingLen := len(packet) - totalHeaderLen - int(parsedLength)
	if paddingLen < 0 {
		return nil, errors.New("corrupted packet length or missing payload data")
	}

	payloadOffset := totalHeaderLen + paddingLen
	return packet[payloadOffset:], nil
}

func (cfg *CFGCompiler) generateMimicPadding(prng *mrand.Rand, mimicType string) []byte {
	switch strings.ToLower(mimicType) {
	case "https", "tls":
		paddingLen := prng.Intn(32) + 16
		padding := make([]byte, paddingLen)
		padding[0] = 0x16
		padding[1] = 0x03
		padding[2] = 0x01
		binary.BigEndian.PutUint16(padding[3:5], uint16(paddingLen-5))
		for i := 5; i < paddingLen; i++ {
			padding[i] = byte(prng.Intn(256))
		}
		return padding
	case "dns":
		padding := make([]byte, 12)
		binary.BigEndian.PutUint16(padding[0:2], uint16(prng.Uint32()))
		binary.BigEndian.PutUint16(padding[2:4], 0x0100)
		binary.BigEndian.PutUint16(padding[4:6], 0x0001)
		binary.BigEndian.PutUint16(padding[6:8], 0x0000)
		binary.BigEndian.PutUint16(padding[8:10], 0x0000)
		binary.BigEndian.PutUint16(padding[10:12], 0x0000)
		return padding
	case "stun":
		padding := make([]byte, 20)
		binary.BigEndian.PutUint16(padding[0:2], 0x0001)
		binary.BigEndian.PutUint16(padding[2:4], 0x0000)
		binary.BigEndian.PutUint32(padding[4:8], 0x2112A442)
		for i := 8; i < 20; i++ {
			padding[i] = byte(prng.Intn(256))
		}
		return padding
	default:
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
	if len(frame) > maxCFGFrameSize {
		return 0, fmt.Errorf("CFG frame too large: %d > %d", len(frame), maxCFGFrameSize)
	}

	var lengthBuf [2]byte
	binary.BigEndian.PutUint16(lengthBuf[:], uint16(len(frame)))
	if err := writeAll(c.Conn, lengthBuf[:]); err != nil {
		return 0, err
	}
	if err := writeAll(c.Conn, frame); err != nil {
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

	var lengthBuf [2]byte
	if _, err := io.ReadFull(c.reader, lengthBuf[:]); err != nil {
		return 0, err
	}
	length := int(binary.BigEndian.Uint16(lengthBuf[:]))
	if length < 13 {
		return 0, fmt.Errorf("invalid CFG frame length: %d", length)
	}

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

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
