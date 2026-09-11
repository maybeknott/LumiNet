package proxy

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	// VP8Keepalive represents a VP8 keyframe/keepalive synthetic signature header
	VP8Keepalive = []byte{
		0x30, 0x01, 0x00, 0x9d, 0x01, 0x2a, 0x10, 0x00,
		0x10, 0x00, 0x00, 0x47, 0x08, 0x85, 0x85, 0x88,
		0x99, 0x84, 0x88, 0xfc,
	}
	// VP8Interframe represents a VP8 interframe synthetic signature header
	VP8Interframe = []byte{
		0xb1, 0x01, 0x00, 0x08, 0x11, 0x18, 0x00, 0x18,
		0x00, 0x18, 0x58, 0x2f, 0xf4, 0x00, 0x08, 0x00,
		0x00,
	}
)

const (
	VP8KeepaliveLen             = 20
	VP8InterframeLen            = 17
	EpochFieldLen               = 4
	KeepaliveHdrLen             = VP8KeepaliveLen + EpochFieldLen
	InterframeHdrLen            = VP8InterframeLen + EpochFieldLen
	webRTCNonceLen              = chacha20poly1305.NonceSizeX
	webRTCTagLen                = 16
	maxWebRTCWireFrame          = int(^uint16(0))
	MaxWebRTCStegoPayload       = maxWebRTCWireFrame - InterframeHdrLen - webRTCNonceLen - webRTCTagLen
	maxConsecutiveControlFrames = 1024
)

// DeriveSecretFromJoinLink extracts a room ID or token from a WebRTC/VoIP link
func DeriveSecretFromJoinLink(joinLink string) []byte {
	if joinLink == "" {
		return nil
	}
	s := strings.TrimSpace(joinLink)
	s = strings.TrimSuffix(s, "/")
	if idx := strings.Index(s, "?"); idx != -1 {
		s = s[:idx]
	}
	if idx := strings.Index(s, "#"); idx != -1 {
		s = s[:idx]
	}
	if idx := strings.LastIndex(s, "/"); idx != -1 {
		s = s[idx+1:]
	}
	if s == "" {
		return nil
	}
	return []byte(s)
}

// WebRTCStegoObfuscator provides WebRTC/VoIP signatures steganographic packaging
type WebRTCStegoObfuscator struct {
	keyHash    []byte
	localEpoch uint32
	peerEpoch  uint32
	hasPeer    bool
	mu         sync.Mutex
}

// NewWebRTCStegoObfuscator initializes an obfuscation context with a secret token
func NewWebRTCStegoObfuscator(secret []byte) (*WebRTCStegoObfuscator, error) {
	if len(secret) == 0 {
		return nil, errors.New("WebRTCStegoObfuscator requires a non-empty secret")
	}
	h := sha256.Sum256(secret)

	var localEpoch uint32
	for {
		buf := make([]byte, 4)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		localEpoch = binary.BigEndian.Uint32(buf)
		if localEpoch != 0 {
			break
		}
	}

	return &WebRTCStegoObfuscator{
		keyHash:    h[:],
		localEpoch: localEpoch,
	}, nil
}

// EncodeKeepalive generates an authenticated VP8 keepalive frame containing the local epoch.
// Keepalives use AEAD over an empty plaintext so a peer cannot forge control frames or epochs.
func (o *WebRTCStegoObfuscator) EncodeKeepalive() []byte {
	hdr := make([]byte, KeepaliveHdrLen)
	copy(hdr[:VP8KeepaliveLen], VP8Keepalive)
	binary.BigEndian.PutUint32(hdr[VP8KeepaliveLen:], o.localEpoch)

	nonce := make([]byte, webRTCNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil
	}
	aead, err := chacha20poly1305.NewX(o.keyHash)
	if err != nil {
		return nil
	}
	tag := aead.Seal(nil, nonce, nil, hdr)

	frame := make([]byte, 0, len(hdr)+len(nonce)+len(tag))
	frame = append(frame, hdr...)
	frame = append(frame, nonce...)
	frame = append(frame, tag...)
	return frame
}

// EncodeData encrypts a payload and packs it into a VP8 interframe synthetic signature
func (o *WebRTCStegoObfuscator) EncodeData(payload []byte) ([]byte, error) {
	hdr := make([]byte, InterframeHdrLen)
	copy(hdr[:VP8InterframeLen], VP8Interframe)
	binary.BigEndian.PutUint32(hdr[VP8InterframeLen:], o.localEpoch)

	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(o.keyHash)
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, payload, nil)

	var buf bytes.Buffer
	buf.Write(hdr)
	buf.Write(nonce)
	buf.Write(ciphertext)

	return buf.Bytes(), nil
}

// EncryptPayload handles plain payload encryption using XChaCha20-Poly1305
func (o *WebRTCStegoObfuscator) EncryptPayload(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(o.keyHash)
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	var buf bytes.Buffer
	buf.Write(nonce)
	buf.Write(ciphertext)

	return buf.Bytes(), nil
}

// DecryptPayload handles payload decryption
func (o *WebRTCStegoObfuscator) DecryptPayload(data []byte) ([]byte, bool) {
	nonceSize := 24
	tagSize := 16
	if len(data) < nonceSize+tagSize {
		return nil, false
	}
	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	aead, err := chacha20poly1305.NewX(o.keyHash)
	if err != nil {
		return nil, false
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, false
	}

	return plaintext, true
}

// DecodeResult represents details extracted from a decoded WebRTC frame
type DecodeResult struct {
	HasFrame    bool
	SelfEcho    bool
	Keepalive   bool
	PeerRestart bool
	PeerEpoch   uint32
	Payload     []byte
}

// Decode decodes and parses incoming data as a WebRTC stego packet.
func (o *WebRTCStegoObfuscator) Decode(frame []byte) DecodeResult {
	if len(frame) == 0 {
		return DecodeResult{HasFrame: false}
	}

	var hdrLen, epochOff int
	var keepalive bool
	switch {
	case len(frame) >= KeepaliveHdrLen && bytes.Equal(frame[:VP8KeepaliveLen], VP8Keepalive):
		hdrLen = KeepaliveHdrLen
		epochOff = VP8KeepaliveLen
		keepalive = true
	case len(frame) >= InterframeHdrLen && bytes.Equal(frame[:VP8InterframeLen], VP8Interframe):
		hdrLen = InterframeHdrLen
		epochOff = VP8InterframeLen
	default:
		return DecodeResult{HasFrame: false}
	}

	peerEpoch := binary.BigEndian.Uint32(frame[epochOff : epochOff+EpochFieldLen])
	if peerEpoch == o.localEpoch {
		return DecodeResult{HasFrame: true, SelfEcho: true, PeerEpoch: peerEpoch}
	}

	body := frame[hdrLen:]
	if len(body) < webRTCNonceLen+webRTCTagLen {
		return DecodeResult{HasFrame: false}
	}
	nonce := body[:webRTCNonceLen]
	ciphertext := body[webRTCNonceLen:]
	aead, err := chacha20poly1305.NewX(o.keyHash)
	if err != nil {
		return DecodeResult{HasFrame: false}
	}

	var plaintext []byte
	if keepalive {
		plaintext, err = aead.Open(nil, nonce, ciphertext, frame[:hdrLen])
		if err != nil || len(plaintext) != 0 {
			return DecodeResult{HasFrame: false}
		}
	} else {
		plaintext, err = aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return DecodeResult{HasFrame: false}
		}
	}

	res := DecodeResult{HasFrame: true, Keepalive: keepalive, PeerEpoch: peerEpoch, Payload: plaintext}
	o.mu.Lock()
	if !o.hasPeer {
		o.peerEpoch = peerEpoch
		o.hasPeer = true
	} else if o.peerEpoch != peerEpoch {
		o.peerEpoch = peerEpoch
		res.PeerRestart = true
	}
	o.mu.Unlock()
	return res
}

// WebRTCStegoConn wraps a net.Conn to apply WebRTC frame camouflage steganography.
type WebRTCStegoConn struct {
	net.Conn
	obfuscator *WebRTCStegoObfuscator
	reader     *bufio.Reader
	readBuf    bytes.Buffer
	readMu     sync.Mutex
	writeMu    sync.Mutex
}

// NewWebRTCStegoConn creates a new WebRTCStegoConn wrapping a net.Conn.
func NewWebRTCStegoConn(conn net.Conn, secret []byte) (net.Conn, error) {
	obf, err := NewWebRTCStegoObfuscator(secret)
	if err != nil {
		return nil, err
	}
	return &WebRTCStegoConn{
		Conn:       conn,
		obfuscator: obf,
		reader:     bufio.NewReader(conn),
	}, nil
}

func (c *WebRTCStegoConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	written := 0
	for len(b) > 0 {
		chunkLen := len(b)
		if chunkLen > MaxWebRTCStegoPayload {
			chunkLen = MaxWebRTCStegoPayload
		}
		frame, err := c.obfuscator.EncodeData(b[:chunkLen])
		if err != nil {
			return written, err
		}
		if len(frame) > maxWebRTCWireFrame {
			return written, errors.New("WebRTC stego encoded frame exceeds uint16 wire limit")
		}
		var lengthBuf [2]byte
		binary.BigEndian.PutUint16(lengthBuf[:], uint16(len(frame)))
		if _, err := io.Copy(c.Conn, bytes.NewReader(lengthBuf[:])); err != nil {
			return written, err
		}
		if _, err := io.Copy(c.Conn, bytes.NewReader(frame)); err != nil {
			return written, err
		}
		written += chunkLen
		b = b[chunkLen:]
	}
	return written, nil
}

func (c *WebRTCStegoConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(b)
	}

	for skipped := 0; skipped <= maxConsecutiveControlFrames; skipped++ {
		var lengthBuf [2]byte
		if _, err := io.ReadFull(c.reader, lengthBuf[:]); err != nil {
			return 0, err
		}
		length := binary.BigEndian.Uint16(lengthBuf[:])
		if length == 0 {
			return 0, errors.New("invalid zero-length WebRTC stego frame")
		}
		frame := make([]byte, int(length))
		if _, err := io.ReadFull(c.reader, frame); err != nil {
			return 0, err
		}

		res := c.obfuscator.Decode(frame)
		if !res.HasFrame {
			return 0, errors.New("invalid or unauthenticated WebRTC stego frame")
		}
		if res.Keepalive || res.SelfEcho {
			continue
		}
		if len(res.Payload) == 0 {
			continue
		}
		c.readBuf.Write(res.Payload)
		return c.readBuf.Read(b)
	}
	return 0, errors.New("WebRTC stego control-frame budget exceeded")
}
