package covert

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	EnvelopeMagic = "SKB1"
	EnvelopeVer   = byte(1)
	SessionIDLen  = 16
	KeyLen        = 32
	HeaderLen     = 39
	MaxSequence   = uint64(1<<56 - 1)

	DirectionUp   = byte(1)
	DirectionDown = byte(2)
	FlagData      = byte(0)
	FlagFinal     = byte(1)

	InteractiveThreshold = 8 * 1024
	BulkThreshold        = 64 * 1024
	ForcedBulkThreshold  = 256 * 1024
)

// BlobEnvelope represents a parsed covert dead-drop envelope header and payload.
type BlobEnvelope struct {
	SessionID    [16]byte `json:"session_id"`
	Direction    byte     `json:"direction"`
	Sequence     uint64   `json:"sequence"`
	Flags        byte     `json:"flags"`
	PlaintextLen uint32   `json:"plaintext_len"`
	Ciphertext   []byte   `json:"ciphertext"`
}

// ComputeNonce creates the 12-byte AES-GCM nonce:
// sid[0..4] (4 bytes) + direction (1 byte) + sequence (7 bytes big-endian)
func ComputeNonce(sid [16]byte, direction byte, sequence uint64) []byte {
	out := make([]byte, 12)
	copy(out[0:4], sid[:4])
	out[4] = direction
	for i := 0; i < 7; i++ {
		out[11-i] = byte(sequence >> (8 * i))
	}
	return out
}

// DeriveBlobKey derives a 32-byte key from secret string (supports hex:, base64:, or raw string).
func DeriveBlobKey(secret string) ([]byte, error) {
	val := strings.TrimSpace(secret)
	switch {
	case strings.HasPrefix(val, "hex:"):
		raw, err := hex.DecodeString(val[4:])
		if err != nil {
			return nil, err
		}
		if len(raw) != KeyLen {
			return nil, fmt.Errorf("hex key must be %d bytes", KeyLen)
		}
		return raw, nil
	case strings.HasPrefix(val, "base64:"):
		raw, err := base64.StdEncoding.DecodeString(val[7:])
		if err != nil {
			return nil, err
		}
		if len(raw) != KeyLen {
			return nil, fmt.Errorf("base64 key must be %d bytes", KeyLen)
		}
		return raw, nil
	default:
		return hkdfSHA256([]byte(val), []byte("skirk-v1-static-salt"), []byte("skirk-blobq-aead-key"), KeyLen), nil
	}
}

// DeriveMuxLaneKeyV4 derives multi-lane subkeys for a given session, direction, client, run, and lane.
func DeriveMuxLaneKeyV4(secret string, sid [16]byte, direction byte, clientID, runID string, lane int) ([]byte, error) {
	base, err := DeriveBlobKey(secret)
	if err != nil {
		return nil, err
	}
	if lane < 0 || lane > 255 {
		return nil, fmt.Errorf("mux lane out of range: %d", lane)
	}
	clientID = strings.TrimSpace(clientID)
	runID = strings.TrimSpace(runID)
	if clientID == "" || runID == "" {
		return nil, errors.New("client id and run id are required")
	}

	info := make([]byte, 0, len("skirk-mux-lane-aead-v4")+SessionIDLen+len(clientID)+len(runID)+4)
	info = append(info, []byte("skirk-mux-lane-aead-v4")...)
	info = append(info, sid[:]...)
	info = append(info, direction)
	info = append(info, []byte(clientID)...)
	info = append(info, 0)
	info = append(info, []byte(runID)...)
	info = append(info, 0, byte(lane))
	return hkdfSHA256(base, []byte("skirk-v4-mux-lane-salt"), info, KeyLen), nil
}

func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	extract := hmac.New(sha256.New, salt)
	extract.Write(ikm)
	prk := extract.Sum(nil)

	var okm []byte
	var previous []byte
	counter := byte(1)
	for len(okm) < length {
		expand := hmac.New(sha256.New, prk)
		expand.Write(previous)
		expand.Write(info)
		expand.Write([]byte{counter})
		previous = expand.Sum(nil)
		okm = append(okm, previous...)
		counter++
	}
	return okm[:length]
}

// SealBlobEnvelope seals plaintext with AES-256-GCM into a 39-byte header authenticated envelope.
func SealBlobEnvelope(key []byte, sid [16]byte, direction byte, sequence uint64, plaintext []byte, isFinal bool) ([]byte, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("key must be %d bytes", KeyLen)
	}
	if sequence > MaxSequence {
		return nil, errors.New("sequence out of supported nonce range")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	flags := FlagData
	if isFinal {
		flags = FlagFinal
	}

	header := make([]byte, HeaderLen)
	copy(header[0:4], []byte(EnvelopeMagic))
	header[4] = EnvelopeVer
	copy(header[5:21], sid[:])
	header[21] = direction
	header[22] = flags
	binary.BigEndian.PutUint64(header[23:31], sequence)
	binary.BigEndian.PutUint32(header[31:35], uint32(len(plaintext)))
	binary.BigEndian.PutUint32(header[35:39], uint32(len(plaintext)+gcm.Overhead()))

	nonce := ComputeNonce(sid, direction, sequence)
	ciphertext := gcm.Seal(nil, nonce, plaintext, header)

	return append(header, ciphertext...), nil
}

// OpenBlobEnvelope validates header, decrypts ciphertext, and returns the envelope and plaintext.
func OpenBlobEnvelope(key, data []byte) (*BlobEnvelope, []byte, error) {
	if len(data) < HeaderLen {
		return nil, nil, errors.New("envelope too short")
	}

	header := data[:HeaderLen]
	if !bytes.Equal(header[0:4], []byte(EnvelopeMagic)) {
		return nil, nil, errors.New("bad envelope magic")
	}
	if header[4] != EnvelopeVer {
		return nil, nil, fmt.Errorf("unsupported envelope version %d", header[4])
	}

	var sid [16]byte
	copy(sid[:], header[5:21])
	direction := header[21]
	flags := header[22]
	sequence := binary.BigEndian.Uint64(header[23:31])
	plaintextLen := binary.BigEndian.Uint32(header[31:35])
	ciphertextLen := binary.BigEndian.Uint32(header[35:39])

	if int(ciphertextLen) != len(data)-HeaderLen {
		return nil, nil, errors.New("ciphertext length mismatch")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce := ComputeNonce(sid, direction, sequence)
	ciphertext := data[HeaderLen:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, nil, err
	}
	if len(plaintext) != int(plaintextLen) {
		return nil, nil, errors.New("plaintext length mismatch")
	}

	env := &BlobEnvelope{
		SessionID:    sid,
		Direction:    direction,
		Sequence:     sequence,
		Flags:        flags,
		PlaintextLen: plaintextLen,
		Ciphertext:   ciphertext,
	}

	return env, plaintext, nil
}

// CoalesceTier defines latency and age bounds for buffered stream coalescing.
type CoalesceTier int

const (
	TierInteractive CoalesceTier = iota
	TierMedium
	TierBulk
	TierForcedBulk
)

// EvaluateCoalesceTier selects the tier based on buffered bytes.
func EvaluateCoalesceTier(bufferedBytes int) CoalesceTier {
	if bufferedBytes < InteractiveThreshold {
		return TierInteractive
	}
	if bufferedBytes < BulkThreshold {
		return TierMedium
	}
	if bufferedBytes < ForcedBulkThreshold {
		return TierBulk
	}
	return TierForcedBulk
}

// MaxAgeForTier returns the maximum buffering duration before forced flush.
func MaxAgeForTier(tier CoalesceTier) time.Duration {
	switch tier {
	case TierInteractive:
		return 15 * time.Millisecond
	case TierMedium:
		return 75 * time.Millisecond
	case TierBulk:
		return 250 * time.Millisecond
	case TierForcedBulk:
		return 1000 * time.Millisecond
	default:
		return 15 * time.Millisecond
	}
}

// ShouldFlush evaluates whether buffered stream bytes should be dispatched immediately.
func ShouldFlush(bufferedBytes int, age time.Duration) bool {
	if bufferedBytes == 0 {
		return false
	}
	if bufferedBytes >= ForcedBulkThreshold {
		return true
	}
	tier := EvaluateCoalesceTier(bufferedBytes)
	return age >= MaxAgeForTier(tier)
}
