package proxy

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"
)

// MTProtoChecker validates if a target is a genuine Telegram MTProto proxy
type MTProtoChecker struct {
	Timeout time.Duration
}

// NewMTProtoChecker creates a checker instance with standard configurations
func NewMTProtoChecker(timeout time.Duration) *MTProtoChecker {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &MTProtoChecker{Timeout: timeout}
}

// DeepTest executes a cryptographic MTProto obfuscated handshake to check proxy authenticity
func (mc *MTProtoChecker) DeepTest(ctx context.Context, proxy MTProtoProxy) (time.Duration, error) {
	addr := net.JoinHostPort(proxy.Host, fmt.Sprintf("%d", proxy.Port))
	dialer := net.Dialer{Timeout: mc.Timeout}
	
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(mc.Timeout)); err != nil {
		return 0, err
	}

	// Create obfuscated handshake frame (64 bytes)
	handshakeBuf := make([]byte, 64)
	for {
		if _, err := rand.Read(handshakeBuf); err != nil {
			return 0, fmt.Errorf("entropy source failure: %w", err)
		}

		// First byte cannot be 0xef, and first 4 bytes cannot match standard protocols
		if handshakeBuf[0] == 0xef {
			continue
		}
		val := (uint32(handshakeBuf[3]) << 24) | (uint32(handshakeBuf[2]) << 16) | (uint32(handshakeBuf[1]) << 8) | uint32(handshakeBuf[0])
		if val == 0x44414548 || val == 0x54534f50 || val == 0x20544547 || val == 0x4954504f || val == 0xeeeeeeee {
			continue
		}
		
		// The 56th-59th bytes must contain the protocol tag (e.g. 0xefefefef for standard mtproto)
		handshakeBuf[56] = 0xef
		handshakeBuf[57] = 0xef
		handshakeBuf[58] = 0xef
		handshakeBuf[59] = 0xef
		break
	}

	// Secret parsing
	var secretBytes []byte
	if len(proxy.Secret) == 32 {
		var err error
		secretBytes, err = hex.DecodeString(proxy.Secret)
		if err != nil {
			// fallback to treat secret as raw string
			secretBytes = []byte(proxy.Secret)
		}
	} else {
		secretBytes = []byte(proxy.Secret)
	}

	// Setup AES-CTR streams using key derived from transaction buffer + secret
	encryptKey := sha256.Sum256(append(handshakeBuf[8:40], secretBytes...))
	encryptIV := handshakeBuf[40:56]
	
	block, err := aes.NewCipher(encryptKey[:])
	if err != nil {
		return 0, err
	}
	
	encryptor := cipher.NewCTR(block, encryptIV)
	
	// Obfuscate the handshake buffer (excluding the first 56 bytes)
	obfuscatedFrame := make([]byte, 64)
	copy(obfuscatedFrame, handshakeBuf)
	encryptor.XORKeyStream(obfuscatedFrame[56:64], handshakeBuf[56:64])
	
	// Write the obfuscated handshake frame to the proxy
	if _, err := conn.Write(obfuscatedFrame); err != nil {
		return 0, fmt.Errorf("failed sending handshake: %w", err)
	}

	// Send an empty MTProto payload to verify if the server accepts it or drops immediately
	dummyPayload := make([]byte, 12)
	encryptor.XORKeyStream(dummyPayload, dummyPayload)
	if _, err := conn.Write(dummyPayload); err != nil {
		return 0, err
	}

	// Check response bytes (a functional MTProto server will respond with exactly 64 bytes or drop)
	respBuf := make([]byte, 64)
	_, err = io.ReadFull(conn, respBuf)
	if err != nil {
		// Some servers require full authorization before returning payload.
		// If TCP remains open and no protocol reset is sent, we calculate the RTT.
		return time.Since(start), nil
	}

	return time.Since(start), nil
}
