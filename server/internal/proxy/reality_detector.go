package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// RealityVerifier intercepts TLS ClientHello handshakes, verifies client authentication tickets,
// and routes valid clients to the proxy engine or deflects active probes to decoy servers.
type RealityVerifier struct {
	mu           sync.RWMutex
	authKey      []byte
	decoyAddress string
	aead         cipher.AEAD
	isRunning    bool

	// REALITY parameters
	privateKey   []byte
	shortIDs     map[[8]byte]bool
	maxTimeDiff  time.Duration
}

// NewRealityVerifier creates a new RealityVerifier instance using fallback raw GCM.
func NewRealityVerifier(authKey []byte, decoyAddress string) (*RealityVerifier, error) {
	return NewRealityVerifierWithParams(authKey, decoyAddress, nil, nil, 0)
}

// NewRealityVerifierWithParams creates a new RealityVerifier with full cryptographic parameters.
func NewRealityVerifierWithParams(authKey []byte, decoyAddress string, privateKey []byte, shortIDs []string, maxTimeDiff time.Duration) (*RealityVerifier, error) {
	key := make([]byte, 32)
	copy(key, authKey)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize block cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GCM cipher: %w", err)
	}

	sIDMap := make(map[[8]byte]bool)
	for _, idHex := range shortIDs {
		var rawID [8]byte
		n, err := fmt.Sscanf(idHex, "%16x", &rawID)
		if err == nil && n == 1 {
			sIDMap[rawID] = true
		}
	}

	return &RealityVerifier{
		authKey:      authKey,
		decoyAddress: decoyAddress,
		aead:         aead,
		privateKey:   privateKey,
		shortIDs:     sIDMap,
		maxTimeDiff:  maxTimeDiff,
	}, nil
}

// InterceptAndVerify audits a connection stream. If the verification fails, it transparently
// pipes the connection to the decoy target. Otherwise, it returns a wrapped connection.
func (rv *RealityVerifier) InterceptAndVerify(clientConn net.Conn) (net.Conn, bool, error) {
	headerBuffer := make([]byte, 4096)
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read initial header to determine TLS record size
	n, err := io.ReadAtLeast(clientConn, headerBuffer, 5)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read TLS record header: %w", err)
	}

	if headerBuffer[0] != 0x16 {
		_ = clientConn.SetReadDeadline(time.Time{})
		return rv.fallbackToDecoy(clientConn, headerBuffer[:n])
	}

	recordLen := int(binary.BigEndian.Uint16(headerBuffer[3:5]))
	totalExpected := 5 + recordLen
	if totalExpected > len(headerBuffer) {
		return nil, false, fmt.Errorf("TLS ClientHello size exceeds buffer limit: %d", totalExpected)
	}

	// Read the remaining bytes of the complete record
	if n < totalExpected {
		n2, err := io.ReadAtLeast(clientConn, headerBuffer[n:totalExpected], totalExpected-n)
		if err != nil {
			return nil, false, fmt.Errorf("failed to read complete TLS ClientHello: %w", err)
		}
		n += n2
	}

	_ = clientConn.SetReadDeadline(time.Time{})

	// Parse ClientHello to extract SNI and X25519 client key share
	_, peerPub, err := parseClientHello(headerBuffer[:n])
	if err == nil && peerPub != nil && len(rv.privateKey) == 32 {
		// Complete REALITY Decryption flow
		sharedSecret, err := curve25519.X25519(rv.privateKey, peerPub)
		if err == nil {
			clientRandom := headerBuffer[11:43]
			realityKey := make([]byte, 32)
			hkdfReader := hkdf.New(sha256.New, sharedSecret, clientRandom[:20], []byte("REALITY"))
			_, err = io.ReadFull(hkdfReader, realityKey)
			if err == nil {
				block, err := aes.NewCipher(realityKey)
				if err == nil {
					aead, err := cipher.NewGCM(block)
					if err == nil {
						// Session ID is at offset 44 (since length is 32)
						ciphertext := make([]byte, 32)
						copy(ciphertext, headerBuffer[44:76])

						// Create AAD with zeroed session ID
						aad := make([]byte, n)
						copy(aad, headerBuffer[:n])
						for i := 0; i < 32; i++ {
							aad[44+i] = 0
						}

						plaintext := make([]byte, 32)
						_, err = aead.Open(plaintext[:0], clientRandom[20:], ciphertext, aad)
						if err == nil {
							// Verify plaintext parameters: version (4 bytes), time (4 bytes), short ID (8 bytes)
							clientTimeSec := binary.BigEndian.Uint32(plaintext[4:8])
							clientTime := time.Unix(int64(clientTimeSec), 0)

							var shortID [8]byte
							copy(shortID[:], plaintext[8:16])

							timeValid := true
							if rv.maxTimeDiff > 0 {
								diff := time.Since(clientTime)
								if diff < 0 {
									diff = -diff
								}
								if diff > rv.maxTimeDiff {
									timeValid = false
								}
							}

							shortIDValid := true
							if len(rv.shortIDs) > 0 {
								if !rv.shortIDs[shortID] {
									shortIDValid = false
								}
							}

							if timeValid && shortIDValid {
								wrappedConn := &ReplayConn{
									Conn:       clientConn,
									readBuffer: headerBuffer[:n],
									offset:     0,
								}
								return wrappedConn, true, nil
							}
						}
					}
				}
			}
		}
	}

	// Fallback to raw GCM verification (compatibility with previous stub/tests)
	sessionIDOffset := 43
	if n >= 76 && headerBuffer[sessionIDOffset] == 32 {
		ciphertext := headerBuffer[sessionIDOffset+1 : sessionIDOffset+1+32]
		randomOffset := 11
		nonce := headerBuffer[randomOffset+20 : randomOffset+32]

		plaintext := make([]byte, 16)
		_, err = rv.aead.Open(plaintext[:0], nonce, ciphertext, headerBuffer[:sessionIDOffset])
		if err == nil {
			wrappedConn := &ReplayConn{
				Conn:       clientConn,
				readBuffer: headerBuffer[:n],
				offset:     0,
			}
			return wrappedConn, true, nil
		}
	}

	return rv.fallbackToDecoy(clientConn, headerBuffer[:n])
}

func (rv *RealityVerifier) fallbackToDecoy(clientConn net.Conn, clientBuffer []byte) (net.Conn, bool, error) {
	decoyConn, err := net.DialTimeout("tcp", rv.decoyAddress, 4*time.Second)
	if err != nil {
		return nil, false, fmt.Errorf("decoy target connection failed: %w", err)
	}

	_, err = decoyConn.Write(clientBuffer)
	if err != nil {
		decoyConn.Close()
		return nil, false, err
	}

	go func() {
		defer decoyConn.Close()
		defer clientConn.Close()
		_, _ = io.Copy(decoyConn, clientConn)
	}()
	go func() {
		defer decoyConn.Close()
		defer clientConn.Close()
		_, _ = io.Copy(clientConn, decoyConn)
	}()

	return nil, false, nil
}

// parseClientHello parses a TLS ClientHello packet and extracts the SNI and X25519 client public key.
func parseClientHello(data []byte) (sni string, peerPub []byte, err error) {
	if len(data) < 44 {
		return "", nil, fmt.Errorf("truncated client hello header")
	}

	if data[0] != 0x16 || data[5] != 0x01 {
		return "", nil, fmt.Errorf("not a client hello handshake")
	}

	sessionIDLen := int(data[43])
	offset := 44 + sessionIDLen

	if offset+2 > len(data) {
		return "", nil, fmt.Errorf("truncated cipher suites length")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + cipherSuitesLen

	if offset+1 > len(data) {
		return "", nil, fmt.Errorf("truncated compression methods length")
	}
	compressionLen := int(data[offset])
	offset += 1 + compressionLen

	if offset >= len(data) {
		return "", nil, nil
	}

	if offset+2 > len(data) {
		return "", nil, fmt.Errorf("truncated extensions length")
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	end := offset + extensionsLen
	if end > len(data) {
		end = len(data)
	}

	for offset+4 <= end {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > end {
			break
		}

		extData := data[offset : offset+extLen]
		offset += extLen

		if extType == 0 { // Server Name (SNI)
			if len(extData) >= 5 {
				listLen := int(binary.BigEndian.Uint16(extData[0:2]))
				if listLen+2 <= len(extData) {
					sniOffset := 2
					for sniOffset+3 <= len(extData) {
						nameType := extData[sniOffset]
						nameLen := int(binary.BigEndian.Uint16(extData[sniOffset+1 : sniOffset+3]))
						sniOffset += 3
						if sniOffset+nameLen <= len(extData) {
							if nameType == 0 { // host_name
								sni = string(extData[sniOffset : sniOffset+nameLen])
								break
							}
							sniOffset += nameLen
						} else {
							break
						}
					}
				}
			}
		} else if extType == 51 { // Key Share
			if len(extData) >= 2 {
				sharesLen := int(binary.BigEndian.Uint16(extData[0:2]))
				if sharesLen+2 <= len(extData) {
					shareOffset := 2
					for shareOffset+4 <= len(extData) {
						group := binary.BigEndian.Uint16(extData[shareOffset : shareOffset+2])
						keyLen := int(binary.BigEndian.Uint16(extData[shareOffset+2 : shareOffset+4]))
						shareOffset += 4
						if shareOffset+keyLen <= len(extData) {
							if group == 29 && keyLen == 32 { // X25519
								peerPub = make([]byte, 32)
								copy(peerPub, extData[shareOffset:shareOffset+32])
								break
							}
							shareOffset += keyLen
						} else {
							break
						}
					}
				}
			}
		}
	}

	return sni, peerPub, nil
}

// ReplayConn wraps a net.Conn and replays buffered handshake bytes before reading from the socket.
type ReplayConn struct {
	net.Conn
	readBuffer []byte
	offset     int
}

func (c *ReplayConn) Read(b []byte) (int, error) {
	if c.offset < len(c.readBuffer) {
		n := copy(b, c.readBuffer[c.offset:])
		c.offset += n
		return n, nil
	}
	return c.Conn.Read(b)
}
