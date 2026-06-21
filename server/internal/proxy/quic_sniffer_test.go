package proxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/hkdf"
)

func TestSniffQuicInitialSNI_Success(t *testing.T) {
	destConnID := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04}
	version := uint32(quicVersion1)

	// 1. Build a valid TLS ClientHello with a mock SNI
	sniName := "test.quic.website"
	clientHello := buildMockClientHello(sniName)

	// 2. Wrap it inside a CRYPTO frame: Type (0x06), Offset (0), Length, Data
	var cryptoFrame bytes.Buffer
	cryptoFrame.WriteByte(cryptoFrameType) // Frame Type
	cryptoFrame.WriteByte(0)               // Offset (0)
	
	// Length (varint)
	chLen := len(clientHello)
	if chLen < 64 {
		cryptoFrame.WriteByte(byte(chLen))
	} else {
		cryptoFrame.WriteByte(byte(0x40 | (chLen >> 8)))
		cryptoFrame.WriteByte(byte(chLen & 0xff))
	}
	cryptoFrame.Write(clientHello)

	// Padding to ensure we have enough bytes for header protection sample (16 bytes)
	payload := cryptoFrame.Bytes()
	paddingLen := 64 - len(payload)
	if paddingLen > 0 {
		payload = append(payload, make([]byte, paddingLen)...)
	}

	// 3. Secrets derivation
	initialSecret := hkdf.Extract(sha256.New, destConnID, getSalt(version))
	clientSecret := hkdfExpandLabel(sha256.New, initialSecret, "client in", []byte{}, 32)

	key := hkdfExpandLabel(sha256.New, clientSecret, keyLabel(version), nil, 16)
	iv := hkdfExpandLabel(sha256.New, clientSecret, ivLabel(version), nil, 12)
	hpKey := hkdfExpandLabel(sha256.New, clientSecret, hpLabel(version), nil, 16)

	// Setup AES GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM failed: %v", err)
	}

	// Nonce (packet number = 2)
	pn := int64(2)
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], uint64(pn))
	for i := range iv {
		nonce[i] ^= iv[i]
	}

	// Construct header (Initial packet, version 1, dest CID len 8, src CID len 0)
	var header bytes.Buffer
	// 0xc0 represents Long Header, Packet Type = Initial (00), and Packet Number Length - 1 = 3 (for 4 bytes PN)
	header.WriteByte(0xc3) 
	
	verBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(verBytes, version)
	header.Write(verBytes)

	header.WriteByte(byte(len(destConnID)))
	header.Write(destConnID)
	header.WriteByte(0) // Src Connection ID Length = 0
	header.WriteByte(0) // Token Length = 0

	// Length = cipherPayloadLen + 4 (packet number len)
	payloadLen := len(payload) + 16 // GCM auth tag size is 16
	totalLen := payloadLen + 4
	if totalLen < 64 {
		header.WriteByte(byte(totalLen))
	} else {
		header.WriteByte(byte(0x40 | (totalLen >> 8)))
		header.WriteByte(byte(totalLen & 0xff))
	}

	headerBytes := header.Bytes()
	headerOffset := len(headerBytes)

	// Encrypt payload
	authHeader := make([]byte, headerOffset+4)
	copy(authHeader, headerBytes)
	binary.BigEndian.PutUint32(authHeader[headerOffset:], uint32(pn))

	ciphertext := aead.Seal(nil, nonce, payload, authHeader)

	// Header protection
	hpBlock, err := aes.NewCipher(hpKey)
	if err != nil {
		t.Fatalf("aes.NewCipher for hpKey failed: %v", err)
	}
	sample := ciphertext[0:16] // Sample is 16 bytes starting 4 bytes after PN offset (which is start of ciphertext for 4-byte PN)
	mask := make([]byte, hpBlock.BlockSize())
	hpBlock.Encrypt(mask, sample)

	// Apply header protection to type byte and packet number
	authHeader[0] ^= mask[0] & 0x0f
	for i := 0; i < 4; i++ {
		authHeader[headerOffset+i] ^= mask[1+i]
	}

	// Build full packet
	packet := append(authHeader, ciphertext...)

	// 4. Sniff SNI
	sniffed, err := SniffQuicInitialSNI(packet)
	if err != nil {
		t.Fatalf("SniffQuicInitialSNI failed: %v", err)
	}

	if sniffed != sniName {
		t.Errorf("Expected sniffed SNI %q, got %q", sniName, sniffed)
	}
}

func buildMockClientHello(sni string) []byte {
	var ch bytes.Buffer
	ch.WriteByte(0x01) // Handshake type: ClientHello
	
	// Skip handshake length (bytes 1-3), we will patch it at the end
	ch.Write([]byte{0, 0, 0})
	
	ch.Write([]byte{0x03, 0x03}) // Version: TLS 1.2
	ch.Write(make([]byte, 32))   // Random: 32 bytes of zeros
	ch.WriteByte(0)              // Session ID length: 0

	// Cipher Suites: Length 2, Suite TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
	ch.Write([]byte{0, 2, 0, 0x2f})
	
	ch.WriteByte(1) // Compression Methods: Length 1
	ch.WriteByte(0) // Compression Method: null

	// Extensions
	var ext bytes.Buffer
	// Extension type: Server Name (0x0000)
	ext.Write([]byte{0, 0})
	
	// Server Name list
	var snList bytes.Buffer
	snList.WriteByte(0) // Name type: host_name
	
	sniBytes := []byte(sni)
	sniLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sniLenBytes, uint16(len(sniBytes)))
	snList.Write(sniLenBytes)
	snList.Write(sniBytes)

	snListBytes := snList.Bytes()
	snListTotalLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(snListTotalLenBytes, uint16(len(snListBytes)))

	// Extension data length = len(snListTotalLenBytes) + len(snListBytes)
	extDataLen := 2 + len(snListBytes)
	extDataLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(extDataLenBytes, uint16(extDataLen))
	ext.Write(extDataLenBytes)

	ext.Write(snListTotalLenBytes)
	ext.Write(snListBytes)

	extBytes := ext.Bytes()
	extTotalLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(extTotalLenBytes, uint16(len(extBytes)))
	
	ch.Write(extTotalLenBytes)
	ch.Write(extBytes)

	res := ch.Bytes()
	// Patch Handshake length (bytes 1-3)
	totalHandshakeLen := len(res) - 4
	res[1] = byte(totalHandshakeLen >> 16)
	res[2] = byte((totalHandshakeLen >> 8) & 0xff)
	res[3] = byte(totalHandshakeLen & 0xff)

	return res
}
