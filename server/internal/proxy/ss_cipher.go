package proxy

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Standard Shadowsocks errors
var (
	ErrReplayAttack = errors.New("shadowsocks: replay attack detected")
	ErrCipherSize   = errors.New("shadowsocks: invalid cipher key size")
	ErrSaltSize     = errors.New("shadowsocks: invalid salt size")
)

// Kdf derives keys using MD5 repetitions, as defined in standard Shadowsocks.
func Kdf(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}

// ReplayCache implements a thread-safe, bounded, high-performance O(1) cache
// using a map and a circular queue to prevent reuse of observed salts.
type ReplayCache struct {
	mu       sync.Mutex
	capacity int
	seen     map[string]struct{}
	queue    []string
	head     int
}

// NewReplayCache instantiates a ReplayCache with the specified capacity.
func NewReplayCache(capacity int) *ReplayCache {
	if capacity <= 0 {
		capacity = 50000
	}
	return &ReplayCache{
		capacity: capacity,
		seen:     make(map[string]struct{}),
		queue:    make([]string, capacity),
	}
}

// CheckAndAdd checks if a salt was already seen. If seen, returns false.
// If new, adds it to the cache and returns true.
func (c *ReplayCache) CheckAndAdd(salt []byte) bool {
	if len(salt) == 0 {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	key := string(salt)
	if _, exists := c.seen[key]; exists {
		return false
	}

	c.seen[key] = struct{}{}
	oldKey := c.queue[c.head]
	if oldKey != "" {
		delete(c.seen, oldKey)
	}

	c.queue[c.head] = key
	c.head = (c.head + 1) % c.capacity
	return true
}

// Increment little-endian encoded nonce byte slice.
func incrementNonce(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

// AEAD Conn constants
const (
	MaxPayloadSize = 0x3FFF    // 16383 bytes
	AEADNonceSize  = 12        // GCM and ChaCha20Poly1305 nonce size
)

// AEADConn represents a net.Conn wrapped with authenticated encryption.
type AEADConn struct {
	net.Conn
	encKey   []byte
	decKey   []byte
	encSalt  []byte
	decSalt  []byte
	method   string
	rNonce   [AEADNonceSize]byte
	wNonce   [AEADNonceSize]byte
	rAEAD    cipher.AEAD
	wAEAD    cipher.AEAD
	rBuf     []byte
	rOff     int
	rLen     int
	initOnce sync.Once
	cache    *ReplayCache
}

// NewAEADConn creates an AEAD encrypted connection.
func NewAEADConn(c net.Conn, method, password string, cache *ReplayCache) (*AEADConn, error) {
	var keyLen int
	switch strings.ToLower(method) {
	case "aes-128-gcm":
		keyLen = 16
	case "aes-256-gcm", "chacha20-ietf-poly1305":
		keyLen = 32
	default:
		return nil, fmt.Errorf("shadowsocks: unsupported cipher method: %s", method)
	}

	psk := Kdf(password, keyLen)
	return &AEADConn{
		Conn:   c,
		encKey: psk,
		decKey: psk,
		method: strings.ToLower(method),
		cache:  cache,
		rBuf:   make([]byte, 2+16+MaxPayloadSize+16), // Max buffer to decrypt single frame
	}, nil
}

// deriveSubkey derives the session AEAD subkey using HKDF-SHA1.
func deriveSubkey(psk, salt []byte, keyLen int) (cipher.AEAD, error) {
	subkey := make([]byte, keyLen)
	r := hkdf.New(sha1.New, psk, salt, []byte("ss-subkey"))
	if _, err := io.ReadFull(r, subkey); err != nil {
		return nil, err
	}

	switch keyLen {
	case 16, 32:
		block, err := aes.NewCipher(subkey)
		if err != nil {
			if keyLen == 32 {
				// Try ChaCha20Poly1305 if AES fails or for chacha20 method
				return chacha20poly1305.New(subkey)
			}
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		return nil, ErrCipherSize
	}
}

func (c *AEADConn) initDecrypter() error {
	saltSize := len(c.encKey)
	if saltSize < 16 {
		saltSize = 16
	}
	c.decSalt = make([]byte, saltSize)
	if _, err := io.ReadFull(c.Conn, c.decSalt); err != nil {
		return err
	}

	if c.cache != nil && !c.cache.CheckAndAdd(c.decSalt) {
		return ErrReplayAttack
	}

	var aead cipher.AEAD
	var err error
	if c.method == "chacha20-ietf-poly1305" {
		subkey := make([]byte, 32)
		r := hkdf.New(sha1.New, c.decKey, c.decSalt, []byte("ss-subkey"))
		if _, err = io.ReadFull(r, subkey); err != nil {
			return err
		}
		aead, err = chacha20poly1305.New(subkey)
	} else {
		aead, err = deriveSubkey(c.decKey, c.decSalt, len(c.decKey))
	}
	if err != nil {
		return err
	}

	c.rAEAD = aead
	return nil
}

func (c *AEADConn) initEncrypter() error {
	saltSize := len(c.encKey)
	if saltSize < 16 {
		saltSize = 16
	}
	c.encSalt = make([]byte, saltSize)
	if _, err := rand.Read(c.encSalt); err != nil {
		return err
	}

	var aead cipher.AEAD
	var err error
	if c.method == "chacha20-ietf-poly1305" {
		subkey := make([]byte, 32)
		r := hkdf.New(sha1.New, c.encKey, c.encSalt, []byte("ss-subkey"))
		if _, err = io.ReadFull(r, subkey); err != nil {
			return err
		}
		aead, err = chacha20poly1305.New(subkey)
	} else {
		aead, err = deriveSubkey(c.encKey, c.encSalt, len(c.encKey))
	}
	if err != nil {
		return err
	}

	c.wAEAD = aead
	if _, err := c.Conn.Write(c.encSalt); err != nil {
		return err
	}
	return nil
}

// Read decrypts shadowsocks stream data.
func (c *AEADConn) Read(b []byte) (int, error) {
	if c.rAEAD == nil {
		if err := c.initDecrypter(); err != nil {
			return 0, err
		}
	}

	if c.rOff < c.rLen {
		n := copy(b, c.rBuf[c.rOff:c.rLen])
		c.rOff += n
		return n, nil
	}

	// Read frame size header: 2 bytes payload size + tag (16 bytes)
	tagLen := c.rAEAD.Overhead()
	headerSize := 2 + tagLen
	headerBuf := make([]byte, headerSize)
	if _, err := io.ReadFull(c.Conn, headerBuf); err != nil {
		return 0, err
	}

	_, err := c.rAEAD.Open(headerBuf[:0], c.rNonce[:], headerBuf, nil)
	incrementNonce(c.rNonce[:])
	if err != nil {
		return 0, fmt.Errorf("shadowsocks: decrypt payload size failed: %w", err)
	}

	payloadLen := int(binary.BigEndian.Uint16(headerBuf[:2])) & MaxPayloadSize
	if payloadLen == 0 {
		return 0, io.ErrUnexpectedEOF
	}

	// Read payload: payloadLen + tag (16 bytes)
	encryptedPayloadSize := payloadLen + tagLen
	payloadBuf := make([]byte, encryptedPayloadSize)
	if _, err := io.ReadFull(c.Conn, payloadBuf); err != nil {
		return 0, err
	}

	_, err = c.rAEAD.Open(payloadBuf[:0], c.rNonce[:], payloadBuf, nil)
	incrementNonce(c.rNonce[:])
	if err != nil {
		return 0, fmt.Errorf("shadowsocks: decrypt payload failed: %w", err)
	}

	c.rOff = 0
	c.rLen = payloadLen
	copy(c.rBuf[:payloadLen], payloadBuf[:payloadLen])

	n := copy(b, c.rBuf[c.rOff:c.rLen])
	c.rOff += n
	return n, nil
}

// Write encrypts and sends stream data.
func (c *AEADConn) Write(b []byte) (int, error) {
	if c.wAEAD == nil {
		if err := c.initEncrypter(); err != nil {
			return 0, err
		}
	}

	written := 0
	tagLen := c.wAEAD.Overhead()
	headerBuf := make([]byte, 2+tagLen)
	payloadBuf := make([]byte, MaxPayloadSize+tagLen)

	for len(b) > 0 {
		chunkSize := len(b)
		if chunkSize > MaxPayloadSize {
			chunkSize = MaxPayloadSize
		}

		// Encrypt header
		binary.BigEndian.PutUint16(headerBuf[:2], uint16(chunkSize))
		c.wAEAD.Seal(headerBuf[:0], c.wNonce[:], headerBuf[:2], nil)
		incrementNonce(c.wNonce[:])

		// Encrypt payload
		c.wAEAD.Seal(payloadBuf[:0], c.wNonce[:], b[:chunkSize], nil)
		incrementNonce(c.wNonce[:])

		if _, err := c.Conn.Write(headerBuf); err != nil {
			return written, err
		}
		if _, err := c.Conn.Write(payloadBuf[:chunkSize+tagLen]); err != nil {
			return written, err
		}

		b = b[chunkSize:]
		written += chunkSize
	}

	return written, nil
}

// Obfuscation connection overlay
type ObfsConn struct {
	net.Conn
	isClient    bool
	mode        string // "http", "tls", "http_simple", "tls1.2"
	host        string
	param       string
	handshook   bool
	handshakeMu sync.Mutex
	readBuf     bytes.Buffer
}

// NewObfsConn wraps a net.Conn with obfuscation overlays.
func NewObfsConn(c net.Conn, mode, host, param string, isClient bool) *ObfsConn {
	return &ObfsConn{
		Conn:     c,
		isClient: isClient,
		mode:     strings.ToLower(mode),
		host:     host,
		param:    param,
	}
}

func (o *ObfsConn) performHandshake(initialWriteData []byte) error {
	o.handshakeMu.Lock()
	defer o.handshakeMu.Unlock()

	if o.handshook {
		return nil
	}

	if o.isClient {
		switch o.mode {
		case "http", "simple-obfs-http":
			req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\nAccept: */*\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", o.host)
			if _, err := o.Conn.Write([]byte(req)); err != nil {
				return err
			}
			// Read response headers
			headerEnd := []byte("\r\n\r\n")
			buf := make([]byte, 1024)
			var received []byte
			for {
				n, err := o.Conn.Read(buf)
				if err != nil {
					return err
				}
				received = append(received, buf[:n]...)
				if idx := bytes.Index(received, headerEnd); idx != -1 {
					o.readBuf.Write(received[idx+4:])
					break
				}
			}

		case "http_simple":
			// Encode initial write (salt) inside URL parameter
			encoded := ""
			if len(initialWriteData) > 0 {
				for _, b := range initialWriteData {
					encoded += fmt.Sprintf("%%%02x", b)
				}
			}
			req := fmt.Sprintf("GET /?data=%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) Gecko/20100101 Firefox/44.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n", encoded, o.host)
			if _, err := o.Conn.Write([]byte(req)); err != nil {
				return err
			}
			// Wait for response headers
			headerEnd := []byte("\r\n\r\n")
			buf := make([]byte, 1024)
			var received []byte
			for {
				n, err := o.Conn.Read(buf)
				if err != nil {
					return err
				}
				received = append(received, buf[:n]...)
				if idx := bytes.Index(received, headerEnd); idx != -1 {
					o.readBuf.Write(received[idx+4:])
					break
				}
			}

		case "tls", "simple-obfs-tls", "tls1.2", "tls1.2_ticket_auth":
			// Write simulated TLS ClientHello
			sessionID := make([]byte, 32)
			rand.Read(sessionID)
			
			// Build simple mock ClientHello
			var ch bytes.Buffer
			ch.Write([]byte{0x16, 0x03, 0x01, 0, 0}) // TLS Record Header (Handshake, TLS 1.0)
			
			var hs bytes.Buffer
			hs.Write([]byte{0x01, 0, 0, 0}) // Handshake Header (ClientHello)
			hs.Write([]byte{0x03, 0x03})    // TLS 1.2
			
			// Random bytes for client hello random
			chRandom := make([]byte, 32)
			rand.Read(chRandom)
			hs.Write(chRandom)
			
			// Session ID
			hs.WriteByte(32)
			hs.Write(sessionID)
			
			// Ciphers
			hs.Write([]byte{0, 2, 0, 0x9c}) // Cipher Suites: TLS_RSA_WITH_AES_128_GCM_SHA256
			hs.Write([]byte{1, 0})          // Compression Methods: null
			
			// Server Name Indication extension
			var ext bytes.Buffer
			ext.Write([]byte{0, 0}) // Extension SNI
			
			var sni bytes.Buffer
			sni.Write([]byte{0, 0}) // List length
			
			var name bytes.Buffer
			name.WriteByte(0) // Hostname type
			binary.Write(&name, binary.BigEndian, uint16(len(o.host)))
			name.Write([]byte(o.host))
			
			binary.Write(&sni, binary.BigEndian, uint16(name.Len()))
			sni.Write(name.Bytes())
			
			binary.Write(&ext, binary.BigEndian, uint16(sni.Len()))
			ext.Write(sni.Bytes())
			
			// Extensions length
			binary.Write(&hs, binary.BigEndian, uint16(ext.Len()))
			hs.Write(ext.Bytes())
			
			// Update handshake payload length
			hsBytes := hs.Bytes()
			hsLen := len(hsBytes) - 4
			hsBytes[1] = byte(hsLen >> 16)
			hsBytes[2] = byte(hsLen >> 8)
			hsBytes[3] = byte(hsLen)
			
			// Update TLS Record Header length
			chBytes := ch.Bytes()
			binary.BigEndian.PutUint16(chBytes[3:5], uint16(len(hsBytes)))
			
			if _, err := o.Conn.Write(chBytes); err != nil {
				return err
			}
			if _, err := o.Conn.Write(hsBytes); err != nil {
				return err
			}

			// Read mock ServerHello response (5 bytes header + payload)
			var shHeader [5]byte
			if _, err := io.ReadFull(o.Conn, shHeader[:]); err != nil {
				return err
			}
			shPayloadLen := int(binary.BigEndian.Uint16(shHeader[3:5]))
			shPayload := make([]byte, shPayloadLen)
			if _, err := io.ReadFull(o.Conn, shPayload); err != nil {
				return err
			}
		}
	} else {
		// Server side handshake
		switch o.mode {
		case "http", "simple-obfs-http":
			buf := make([]byte, 2048)
			var request []byte
			for {
				n, err := o.Conn.Read(buf)
				if err != nil {
					return err
				}
				request = append(request, buf[:n]...)
				if bytes.Contains(request, []byte("\r\n\r\n")) {
					break
				}
			}
			
			resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
			if _, err := o.Conn.Write([]byte(resp)); err != nil {
				return err
			}

		case "http_simple":
			buf := make([]byte, 2048)
			var request []byte
			var headerIdx int
			for {
				n, err := o.Conn.Read(buf)
				if err != nil {
					return err
				}
				request = append(request, buf[:n]...)
				headerIdx = bytes.Index(request, []byte("\r\n\r\n"))
				if headerIdx != -1 {
					break
				}
			}
			
			// Exclude headers and extract hex-encoded data from url query if present
			reqLineEnd := bytes.Index(request, []byte("\r\n"))
			if reqLineEnd != -1 {
				reqLine := string(request[:reqLineEnd])
				if idx := strings.Index(reqLine, "?data="); idx != -1 {
					endIdx := strings.Index(reqLine[idx:], " ")
					if endIdx != -1 {
						queryVal := reqLine[idx+6 : idx+endIdx]
						rawHex := strings.ReplaceAll(queryVal, "%", "")
						rawBytes, _ := hex.DecodeString(rawHex)
						o.readBuf.Write(rawBytes)
					}
				}
			}
			
			o.readBuf.Write(request[headerIdx+4:])
			
			resp := "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n"
			if _, err := o.Conn.Write([]byte(resp)); err != nil {
				return err
			}

		case "tls", "simple-obfs-tls", "tls1.2", "tls1.2_ticket_auth":
			var chHeader [5]byte
			if _, err := io.ReadFull(o.Conn, chHeader[:]); err != nil {
				return err
			}
			chPayloadLen := int(binary.BigEndian.Uint16(chHeader[3:5]))
			chPayload := make([]byte, chPayloadLen)
			if _, err := io.ReadFull(o.Conn, chPayload); err != nil {
				return err
			}
			
			// Respond with ServerHello
			var sh bytes.Buffer
			sh.Write([]byte{0x16, 0x03, 0x03, 0, 0}) // Handshake, TLS 1.2
			
			var hs bytes.Buffer
			hs.Write([]byte{0x02, 0, 0, 0}) // ServerHello
			hs.Write([]byte{0x03, 0x03})
			
			shRandom := make([]byte, 32)
			rand.Read(shRandom)
			hs.Write(shRandom)
			
			hs.WriteByte(0)      // Session ID length 0
			hs.Write([]byte{0, 0x9c, 0}) // Cipher & compression
			
			hsBytes := hs.Bytes()
			hsLen := len(hsBytes) - 4
			hsBytes[1] = byte(hsLen >> 16)
			hsBytes[2] = byte(hsLen >> 8)
			hsBytes[3] = byte(hsLen)
			
			shBytes := sh.Bytes()
			binary.BigEndian.PutUint16(shBytes[3:5], uint16(len(hsBytes)))
			
			if _, err := o.Conn.Write(shBytes); err != nil {
				return err
			}
			if _, err := o.Conn.Write(hsBytes); err != nil {
				return err
			}
		}
	}

	o.handshook = true
	return nil
}

// Read handles stripping mock obfuscation frames.
func (o *ObfsConn) Read(b []byte) (int, error) {
	if err := o.performHandshake(nil); err != nil {
		return 0, err
	}

	if o.readBuf.Len() > 0 {
		return o.readBuf.Read(b)
	}

	if o.mode == "tls" || o.mode == "simple-obfs-tls" || o.mode == "tls1.2" || o.mode == "tls1.2_ticket_auth" {
		// Read TLS record layer header (5 bytes)
		var h [5]byte
		if _, err := io.ReadFull(o.Conn, h[:]); err != nil {
			return 0, err
		}
		
		size := int(binary.BigEndian.Uint16(h[3:5]))
		if size > len(b) {
			// Read into local buffer if client buffer is too small
			temp := make([]byte, size)
			if _, err := io.ReadFull(o.Conn, temp); err != nil {
				return 0, err
			}
			n := copy(b, temp)
			if n < len(temp) {
				o.readBuf.Write(temp[n:])
			}
			return n, nil
		}
		
		return io.ReadFull(o.Conn, b[:size])
	}

	return o.Conn.Read(b)
}

// Write handles wrapping data in mock obfuscation frames.
func (o *ObfsConn) Write(b []byte) (int, error) {
	if !o.handshook {
		// client encodes salt in http GET query
		if err := o.performHandshake(b); err != nil {
			return 0, err
		}
		if o.mode == "http_simple" && o.isClient {
			// Salt was already written in performHandshake GET parameter
			return len(b), nil
		}
	}

	if o.mode == "tls" || o.mode == "simple-obfs-tls" || o.mode == "tls1.2" || o.mode == "tls1.2_ticket_auth" {
		// Encapsulate payload in TLS application data (0x17) record
		header := []byte{0x17, 0x03, 0x03, 0, 0}
		binary.BigEndian.PutUint16(header[3:5], uint16(len(b)))
		
		if _, err := o.Conn.Write(header); err != nil {
			return 0, err
		}
		return o.Conn.Write(b)
	}

	return o.Conn.Write(b)
}

// DialShadowsocks establishes a custom Shadowsocks connection.
func DialShadowsocks(ctx context.Context, cfg *ProxyConfig, cache *ReplayCache) (net.Conn, error) {
	var dialer net.Dialer
	rawConn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", cfg.Address, cfg.Port))
	if err != nil {
		return nil, err
	}

	conn := rawConn
	if cfg.Plugin != "" {
		plugin := strings.ToLower(cfg.Plugin)
		if plugin == "obfs-local" || plugin == "simple-obfs" {
			opts := make(map[string]string)
			for _, part := range strings.Split(cfg.PluginOpts, ";") {
				kv := strings.SplitN(part, "=", 2)
				if len(kv) == 2 {
					opts[strings.ToLower(kv[0])] = kv[1]
				}
			}
			mode := opts["obfs"]
			host := opts["obfs-host"]
			if host == "" {
				host = cfg.Address
			}
			conn = NewObfsConn(rawConn, mode, host, cfg.PluginOpts, true)
		}
	} else if cfg.Protocol == ProtocolShadowsocksR && cfg.Obfs != "" {
		conn = NewObfsConn(rawConn, cfg.Obfs, cfg.Address, cfg.ObfsParam, true)
	}

	ssConn, err := NewAEADConn(conn, cfg.Method, cfg.Password, cache)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return ssConn, nil
}
