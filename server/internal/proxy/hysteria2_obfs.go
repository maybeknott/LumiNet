package proxy

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"net"
	"sync"
)

// Hysteria2Outbound represents Hysteria2 connection settings.
type Hysteria2Outbound struct {
	Server      string `json:"server"`
	Port        int    `json:"port"`
	Password    string `json:"password"`
	Obfuscation string `json:"obfuscation"`
	UpMbps      int    `json:"up_mbps"`
	DownMbps    int    `json:"down_mbps"`
}

// GenerateHysteria2Config constructs outbound configuration parameters for Hysteria2.
func GenerateHysteria2Config(cfg Hysteria2Outbound) (map[string]interface{}, error) {
	if cfg.Server == "" {
		return nil, fmt.Errorf("missing hysteria2 server address")
	}
	if cfg.Password == "" {
		return nil, fmt.Errorf("missing hysteria2 password")
	}

	out := map[string]interface{}{
		"type":        "hysteria2",
		"tag":         "proxy",
		"server":      cfg.Server,
		"server_port": cfg.Port,
		"password":    cfg.Password,
	}

	if cfg.Obfuscation != "" {
		out["obfs"] = map[string]interface{}{
			"type":     "salamander",
			"password": cfg.Obfuscation,
		}
	}

	if cfg.UpMbps > 0 || cfg.DownMbps > 0 {
		out["bandwidth"] = map[string]interface{}{
			"up":   fmt.Sprintf("%d Mbps", cfg.UpMbps),
			"down": fmt.Sprintf("%d Mbps", cfg.DownMbps),
		}
	}

	return out, nil
}

// ObfuscatedConn wraps net.Conn to apply stream-level XOR obfuscation.
type ObfuscatedConn struct {
	net.Conn
	key   []byte
	txIdx int
	rxIdx int
	muTx  sync.Mutex
	muRx  sync.Mutex
}

// NewObfuscatedConn creates a new ObfuscatedConn stream wrapper.
func NewObfuscatedConn(conn net.Conn, password string) net.Conn {
	if password == "" {
		return conn
	}
	h := sha256.Sum256([]byte(password))
	return &ObfuscatedConn{
		Conn: conn,
		key:  h[:],
	}
}

func (c *ObfuscatedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.muRx.Lock()
		for i := 0; i < n; i++ {
			b[i] ^= c.key[c.rxIdx%len(c.key)]
			c.rxIdx++
		}
		c.muRx.Unlock()
	}
	return n, err
}

func (c *ObfuscatedConn) Write(b []byte) (int, error) {
	buf := make([]byte, len(b))
	c.muTx.Lock()
	for i := 0; i < len(b); i++ {
		buf[i] = b[i] ^ c.key[c.txIdx%len(c.key)]
		c.txIdx++
	}
	c.muTx.Unlock()
	return c.Conn.Write(buf)
}

// ObfuscatedPacketConn wraps net.PacketConn to apply datagram-level XOR obfuscation and random padding.
type ObfuscatedPacketConn struct {
	net.PacketConn
	key []byte
}

// NewObfuscatedPacketConn creates a new ObfuscatedPacketConn datagram wrapper.
func NewObfuscatedPacketConn(pc net.PacketConn, password string) net.PacketConn {
	if password == "" {
		return pc
	}
	h := sha256.Sum256([]byte(password))
	return &ObfuscatedPacketConn{
		PacketConn: pc,
		key:        h[:],
	}
}

func (c *ObfuscatedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if n > 0 && err == nil {
		// Deobfuscate
		for i := 0; i < n; i++ {
			p[i] ^= c.key[i%len(c.key)]
		}

		// Strip Hysteria 2 custom salamander padding if it has a length prefix
		if n > 0 {
			padLen := int(p[n-1])
			if n-1-padLen >= 0 {
				n = n - 1 - padLen
			}
		}
	}
	return n, addr, err
}

func (c *ObfuscatedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	// Generate random padding to hide length signatures (up to 32 bytes)
	padLen := rand.Intn(32)
	buf := make([]byte, len(p)+padLen+1)
	copy(buf, p)

	// Fill padding with random bytes
	for i := len(p); i < len(p)+padLen; i++ {
		buf[i] = byte(rand.Intn(256))
	}
	buf[len(buf)-1] = byte(padLen) // Save padding length in the last byte

	// Obfuscate using key-based XOR
	for i := 0; i < len(buf); i++ {
		buf[i] ^= c.key[i%len(c.key)]
	}

	return c.PacketConn.WriteTo(buf, addr)
}

