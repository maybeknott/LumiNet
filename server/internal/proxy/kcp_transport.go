package proxy

import (
	"crypto/sha1"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/pbkdf2"
)

// deriveKCPKey derives a block crypt key from a password.
func deriveKCPKey(password string, keySize int) []byte {
	return pbkdf2.Key([]byte(password), []byte("kcp-go-salt"), 1024, keySize, sha1.New)
}

// createKCPBlockCrypt selects and instantiates a KCP block cipher algorithm based on config crypt string.
func createKCPBlockCrypt(crypt, password string) (kcp.BlockCrypt, error) {
	if password == "" {
		return kcp.NewNoneBlockCrypt(nil)
	}
	switch crypt {
	case "aes":
		return kcp.NewAESBlockCrypt(deriveKCPKey(password, 32))
	case "aes-128":
		return kcp.NewAESBlockCrypt(deriveKCPKey(password, 16))
	case "aes-192":
		return kcp.NewAESBlockCrypt(deriveKCPKey(password, 24))
	case "aes-256":
		return kcp.NewAESBlockCrypt(deriveKCPKey(password, 32))
	case "salsa20":
		return kcp.NewSalsa20BlockCrypt(deriveKCPKey(password, 32))
	case "twofish":
		return kcp.NewTwofishBlockCrypt(deriveKCPKey(password, 32))
	case "tripledes":
		return kcp.NewTripleDESBlockCrypt(deriveKCPKey(password, 24))
	case "cast5":
		return kcp.NewCast5BlockCrypt(deriveKCPKey(password, 16))
	case "blowfish":
		return kcp.NewBlowfishBlockCrypt(deriveKCPKey(password, 32))
	case "tea":
		return kcp.NewTEABlockCrypt(deriveKCPKey(password, 16))
	case "xtea":
		return kcp.NewXTEABlockCrypt(deriveKCPKey(password, 16))
	case "none", "":
		return kcp.NewNoneBlockCrypt(nil)
	default:
		return nil, fmt.Errorf("unsupported KCP encryption cipher: %s", crypt)
	}
}

// KcpTransportManager manages client SMUX multiplexed sessions over KCP connections.
type KcpTransportManager struct {
	mu       sync.Mutex
	sessions map[string]*smux.Session
}

// NewKcpTransportManager creates a new KcpTransportManager instance.
func NewKcpTransportManager() *KcpTransportManager {
	return &KcpTransportManager{
		sessions: make(map[string]*smux.Session),
	}
}

// Dial establishes a KCP connection to the proxy server and wraps it in an SMUX multiplexed stream.
func (m *KcpTransportManager) Dial(cfg *ProxyConfig) (net.Conn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	addr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
	smuxSess, ok := m.sessions[addr]
	if !ok || smuxSess.IsClosed() {
		block, err := createKCPBlockCrypt(cfg.Method, cfg.Password)
		if err != nil {
			return nil, err
		}

		// Dial KCP with default FEC configuration (10 data shards, 3 parity shards)
		dataShards := 10
		parityShards := 3
		kcpConn, err := kcp.DialWithOptions(addr, block, dataShards, parityShards)
		if err != nil {
			return nil, err
		}

		// Configure KCP protocol settings
		nodelay := 1
		interval := 20
		resend := 2
		nc := 1
		sndwnd := 128
		rcvwnd := 128
		mtu := 0

		if cfg.KCPProfile != "" {
			applyKCPProfile(cfg.KCPProfile, &nodelay, &interval, &resend, &nc, &sndwnd, &rcvwnd, &mtu)
		}

		if cfg.KCPNoDelay != 0 {
			nodelay = cfg.KCPNoDelay
		}
		if cfg.KCPInterval != 0 {
			interval = cfg.KCPInterval
		}
		if cfg.KCPResend != 0 {
			resend = cfg.KCPResend
		}
		if cfg.KCPNoCongestion != 0 {
			nc = cfg.KCPNoCongestion
		}
		kcpConn.SetNoDelay(nodelay, interval, resend, nc)

		if cfg.KCPSendWindow != 0 {
			sndwnd = cfg.KCPSendWindow
		}
		if cfg.KCPReceiveWindow != 0 {
			rcvwnd = cfg.KCPReceiveWindow
		}
		kcpConn.SetWindowSize(sndwnd, rcvwnd)

		if cfg.KCPMTU != 0 {
			mtu = cfg.KCPMTU
		}
		if mtu != 0 {
			kcpConn.SetMtu(mtu)
		}

		kcpConn.SetStreamMode(true)

		var transportConn net.Conn = kcpConn
		if cfg.KCPCompression != "" || cfg.KCPJitter {
			transportConn = NewNetrixConn(kcpConn, cfg.KCPCompression, cfg.KCPJitter, cfg.KCPJitterMin, cfg.KCPJitterMax)
		}

		// Create SMUX client configuration
		smuxConfig := smux.DefaultConfig()
		smuxConfig.KeepAliveInterval = 10 * time.Second
		smuxConfig.KeepAliveTimeout = 30 * time.Second

		smuxSess, err = smux.Client(transportConn, smuxConfig)
		if err != nil {
			transportConn.Close()
			return nil, err
		}

		m.sessions[addr] = smuxSess
	}

	// Open a multiplexed virtual stream
	stream, err := smuxSess.OpenStream()
	if err != nil {
		smuxSess.Close()
		delete(m.sessions, addr)
		return nil, err
	}

	return stream, nil
}

// KcpListener wraps a KCP + SMUX listener to accept streams.
type KcpListener struct {
	kcpListener *kcp.Listener
	mu          sync.Mutex
	sessions    []*smux.Session
	accepted    chan net.Conn
	die         chan struct{}
	dieOnce     sync.Once
}

// ListenKcp creates a server KCP + SMUX listener.
func ListenKcp(laddr string, cfg *ProxyConfig) (net.Listener, error) {
	block, err := createKCPBlockCrypt(cfg.Method, cfg.Password)
	if err != nil {
		return nil, err
	}

	dataShards := 10
	parityShards := 3
	kcpListener, err := kcp.ListenWithOptions(laddr, block, dataShards, parityShards)
	if err != nil {
		return nil, err
	}

	l := &KcpListener{
		kcpListener: kcpListener,
		accepted:    make(chan net.Conn, 100),
		die:         make(chan struct{}),
	}

	go l.acceptLoop(cfg)
	return l, nil
}

func (l *KcpListener) acceptLoop(cfg *ProxyConfig) {
	for {
		kcpConn, err := l.kcpListener.AcceptKCP()
		if err != nil {
			select {
			case <-l.die:
				return
			default:
				continue
			}
		}

		// Configure accepted KCP connection settings
		nodelay := 1
		interval := 20
		resend := 2
		nc := 1
		sndwnd := 128
		rcvwnd := 128
		mtu := 0

		if cfg.KCPProfile != "" {
			applyKCPProfile(cfg.KCPProfile, &nodelay, &interval, &resend, &nc, &sndwnd, &rcvwnd, &mtu)
		}

		if cfg.KCPNoDelay != 0 {
			nodelay = cfg.KCPNoDelay
		}
		if cfg.KCPInterval != 0 {
			interval = cfg.KCPInterval
		}
		if cfg.KCPResend != 0 {
			resend = cfg.KCPResend
		}
		if cfg.KCPNoCongestion != 0 {
			nc = cfg.KCPNoCongestion
		}
		kcpConn.SetNoDelay(nodelay, interval, resend, nc)

		if cfg.KCPSendWindow != 0 {
			sndwnd = cfg.KCPSendWindow
		}
		if cfg.KCPReceiveWindow != 0 {
			rcvwnd = cfg.KCPReceiveWindow
		}
		kcpConn.SetWindowSize(sndwnd, rcvwnd)

		if cfg.KCPMTU != 0 {
			mtu = cfg.KCPMTU
		}
		if mtu != 0 {
			kcpConn.SetMtu(mtu)
		}

		kcpConn.SetStreamMode(true)

		var transportConn net.Conn = kcpConn
		if cfg.KCPCompression != "" || cfg.KCPJitter {
			transportConn = NewNetrixConn(kcpConn, cfg.KCPCompression, cfg.KCPJitter, cfg.KCPJitterMin, cfg.KCPJitterMax)
		}

		smuxConfig := smux.DefaultConfig()
		smuxConfig.KeepAliveInterval = 10 * time.Second
		smuxConfig.KeepAliveTimeout = 30 * time.Second

		smuxSess, err := smux.Server(transportConn, smuxConfig)
		if err != nil {
			transportConn.Close()
			continue
		}

		l.mu.Lock()
		l.sessions = append(l.sessions, smuxSess)
		l.mu.Unlock()

		go func(sess *smux.Session) {
			for {
				stream, err := sess.AcceptStream()
				if err != nil {
					return
				}
				select {
				case l.accepted <- stream:
				case <-l.die:
					stream.Close()
					return
				}
			}
		}(smuxSess)
	}
}

// Accept accepts the next incoming stream connection.
func (l *KcpListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.accepted:
		return conn, nil
	case <-l.die:
		return nil, io.ErrClosedPipe
	}
}

// Close terminates KCP listener and closes all active multiplexed sessions.
func (l *KcpListener) Close() error {
	var err error
	l.dieOnce.Do(func() {
		close(l.die)
		err = l.kcpListener.Close()

		l.mu.Lock()
		for _, sess := range l.sessions {
			sess.Close()
		}
		l.mu.Unlock()
	})
	return err
}

// Addr returns the network address of the listener.
func (l *KcpListener) Addr() net.Addr {
	return l.kcpListener.Addr()
}

// applyKCPProfile sets KCP properties based on standard performance profile.
func applyKCPProfile(profile string, nodelay, interval, resend, nc, sndwnd, rcvwnd, mtu *int) {
	switch strings.ToLower(profile) {
	case "balanced":
		*nodelay = 0
		*interval = 20
		*resend = 2
		*nc = 0
		*sndwnd = 512
		*rcvwnd = 512
		*mtu = 1350
	case "aggressive":
		*nodelay = 0
		*interval = 10
		*resend = 2
		*nc = 1
		*sndwnd = 2048
		*rcvwnd = 2048
		*mtu = 1400
	case "latency":
		*nodelay = 1
		*interval = 5
		*resend = 1
		*nc = 1
		*sndwnd = 256
		*rcvwnd = 256
		*mtu = 1200
	case "cpu-efficient":
		*nodelay = 0
		*interval = 50
		*resend = 3
		*nc = 0
		*sndwnd = 128
		*rcvwnd = 128
		*mtu = 1400
	}
}
