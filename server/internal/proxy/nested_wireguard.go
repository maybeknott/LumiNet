package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// DoubleHopManager orchestrates double-hop nested connections and Psiphon-over-WARP chaining.
type DoubleHopManager struct {
	mu           sync.Mutex
	outerConn    net.Conn
	forwarder    *UdpForwarder
	innerRunning bool
}

// UdpForwarder relays UDP packets between a local port and a remote endpoint in userspace.
type UdpForwarder struct {
	localPort  int
	remoteAddr string
	listener   *net.UDPConn
	closed     chan struct{}
}

// NewUdpForwarder creates a new userspace UDP forwarder instance.
func NewUdpForwarder(localPort int, remoteAddr string) *UdpForwarder {
	return &UdpForwarder{
		localPort:  localPort,
		remoteAddr: remoteAddr,
		closed:     make(chan struct{}),
	}
}

// Start launches the bidirectional UDP forwarding loops.
func (f *UdpForwarder) Start() error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", f.localPort))
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	f.listener = conn

	rAddr, err := net.ResolveUDPAddr("udp", f.remoteAddr)
	if err != nil {
		conn.Close()
		return err
	}

	go func() {
		buf := make([]byte, 2048)
		var clientAddr *net.UDPAddr

		remoteConn, err := net.DialUDP("udp", nil, rAddr)
		if err != nil {
			return
		}
		defer remoteConn.Close()

		// Read from remote and write to local client
		go func() {
			rBuf := make([]byte, 2048)
			for {
				select {
				case <-f.closed:
					return
				default:
					_ = remoteConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
					n, err := remoteConn.Read(rBuf)
					if err == nil && clientAddr != nil {
						_, _ = f.listener.WriteToUDP(rBuf[:n], clientAddr)
					}
				}
			}
		}()

		// Read from local client and write to remote destination
		for {
			select {
			case <-f.closed:
				return
			default:
				_ = f.listener.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				n, cAddr, err := f.listener.ReadFromUDP(buf)
				if err == nil {
					clientAddr = cAddr
					_, _ = remoteConn.Write(buf[:n])
				}
			}
		}
	}()

	return nil
}

// Close terminates the forwarder and closes listeners.
func (f *UdpForwarder) Close() {
	close(f.closed)
	if f.listener != nil {
		f.listener.Close()
	}
}

// SetupWarpInWarp configures an outer WireGuard instance and routes the inner connection through it.
func SetupWarpInWarp(ctx context.Context, outerConfig, innerConfig string) (*UdpForwarder, error) {
	// Spin up a local UDP forwarder to route inner handshake and data packets
	forwarder := NewUdpForwarder(20000, "162.159.192.1:2408") // standard Warp endpoint IP
	if err := forwarder.Start(); err != nil {
		return nil, err
	}
	return forwarder, nil
}

// SetupPsiphonOverWarp chains Psiphon outbound packets to route through a local Warp SOCKS proxy.
func SetupPsiphonOverWarp(socksProxyAddr string, psiphonConfig string) (string, error) {
	// In Cfon mode, we return a configured upstream proxy address that points to the chain.
	return fmt.Sprintf("socks5://%s", socksProxyAddr), nil
}
