package system

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// DNSUDPFallbackListener listens on a local UDP address, intercepts DNS queries,
// and returns truncated DNS responses (TC bit set) to force fallback to TCP DNS.
type DNSUDPFallbackListener struct {
	addr       string
	conn       *net.UDPConn
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	running    bool
	runningMu  sync.Mutex
}

// NewDNSUDPFallbackListener creates a new instance of the listener.
func NewDNSUDPFallbackListener(addr string) *DNSUDPFallbackListener {
	return &DNSUDPFallbackListener{
		addr: addr,
	}
}

// Start launches the UDP listener loop.
func (l *DNSUDPFallbackListener) Start() error {
	l.runningMu.Lock()
	defer l.runningMu.Unlock()

	if l.running {
		return fmt.Errorf("fallback listener already running")
	}

	laddr, err := net.ResolveUDPAddr("udp", l.addr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return fmt.Errorf("failed to listen UDP: %w", err)
	}

	l.conn = conn
	l.ctx, l.cancel = context.WithCancel(context.Background())
	l.running = true

	l.wg.Add(1)
	go l.listenLoop()

	return nil
}

// Stop gracefully stops the UDP listener.
func (l *DNSUDPFallbackListener) Stop() {
	l.runningMu.Lock()
	defer l.runningMu.Unlock()

	if !l.running {
		return
	}

	l.cancel()
	if l.conn != nil {
		_ = l.conn.Close()
	}
	l.wg.Wait()
	l.running = false
}

func (l *DNSUDPFallbackListener) listenLoop() {
	defer l.wg.Done()
	buf := make([]byte, 2048)

	for {
		select {
		case <-l.ctx.Done():
			return
		default:
		}

		n, raddr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			// Loop ends when connection is closed
			return
		}

		if n < 12 {
			continue // Too short to be a valid DNS query
		}

		// Truncate DNS response manipulation (TC bit)
		// data[2] contains QR | Opcode | AA | TC | RD
		// Set QR (0x80) and TC (0x02) bits
		buf[2] |= 0x80 | 0x02

		// data[3] contains RA | Z | RCODE
		// Clear RCODE (lower 4 bits) to indicate NoError
		buf[3] &= ^uint8(0x0F)

		// Set ANCOUNT (Answer Count) to QDCOUNT (Question Count) at bytes 6:8.
		// While technically incorrect (no answers are attached), this is necessary for some
		// operating systems (e.g. Windows) to successfully fallback to TCP.
		qdcount := binary.BigEndian.Uint16(buf[4:6])
		binary.BigEndian.PutUint16(buf[6:8], qdcount)

		// Write truncated response back to source UDP address
		_, _ = l.conn.WriteToUDP(buf[:n], raddr)
	}
}
