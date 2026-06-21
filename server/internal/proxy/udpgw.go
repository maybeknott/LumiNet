package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	udpgwMagicIP   = "192.0.2.1"
	udpgwLegacyIP  = "198.18.0.1"
	udpgwMagicPort = 7300

	flagKeepAlive = 0x01
	flagData      = 0x02
	flagErr       = 0x20

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	udpMtu = 10240
)

// isUDPGWDest returns true if the connection target points to the magic UDP gateway.
func isUDPGWDest(target string) bool {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	return port == udpgwMagicPort && (host == udpgwMagicIP || host == udpgwLegacyIP)
}

type udpgwFrame struct {
	flags   byte
	connID  uint16
	atyp    byte
	dstAddr string
	dstPort uint16
	payload []byte
}

func readUDPGWFrame(r io.Reader) (*udpgwFrame, error) {
	var bodyLen uint16
	if err := binary.Read(r, binary.BigEndian, &bodyLen); err != nil {
		return nil, err
	}

	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}

	if len(body) < 3 {
		return nil, errors.New("udpgw frame body too short")
	}

	flags := body[0]
	connID := binary.BigEndian.Uint16(body[1:3])
	rest := body[3:]

	frame := &udpgwFrame{
		flags:  flags,
		connID: connID,
	}

	if flags&flagData != 0 {
		if len(rest) < 1 {
			return nil, errors.New("missing ATYP")
		}
		atyp := rest[0]
		frame.atyp = atyp
		rest = rest[1:]

		switch atyp {
		case atypIPv4:
			if len(rest) < 4+2 {
				return nil, errors.New("short IPv4 address")
			}
			ip := net.IP(rest[:4])
			frame.dstPort = binary.BigEndian.Uint16(rest[4:6])
			frame.dstAddr = ip.String()
			frame.payload = rest[6:]
		case atypIPv6:
			if len(rest) < 16+2 {
				return nil, errors.New("short IPv6 address")
			}
			ip := net.IP(rest[:16])
			frame.dstPort = binary.BigEndian.Uint16(rest[16:18])
			frame.dstAddr = ip.String()
			frame.payload = rest[18:]
		case atypDomain:
			if len(rest) < 1 {
				return nil, errors.New("short domain address")
			}
			dlen := int(rest[0])
			if len(rest) < 1+dlen+2 {
				return nil, errors.New("short domain address")
			}
			frame.dstAddr = string(rest[1 : 1+dlen])
			frame.dstPort = binary.BigEndian.Uint16(rest[1+dlen : 1+dlen+2])
			frame.payload = rest[1+dlen+2:]
		default:
			return nil, fmt.Errorf("unknown ATYP 0x%02x", atyp)
		}
	} else {
		frame.payload = rest
	}

	return frame, nil
}

func writeUDPGWFrame(w io.Writer, flags byte, connID uint16, atyp byte, dstAddr string, dstPort uint16, payload []byte) error {
	var addrBytes []byte
	if flags&flagData != 0 {
		addrBytes = append(addrBytes, atyp)
		switch atyp {
		case atypIPv4:
			ip := net.ParseIP(dstAddr).To4()
			if ip == nil {
				ip = net.IPv4zero
			}
			addrBytes = append(addrBytes, ip...)
			var pBuf [2]byte
			binary.BigEndian.PutUint16(pBuf[:], dstPort)
			addrBytes = append(addrBytes, pBuf[:]...)
		case atypIPv6:
			ip := net.ParseIP(dstAddr).To16()
			if ip == nil {
				ip = net.IPv6zero
			}
			addrBytes = append(addrBytes, ip...)
			var pBuf [2]byte
			binary.BigEndian.PutUint16(pBuf[:], dstPort)
			addrBytes = append(addrBytes, pBuf[:]...)
		case atypDomain:
			addrBytes = append(addrBytes, byte(len(dstAddr)))
			addrBytes = append(addrBytes, []byte(dstAddr)...)
			var pBuf [2]byte
			binary.BigEndian.PutUint16(pBuf[:], dstPort)
			addrBytes = append(addrBytes, pBuf[:]...)
		}
	}

	bodyLen := 1 + 2 + len(addrBytes) + len(payload)
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(bodyLen))

	if _, err := w.Write(header); err != nil {
		return err
	}
	body := make([]byte, 0, bodyLen)
	body = append(body, flags)
	var cBuf [2]byte
	binary.BigEndian.PutUint16(cBuf[:], connID)
	body = append(body, cBuf[:]...)
	body = append(body, addrBytes...)
	body = append(body, payload...)

	_, err := w.Write(body)
	return err
}

func writeUDPGWError(w io.Writer, connID uint16) error {
	return writeUDPGWFrame(w, flagErr, connID, 0, "", 0, nil)
}

type udpConnKey struct {
	connID  uint16
	dstAddr string
	dstPort uint16
}

type udpgwSession struct {
	writer     io.Writer
	conns      map[udpConnKey]*net.UDPConn
	connsMu    sync.Mutex
	cleanupCtx chan struct{}
}

// runUDPGWServer processes incoming UDP-over-TCP multiplexed frames.
func runUDPGWServer(stream io.ReadWriteCloser) {
	session := &udpgwSession{
		writer:     stream,
		conns:      make(map[udpConnKey]*net.UDPConn),
		cleanupCtx: make(chan struct{}),
	}
	defer func() {
		close(session.cleanupCtx)
		stream.Close()
		session.connsMu.Lock()
		for _, uc := range session.conns {
			uc.Close()
		}
		session.conns = nil
		session.connsMu.Unlock()
	}()

	for {
		frame, err := readUDPGWFrame(stream)
		if err != nil {
			break
		}

		if frame.flags&flagKeepAlive != 0 {
			_ = writeUDPGWFrame(stream, flagKeepAlive, frame.connID, 0, "", 0, nil)
			continue
		}

		if frame.flags&flagData == 0 {
			continue
		}

		dstPort := frame.dstPort
		if dstPort == 443 || dstPort == 53 {
			// Block QUIC (UDP 443) and DNS (UDP 53) from udpgw
			_ = writeUDPGWError(stream, frame.connID)
			continue
		}

		targetAddr := net.JoinHostPort(frame.dstAddr, strconv.Itoa(int(dstPort)))
		udpAddr, err := net.ResolveUDPAddr("udp", targetAddr)
		if err != nil {
			_ = writeUDPGWError(stream, frame.connID)
			continue
		}

		key := udpConnKey{
			connID:  frame.connID,
			dstAddr: frame.dstAddr,
			dstPort: dstPort,
		}

		session.connsMu.Lock()
		if session.conns == nil {
			session.connsMu.Unlock()
			break
		}
		uc, exists := session.conns[key]
		if !exists {
			var err error
			uc, err = net.DialUDP("udp", nil, udpAddr)
			if err != nil {
				session.connsMu.Unlock()
				_ = writeUDPGWError(stream, frame.connID)
				continue
			}
			session.conns[key] = uc
			session.connsMu.Unlock()

			// Start background reader for this UDP socket
			go func(k udpConnKey, conn *net.UDPConn, frameAtyp byte, frameDstAddr string, frameDstPort uint16) {
				buf := make([]byte, udpMtu)
				for {
					_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
					n, err := conn.Read(buf)
					if err != nil {
						session.connsMu.Lock()
						if session.conns != nil {
							if c, ok := session.conns[k]; ok && c == conn {
								conn.Close()
								delete(session.conns, k)
							}
						}
						session.connsMu.Unlock()
						break
					}
					if n > 0 {
						session.connsMu.Lock()
						_ = writeUDPGWFrame(session.writer, flagData, k.connID, frameAtyp, frameDstAddr, frameDstPort, buf[:n])
						session.connsMu.Unlock()
					}
				}
			}(key, uc, frame.atyp, frame.dstAddr, frame.dstPort)
		} else {
			session.connsMu.Unlock()
		}

		_, _ = uc.Write(frame.payload)
	}
}

type chanConn struct {
	readChan  chan []byte
	writeChan chan []byte
	readBuf   []byte
	closed    chan struct{}
	once      sync.Once
	readDead  time.Time
	writeDead time.Time
	mu        sync.Mutex
}

// newChanPipe creates a full-duplex deadline-supported in-memory network connection.
func newChanPipe() (*chanConn, *chanConn) {
	c1 := make(chan []byte, 1024)
	c2 := make(chan []byte, 1024)
	closed1 := make(chan struct{})
	closed2 := make(chan struct{})

	conn1 := &chanConn{readChan: c1, writeChan: c2, closed: closed1}
	conn2 := &chanConn{readChan: c2, writeChan: c1, closed: closed2}

	// Link close signals
	go func() {
		select {
		case <-closed1:
			conn2.Close()
		case <-closed2:
			conn1.Close()
		}
	}()

	return conn1, conn2
}

func (c *chanConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		c.mu.Unlock()
		return n, nil
	}
	readDead := c.readDead
	c.mu.Unlock()

	var timeoutChan <-chan time.Time
	if !readDead.IsZero() {
		dur := time.Until(readDead)
		if dur <= 0 {
			return 0, context.DeadlineExceeded
		}
		timeoutChan = time.After(dur)
	}

	select {
	case <-c.closed:
		return 0, io.EOF
	case <-timeoutChan:
		return 0, context.DeadlineExceeded
	case data, ok := <-c.readChan:
		if !ok {
			return 0, io.EOF
		}
		c.mu.Lock()
		n := copy(b, data)
		if n < len(data) {
			c.readBuf = data[n:]
		}
		c.mu.Unlock()
		return n, nil
	}
}

func (c *chanConn) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, io.ErrClosedPipe
	default:
	}

	c.mu.Lock()
	writeDead := c.writeDead
	c.mu.Unlock()

	var timeoutChan <-chan time.Time
	if !writeDead.IsZero() {
		dur := time.Until(writeDead)
		if dur <= 0 {
			return 0, context.DeadlineExceeded
		}
		timeoutChan = time.After(dur)
	}

	dataCopy := make([]byte, len(b))
	copy(dataCopy, b)

	select {
	case <-c.closed:
		return 0, io.ErrClosedPipe
	case <-timeoutChan:
		return 0, context.DeadlineExceeded
	case c.writeChan <- dataCopy:
		return len(b), nil
	}
}

func (c *chanConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
	})
	return nil
}

func (c *chanConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 7300}
}

func (c *chanConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func (c *chanConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDead = t
	c.writeDead = t
	return nil
}

func (c *chanConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDead = t
	return nil
}

func (c *chanConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDead = t
	return nil
}
