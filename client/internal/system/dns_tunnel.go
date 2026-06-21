package system

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

const (
	numPadding          = 3
	numPaddingForPoll   = 8
	initPollDelay       = 500 * time.Millisecond
	maxPollDelay        = 10 * time.Second
	pollDelayMultiplier = 2.0
	pollLimit           = 16
	queueSize           = 128
)

var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

type taggedPacket struct {
	P    []byte
	Addr net.Addr
}

// QueuePacketConn implements a simple packet queue mapping network interfaces.
type QueuePacketConn struct {
	recvQueue chan taggedPacket
	sendQueue chan []byte
	localAddr net.Addr
	closed    chan struct{}
	closeOnce sync.Once
}

func NewQueuePacketConn(localAddr net.Addr) *QueuePacketConn {
	return &QueuePacketConn{
		recvQueue: make(chan taggedPacket, queueSize),
		sendQueue: make(chan []byte, queueSize),
		localAddr: localAddr,
		closed:    make(chan struct{}),
	}
}

func (c *QueuePacketConn) QueueIncoming(p []byte, addr net.Addr) {
	select {
	case <-c.closed:
		return
	default:
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case c.recvQueue <- taggedPacket{buf, addr}:
	default:
	}
}

func (c *QueuePacketConn) OutgoingQueue() <-chan []byte {
	return c.sendQueue
}

func (c *QueuePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, io.EOF
	default:
	}
	select {
	case <-c.closed:
		return 0, nil, io.EOF
	case packet := <-c.recvQueue:
		return copy(p, packet.P), packet.Addr, nil
	}
}

func (c *QueuePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, io.ErrClosedPipe
	default:
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case c.sendQueue <- buf:
		return len(buf), nil
	default:
		return len(buf), nil // drop if queue is full
	}
}

func (c *QueuePacketConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return nil
}

func (c *QueuePacketConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *QueuePacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *QueuePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *QueuePacketConn) SetWriteDeadline(t time.Time) error { return nil }

type ClientIDAddr struct {
	ID [8]byte
}

func (a ClientIDAddr) Network() string { return "dns" }
func (a ClientIDAddr) String() string  { return fmt.Sprintf("%x", a.ID) }

// DNSPacketConn wraps QueuePacketConn and handles DNS TXT packing/encoding.
type DNSPacketConn struct {
	clientID       [8]byte
	tunnelDomain   string
	pollChan       chan struct{}
	balancer       *DNSBalancer
	transport      net.PacketConn
	pendingMu      sync.Mutex
	pendingQueries map[uint16]queryMeta
	*QueuePacketConn
	ctx            context.Context
	cancel         context.CancelFunc
	socketCreated  time.Time
}

type queryMeta struct {
	sentAt   time.Time
	resolver string
}

func NewDNSPacketConn(transport net.PacketConn, balancer *DNSBalancer, tunnelDomain string) *DNSPacketConn {
	var id [8]byte
	_, _ = rand.Read(id[:])

	ctx, cancel := context.WithCancel(context.Background())
	c := &DNSPacketConn{
		clientID:        id,
		tunnelDomain:    tunnelDomain,
		pollChan:        make(chan struct{}, pollLimit),
		balancer:        balancer,
		transport:       transport,
		pendingQueries:  make(map[uint16]queryMeta),
		QueuePacketConn: NewQueuePacketConn(ClientIDAddr{ID: id}),
		ctx:             ctx,
		cancel:          cancel,
		socketCreated:   time.Now(),
	}

	go c.recvLoop()
	go c.sendLoop()

	return c
}

func (c *DNSPacketConn) Close() error {
	c.cancel()
	_ = c.QueuePacketConn.Close()
	return c.transport.Close()
}

func (c *DNSPacketConn) send(p []byte) error {
	c.pendingMu.Lock()
	if time.Since(c.socketCreated) > 90*time.Second {
		_ = c.transport.Close()
		newTransport, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err == nil {
			c.transport = newTransport
			c.socketCreated = time.Now()
			go c.recvLoop()
		}
	}
	c.pendingMu.Unlock()

	var decoded []byte
	{
		if len(p) >= 224 {
			return fmt.Errorf("packet too long for DNS label")
		}
		var buf bytes.Buffer
		buf.Write(c.clientID[:])
		n := numPadding
		if len(p) == 0 {
			n = numPaddingForPoll
		}
		buf.WriteByte(byte(224 + n))
		pad := make([]byte, n)
		_, _ = rand.Read(pad)
		buf.Write(pad)
		if len(p) > 0 {
			buf.WriteByte(byte(len(p)))
			buf.Write(p)
		}
		decoded = buf.Bytes()
	}

	encoded := base32Encoding.EncodeToString(decoded)
	encoded = strings.ToLower(encoded)
	labels := chunkString(encoded, 63)
	domainLabels := strings.Split(c.tunnelDomain, ".")
	labels = append(labels, domainLabels...)

	queryDomain := strings.Join(labels, ".")

	var id uint16
	_ = binary.Read(rand.Reader, binary.BigEndian, &id)

	queryData, err := buildDNSQuery(queryDomain, 16, id) // TXT record = 16
	if err != nil {
		return err
	}

	resolverAddr := c.balancer.SelectResolver()
	if resolverAddr == "" {
		return fmt.Errorf("no resolver available")
	}

	raddr, err := net.ResolveUDPAddr("udp", resolverAddr)
	if err != nil {
		return err
	}

	c.pendingMu.Lock()
	c.pendingQueries[id] = queryMeta{
		sentAt:   time.Now(),
		resolver: resolverAddr,
	}
	c.pendingMu.Unlock()

	_, err = c.transport.WriteTo(queryData, raddr)
	if err != nil {
		c.balancer.ReportFailure(resolverAddr)
		c.pendingMu.Lock()
		delete(c.pendingQueries, id)
		c.pendingMu.Unlock()
		return err
	}

	return nil
}

func (c *DNSPacketConn) recvLoop() {
	buf := make([]byte, 4096)
	t := c.transport
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		n, addr, err := t.ReadFrom(buf)
		if err != nil {
			return
		}

		id, txtPayloads, err := parseDNSResponse(buf[:n])
		if err != nil {
			continue
		}

		c.pendingMu.Lock()
		meta, ok := c.pendingQueries[id]
		if ok {
			delete(c.pendingQueries, id)
			c.balancer.ReportSuccess(meta.resolver, time.Since(meta.sentAt))
		}
		c.pendingMu.Unlock()

		anyPacket := false
		for _, payload := range txtPayloads {
			r := bytes.NewReader(payload)
			for {
				var length uint16
				err := binary.Read(r, binary.BigEndian, &length)
				if err != nil {
					break
				}
				packet := make([]byte, length)
				_, err = io.ReadFull(r, packet)
				if err != nil {
					break
				}
				anyPacket = true
				c.QueuePacketConn.QueueIncoming(packet, addr)
			}
		}

		if anyPacket {
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
		}
	}
}

func (c *DNSPacketConn) sendLoop() {
	pollDelay := initPollDelay
	pollTimer := time.NewTimer(pollDelay)
	defer pollTimer.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		var p []byte
		outgoing := c.QueuePacketConn.OutgoingQueue()
		pollTimerExpired := false

		select {
		case p = <-outgoing:
		default:
			select {
			case <-c.ctx.Done():
				return
			case p = <-outgoing:
			case <-c.pollChan:
			case <-pollTimer.C:
				pollTimerExpired = true
			}
		}

		if len(p) > 0 {
			select {
			case <-c.pollChan:
			default:
			}
		}

		if pollTimerExpired {
			pollDelay = time.Duration(float64(pollDelay) * pollDelayMultiplier)
			if pollDelay > maxPollDelay {
				pollDelay = maxPollDelay
			}
		} else {
			if !pollTimer.Stop() {
				select {
				case <-pollTimer.C:
				default:
				}
			}
			pollDelay = initPollDelay
		}
		pollTimer.Reset(pollDelay)

		_ = c.send(p)
	}
}

// DialDNSTunnel starts the DNS packet connection, sets up KCP and smux client session.
func DialDNSTunnel(resolvers []string, tunnelDomain string) (net.Conn, error) {
	balancer := NewDNSBalancer(resolvers, "lowest_latency")
	
	transport, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("failed to listen UDP: %w", err)
	}

	dnsPacketConn := NewDNSPacketConn(transport, balancer, tunnelDomain)

	// Calculate MTU
	mtu := dnsNameCapacity(tunnelDomain) - 13
	if mtu < 80 {
		_ = dnsPacketConn.Close()
		return nil, fmt.Errorf("domain leaves too small MTU: %d", mtu)
	}

	dummyAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	kcpConn, err := kcp.NewConn2(dummyAddr, nil, 0, 0, dnsPacketConn)
	if err != nil {
		_ = dnsPacketConn.Close()
		return nil, fmt.Errorf("failed to open KCP: %w", err)
	}

	kcpConn.SetStreamMode(true)
	kcpConn.SetNoDelay(1, 10, 2, 1)
	kcpConn.SetWindowSize(128, 128)
	kcpConn.SetMtu(mtu)

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = 2 * time.Minute
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024

	sess, err := smux.Client(kcpConn, smuxConfig)
	if err != nil {
		_ = kcpConn.Close()
		_ = dnsPacketConn.Close()
		return nil, fmt.Errorf("failed to start smux client: %w", err)
	}

	stream, err := sess.OpenStream()
	if err != nil {
		_ = sess.Close()
		_ = kcpConn.Close()
		_ = dnsPacketConn.Close()
		return nil, fmt.Errorf("failed to open smux stream: %w", err)
	}

	return stream, nil
}

func dnsNameCapacity(domain string) int {
	capacity := 254
	labels := strings.Split(domain, ".")
	for _, l := range labels {
		capacity -= len(l) + 1
	}
	capacity = capacity * 63 / 64
	capacity = capacity * 5 / 8
	return capacity
}

func chunkString(s string, size int) []string {
	var chunks []string
	for len(s) > 0 {
		if len(s) > size {
			chunks = append(chunks, s[:size])
			s = s[size:]
		} else {
			chunks = append(chunks, s)
			break
		}
	}
	return chunks
}

func buildDNSQuery(domain string, qtype uint16, qid uint16) ([]byte, error) {
	var buf bytes.Buffer
	// Transaction ID
	_ = binary.Write(&buf, binary.BigEndian, qid)
	// Flags: QR=0, Opcode=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0 (0x0100)
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x0100))
	// QDCOUNT: 1
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	// ANCOUNT, NSCOUNT, ARCOUNT: 0
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))

	// Question Name
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) == 0 {
			continue
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("label exceeds 63 chars")
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0) // null terminator

	// Question Type
	_ = binary.Write(&buf, binary.BigEndian, qtype)
	// Question Class: IN (1)
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))

	return buf.Bytes(), nil
}

func skipName(data []byte, offset int) (int, error) {
	for offset < len(data) {
		b := data[offset]
		if b == 0 {
			return offset + 1, nil
		}
		if b&0xc0 == 0xc0 {
			if offset+2 > len(data) {
				return 0, fmt.Errorf("truncated pointer")
			}
			return offset + 2, nil
		}
		length := int(b)
		if offset+1+length > len(data) {
			return 0, fmt.Errorf("truncated label")
		}
		offset += 1 + length
	}
	return 0, fmt.Errorf("name not terminated")
}

func parseDNSResponse(data []byte) (uint16, [][]byte, error) {
	if len(data) < 12 {
		return 0, nil, fmt.Errorf("dns response too short")
	}

	id := binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	qdcount := binary.BigEndian.Uint16(data[4:6])
	ancount := binary.BigEndian.Uint16(data[6:8])

	// Check QR flag is 1 (response) and RCODE is NoError (0)
	if flags&0x8000 == 0 {
		return 0, nil, fmt.Errorf("not a response")
	}
	if flags&0x000f != 0 {
		return id, nil, fmt.Errorf("dns error code: %d", flags&0x000f)
	}

	offset := 12
	// Skip question records
	for i := uint16(0); i < qdcount; i++ {
		next, err := skipName(data, offset)
		if err != nil {
			return id, nil, fmt.Errorf("skipping question name: %w", err)
		}
		offset = next + 4 // Skip QTYPE (2) + QCLASS (2)
	}

	var txtPayloads [][]byte

	// Parse answer records
	for i := uint16(0); i < ancount; i++ {
		next, err := skipName(data, offset)
		if err != nil {
			return id, nil, fmt.Errorf("skipping answer name: %w", err)
		}
		if next+10 > len(data) {
			return id, nil, fmt.Errorf("truncated answer rr headers")
		}
		rrType := binary.BigEndian.Uint16(data[next : next+2])
		rdlen := int(binary.BigEndian.Uint16(data[next+8 : next+10]))

		offset = next + 10
		if offset+rdlen > len(data) {
			return id, nil, fmt.Errorf("truncated answer rr data")
		}

		if rrType == 16 { // TXT record
			var rdata []byte
			txtOffset := offset
			end := offset + rdlen
			for txtOffset < end {
				length := int(data[txtOffset])
				if txtOffset+1+length > end {
					break
				}
				rdata = append(rdata, data[txtOffset+1:txtOffset+1+length]...)
				txtOffset += 1 + length
			}
			txtPayloads = append(txtPayloads, rdata)
		}

		offset += rdlen
	}

	return id, txtPayloads, nil
}
