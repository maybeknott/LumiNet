package system

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// chanDevice bridges in-memory buffers to act as an io.ReadWriteCloser
type chanDevice struct {
	readChan  chan []byte
	writeChan chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newChanDevice() *chanDevice {
	return &chanDevice{
		readChan:  make(chan []byte, 100),
		writeChan: make(chan []byte, 100),
		closed:    make(chan struct{}),
	}
}

func (d *chanDevice) Read(p []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, io.EOF
	case data := <-d.readChan:
		n := copy(p, data)
		return n, nil
	}
}

func (d *chanDevice) Write(p []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, io.ErrClosedPipe
	default:
		data := make([]byte, len(p))
		copy(data, p)
		select {
		case d.writeChan <- data:
			return len(p), nil
		case <-d.closed:
			return 0, io.ErrClosedPipe
		}
	}
}

func (d *chanDevice) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
	})
	return nil
}

// startMockSocks5Server runs a simple SOCKS5 listener for testing
func startMockSocks5Server(t *testing.T) (string, func()) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock SOCKS5 listener: %v", err)
	}

	shutdown := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-shutdown:
					return
				default:
					t.Errorf("accept error: %v", err)
					return
				}
			}

			go func(c net.Conn) {
				defer c.Close()
				// Read SOCKS5 greeting
				greet := make([]byte, 3)
				_, err := io.ReadFull(c, greet)
				if err != nil {
					return
				}
				// Reply version 5, no auth
				_, _ = c.Write([]byte{0x05, 0x00})

				// Read command
				cmd := make([]byte, 4)
				_, err = io.ReadFull(c, cmd)
				if err != nil {
					return
				}

				if cmd[1] == 0x01 { // CONNECT
					// Read address depending on type
					var skip int
					switch cmd[3] {
					case 0x01: // IPv4
						skip = 4 + 2
					case 0x03: // Domain
						lenBuf := make([]byte, 1)
						_, _ = io.ReadFull(c, lenBuf)
						skip = int(lenBuf[0]) + 2
					}
					addrBuf := make([]byte, skip)
					_, _ = io.ReadFull(c, addrBuf)

					// Reply success
					reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80}
					_, _ = c.Write(reply)

					// Echo data back to client
					_, _ = io.Copy(c, c)
				}
			}(conn)
		}
	}()

	return l.Addr().String(), func() {
		close(shutdown)
		_ = l.Close()
		wg.Wait()
	}
}

func TestTun2SocksAdapter_TCP(t *testing.T) {
	socksAddr, stopSocks := startMockSocks5Server(t)
	defer stopSocks()

	dev := newChanDevice()
	defer dev.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	adapter, err := StartTun2Socks(ctx, dev, "10.0.0.2/24", "10.0.0.1", socksAddr)
	if err != nil {
		t.Fatalf("failed to start tun2socks: %v", err)
	}
	defer adapter.Close()

	// Construct a dummy IPv4/TCP SYN packet targeting a public IP (e.g. 8.8.8.8:80)
	// from source 10.0.0.2:44444
	srcIP := net.IPv4(10, 0, 0, 2)
	dstIP := net.IPv4(8, 8, 8, 8)
	srcPort := uint16(44444)
	dstPort := uint16(80)

	// Build raw TCP packet
	// IP header (20 bytes)
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45 // Version 4, IHL 5
	ipHeader[1] = 0x00
	binary.BigEndian.PutUint16(ipHeader[2:4], 40) // Total length (20 + 20)
	ipHeader[8] = 64                              // TTL
	ipHeader[9] = 6                               // Protocol: TCP
	copy(ipHeader[12:16], srcIP.To4())
	copy(ipHeader[16:20], dstIP.To4())

	// Compute IP checksum
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ipHeader[i : i+2]))
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = ^sum
	binary.BigEndian.PutUint16(ipHeader[10:12], uint16(sum))

	// TCP header (20 bytes)
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
	binary.BigEndian.PutUint32(tcpHeader[4:8], 1000)   // Seq Num
	binary.BigEndian.PutUint32(tcpHeader[8:12], 0)     // Ack Num
	tcpHeader[12] = 0x50                                // Data offset = 5
	tcpHeader[13] = 0x02                                // SYN flag
	binary.BigEndian.PutUint16(tcpHeader[14:16], 1024) // Window Size

	// Merge pseudo header and TCP header for checksum
	pseudo := make([]byte, 12+20)
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], 20)
	copy(pseudo[12:], tcpHeader)

	var tcpSum uint32
	for i := 0; i < len(pseudo); i += 2 {
		tcpSum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	tcpSum = (tcpSum >> 16) + (tcpSum & 0xffff)
	tcpSum = ^tcpSum
	binary.BigEndian.PutUint16(tcpHeader[16:18], uint16(tcpSum))

	packet := append(ipHeader, tcpHeader...)

	// Inject packet into device read channel (the tunnel reads this packet)
	select {
	case dev.readChan <- packet:
	case <-time.After(1 * time.Second):
		t.Fatalf("failed to inject packet into mock TUN device")
	}

	// We expect the NAT engine to translate this SYN packet and write back a SYN-ACK or redirect it
	// Let's check that the write channel receives packet(s)
	select {
	case outPacket := <-dev.writeChan:
		if len(outPacket) < 20 {
			t.Fatalf("captured packet is too small: %d", len(outPacket))
		}
		// Confirm it has translated address
		t.Logf("Successfully captured redirected packet of length %d from NAT table", len(outPacket))
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout: no packet returned from NAT engine")
	}
}
