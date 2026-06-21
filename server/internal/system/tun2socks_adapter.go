package system

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/maybeknott/luminet/internal/system/nat"
)

type udpAssociation struct {
	clientSrcAddr string
	socksTCP      net.Conn
	socksUDP      *net.UDPConn
	relayAddr     *net.UDPAddr
	lastUsed      time.Time
	mu            sync.Mutex
	closed        bool
}

type Tun2SocksAdapter struct {
	mu           sync.Mutex
	associations map[string]*udpAssociation
	socksAddr    string
	tcpListener  *nat.TCP
	udpHandler   *nat.UDP
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	device       io.ReadWriteCloser
}

func StartTun2Socks(ctx context.Context, device io.ReadWriteCloser, tunAddr string, gatewayAddr string, socksAddr string) (*Tun2SocksAdapter, error) {
	// Parse network addresses
	prefix, err := netip.ParsePrefix(tunAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid TUN interface address: %w", err)
	}

	portal, err := netip.ParseAddr(gatewayAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid gateway portal address: %w", err)
	}

	tcpListener, udpHandler, err := nat.Start(device, prefix, portal)
	if err != nil {
		return nil, fmt.Errorf("failed to start userspace network translation: %w", err)
	}

	subCtx, cancel := context.WithCancel(ctx)
	adapter := &Tun2SocksAdapter{
		associations: make(map[string]*udpAssociation),
		socksAddr:    socksAddr,
		tcpListener:  tcpListener,
		udpHandler:   udpHandler,
		ctx:          subCtx,
		cancel:       cancel,
		device:       device,
	}

	// Start TCP listener loop
	adapter.wg.Add(1)
	go func() {
		defer adapter.wg.Done()
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go adapter.handleTCP(conn)
		}
	}()

	// Start UDP handler loop
	adapter.wg.Add(1)
	go func() {
		defer adapter.wg.Done()
		buf := make([]byte, 65535)
		for {
			n, srcAddr, dstAddr, err := udpHandler.ReadFrom(buf)
			if err != nil {
				return
			}
			packet := make([]byte, n)
			copy(packet, buf[:n])
			adapter.handleUDP(srcAddr, dstAddr, packet)
		}
	}()

	// Clean idle UDP associations
	adapter.wg.Add(1)
	go func() {
		defer adapter.wg.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-subCtx.Done():
				return
			case <-ticker.C:
				adapter.cleanIdleUDP()
			}
		}
	}()

	return adapter, nil
}

func (a *Tun2SocksAdapter) Close() error {
	a.cancel()
	_ = a.tcpListener.Close()
	_ = a.udpHandler.Close()

	a.mu.Lock()
	for _, assoc := range a.associations {
		assoc.mu.Lock()
		assoc.closed = true
		if assoc.socksTCP != nil {
			_ = assoc.socksTCP.Close()
		}
		if assoc.socksUDP != nil {
			_ = assoc.socksUDP.Close()
		}
		assoc.mu.Unlock()
	}
	a.associations = make(map[string]*udpAssociation)
	a.mu.Unlock()

	_ = a.device.Close()
	a.wg.Wait()
	return nil
}

func (a *Tun2SocksAdapter) handleTCP(client net.Conn) {
	defer client.Close()

	dialer := net.Dialer{}
	socksConn, err := dialer.DialContext(a.ctx, "tcp", a.socksAddr)
	if err != nil {
		return
	}
	defer socksConn.Close()

	remoteAddr := client.RemoteAddr().(*net.TCPAddr)
	err = socks5Handshake(socksConn, remoteAddr.IP, remoteAddr.Port)
	if err != nil {
		return
	}

	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(socksConn, client)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(client, socksConn)
		errChan <- err
	}()

	select {
	case <-a.ctx.Done():
	case <-errChan:
	}
}

func (a *Tun2SocksAdapter) handleUDP(src net.Addr, dst net.Addr, payload []byte) {
	assoc := a.getOrCreateUDPAssoc(src)
	if assoc == nil {
		return
	}

	assoc.mu.Lock()
	defer assoc.mu.Unlock()
	if assoc.closed {
		return
	}

	assoc.lastUsed = time.Now()

	// Wrap in SOCKS5 UDP request format
	dstAddr := dst.(*net.UDPAddr)
	dstIP := dstAddr.IP.To4()
	if dstIP == nil {
		return
	}

	header := make([]byte, 4+4+2)
	header[0] = 0x00 // RSV
	header[1] = 0x00 // RSV
	header[2] = 0x00 // FRAG
	header[3] = 0x01 // ATYP: IPv4
	copy(header[4:8], dstIP)
	binary.BigEndian.PutUint16(header[8:10], uint16(dstAddr.Port))

	packet := append(header, payload...)
	_, _ = assoc.socksUDP.WriteTo(packet, assoc.relayAddr)
}

func (a *Tun2SocksAdapter) getOrCreateUDPAssoc(src net.Addr) *udpAssociation {
	key := src.String()

	a.mu.Lock()
	assoc, exists := a.associations[key]
	if exists {
		a.mu.Unlock()
		return assoc
	}

	a.mu.Unlock()

	// Create new association
	socksTCP, err := net.Dial("tcp", a.socksAddr)
	if err != nil {
		return nil
	}

	// Greet SOCKS5
	_, err = socksTCP.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		socksTCP.Close()
		return nil
	}
	greeting := make([]byte, 2)
	_, err = io.ReadFull(socksTCP, greeting)
	if err != nil || greeting[0] != 0x05 || greeting[1] != 0x00 {
		socksTCP.Close()
		return nil
	}

	// Send UDP Associate command
	_, err = socksTCP.Write([]byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		socksTCP.Close()
		return nil
	}

	response := make([]byte, 4)
	_, err = io.ReadFull(socksTCP, response)
	if err != nil || response[0] != 0x05 || response[1] != 0x00 {
		socksTCP.Close()
		return nil
	}

	var relayIP net.IP
	var relayPort int
	switch response[3] {
	case 0x01: // IPv4
		ipBuf := make([]byte, 4)
		_, err = io.ReadFull(socksTCP, ipBuf)
		if err != nil {
			socksTCP.Close()
			return nil
		}
		relayIP = net.IP(ipBuf)
	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		_, err = io.ReadFull(socksTCP, lenBuf)
		if err != nil {
			socksTCP.Close()
			return nil
		}
		domainBuf := make([]byte, int(lenBuf[0]))
		_, err = io.ReadFull(socksTCP, domainBuf)
		if err != nil {
			socksTCP.Close()
			return nil
		}
		// Resolve the relay host
		ips, err := net.LookupIP(string(domainBuf))
		if err != nil || len(ips) == 0 {
			socksTCP.Close()
			return nil
		}
		relayIP = ips[0]
	default:
		socksTCP.Close()
		return nil
	}

	portBuf := make([]byte, 2)
	_, err = io.ReadFull(socksTCP, portBuf)
	if err != nil {
		socksTCP.Close()
		return nil
	}
	relayPort = int(binary.BigEndian.Uint16(portBuf))

	// Listen on local UDP
	socksUDP, err := net.ListenUDP("udp4", nil)
	if err != nil {
		socksTCP.Close()
		return nil
	}

	relayAddr := &net.UDPAddr{
		IP:   relayIP,
		Port: relayPort,
	}

	newAssoc := &udpAssociation{
		clientSrcAddr: key,
		socksTCP:      socksTCP,
		socksUDP:      socksUDP,
		relayAddr:     relayAddr,
		lastUsed:      time.Now(),
	}

	// Start reading back from SOCKS UDP socket
	go a.readSocksUDP(newAssoc, src)

	a.mu.Lock()
	a.associations[key] = newAssoc
	a.mu.Unlock()

	return newAssoc
}

func (a *Tun2SocksAdapter) readSocksUDP(assoc *udpAssociation, src net.Addr) {
	buf := make([]byte, 65535)
	for {
		n, _, err := assoc.socksUDP.ReadFrom(buf)
		if err != nil {
			return
		}

		if n < 10 {
			continue // Invalid header
		}

		// SOCKS5 UDP Header: RSV(2) + FRAG(1) + ATYP(1) + IP(4) + Port(2)
		if buf[2] != 0x00 {
			continue // Fragments not supported
		}

		if buf[3] != 0x01 {
			continue // Only IPv4 is supported in this parser implementation
		}

		senderIP := net.IP(buf[4:8])
		senderPort := int(binary.BigEndian.Uint16(buf[8:10]))
		payload := buf[10:n]

		senderAddr := &net.UDPAddr{
			IP:   senderIP,
			Port: senderPort,
		}

		// Write packet back to the client via our userspace NAT stack
		_, _ = a.udpHandler.WriteTo(payload, senderAddr, src)
	}
}

func (a *Tun2SocksAdapter) cleanIdleUDP() {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	for key, assoc := range a.associations {
		assoc.mu.Lock()
		if now.Sub(assoc.lastUsed) > 60*time.Second {
			assoc.closed = true
			if assoc.socksTCP != nil {
				_ = assoc.socksTCP.Close()
			}
			if assoc.socksUDP != nil {
				_ = assoc.socksUDP.Close()
			}
			delete(a.associations, key)
		}
		assoc.mu.Unlock()
	}
}

func socks5Handshake(conn net.Conn, targetIP net.IP, targetPort int) error {
	_, err := conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		return err
	}
	resp := make([]byte, 2)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		return err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fmt.Errorf("socks5 auth negotiation failed: %v", resp)
	}

	ip4 := targetIP.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 destination supported")
	}

	req := make([]byte, 4+4+2)
	req[0] = 0x05
	req[1] = 0x01
	req[2] = 0x00
	req[3] = 0x01
	copy(req[4:8], ip4)
	binary.BigEndian.PutUint16(req[8:10], uint16(targetPort))

	_, err = conn.Write(req)
	if err != nil {
		return err
	}

	repHeader := make([]byte, 4)
	_, err = io.ReadFull(conn, repHeader)
	if err != nil {
		return err
	}
	if repHeader[0] != 0x05 || repHeader[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed with status %d", repHeader[1])
	}

	var skipLen int
	switch repHeader[3] {
	case 0x01: // IPv4
		skipLen = 4 + 2
	case 0x03: // Domain
		domainLenBuf := make([]byte, 1)
		_, err = io.ReadFull(conn, domainLenBuf)
		if err != nil {
			return err
		}
		skipLen = int(domainLenBuf[0]) + 2
	case 0x04: // IPv6
		skipLen = 16 + 2
	default:
		return fmt.Errorf("unsupported atyp in socks5 response: %d", repHeader[3])
	}
	skipBuf := make([]byte, skipLen)
	_, err = io.ReadFull(conn, skipBuf)
	return err
}
