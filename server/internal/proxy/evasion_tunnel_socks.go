package proxy

import (
	"encoding/binary"
	"io"
	"net"
)

// handleSocksConnection handles the negotiation and forwarding of a SOCKS5 client connection.
func (m *EvasionTunnelManager) handleSocksConnection(client net.Conn, splitBytes int, delayMs int, mutateHost bool, mutateHeaderSpace bool, autoSni bool, sniSplitOffset int, packets string, minLen, maxLen int, tlsRecordSplit bool, dnsResolver string, sniSpoof string, clientHelloPadding int, delayJitter bool, tcpWindowClamp int, customUserAgent string) {
	shouldClose := true
	defer func() {
		if shouldClose {
			client.Close()
		}
	}()

	buf := make([]byte, 256)
	if _, err := io.ReadAtLeast(client, buf, 2); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	numMethods := int(buf[1])
	if _, err := io.ReadAtLeast(client, buf[:numMethods], numMethods); err != nil {
		return
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	if _, err := io.ReadAtLeast(client, buf[:4], 4); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}

	if buf[1] == 0x03 {
		localIP, _, _ := net.SplitHostPort(client.LocalAddr().String())
		HandleSocksUDPAssociate(client, localIP)
		shouldClose = false
		return
	}

	if buf[1] != 0x01 {
		return
	}

	var host string
	var port uint16

	switch buf[3] {
	case 0x01:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadAtLeast(client, ipBuf, 4); err != nil {
			return
		}
		host = net.IP(ipBuf).String()
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadAtLeast(client, lenBuf, 1); err != nil {
			return
		}
		domainLen := int(lenBuf[0])
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadAtLeast(client, domainBuf, domainLen); err != nil {
			return
		}
		host = string(domainBuf)
	case 0x04:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadAtLeast(client, ipBuf, 16); err != nil {
			return
		}
		host = net.IP(ipBuf).String()
	default:
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadAtLeast(client, portBuf, 2); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(portBuf)

	m.log("Routing request to %s:%d through evasion engine...", host, port)
	target, err := m.dialWithEvasion(host, port, splitBytes, delayMs, mutateHost, mutateHeaderSpace, autoSni, sniSplitOffset, packets, minLen, maxLen, tlsRecordSplit, dnsResolver, sniSpoof, clientHelloPadding, delayJitter, tcpWindowClamp, customUserAgent)
	if err != nil {
		m.log("Dial failure to %s:%d: %v", host, port, err)
		_, _ = client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer func() {
		if shouldClose {
			target.Close()
		}
	}()

	_, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})
	if err != nil {
		return
	}

	m.mu.Lock()
	reactorEnabled := m.asyncReactorEnabled
	reactor := m.reactor
	m.mu.Unlock()

	if reactorEnabled && reactor != nil {
		err = reactor.Register(client, target)
		if err == nil {
			m.log("Asynchronously registered connection pair (%s:%d) with AsyncReactor.", host, port)
			shouldClose = false
			return
		}
		m.log("Failed to register with AsyncReactor: %v. Falling back to copy goroutines.", err)
	}

	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, client)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(client, target)
		errChan <- err
	}()

	err = <-errChan
	if err != nil {
		m.log("Connection closed with log: %v", err)
	} else {
		m.log("Connection to %s:%d closed normally.", host, port)
	}
}
