package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestDialWithMark(t *testing.T) {
	// Start a local test listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := DialWithMark(ctx, "tcp", l.Addr().String(), 0x40)
	if err != nil {
		t.Fatalf("DialWithMark failed: %v", err)
	}
	defer conn.Close()
}

func TestHandleSocksUDPAssociate(t *testing.T) {
	// 1. Start target UDP Echo Server
	targetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to start target UDP server: %v", err)
	}
	defer targetConn.Close()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := targetConn.ReadFrom(buf)
			if err != nil {
				return
			}
			// Echo back
			_, _ = targetConn.WriteTo(buf[:n], addr)
		}
	}()

	_, targetPortStr, _ := net.SplitHostPort(targetConn.LocalAddr().String())
	var targetPort uint16
	_, _ = fmt.Sscanf(targetPortStr, "%d", &targetPort)

	// 2. Start mock SOCKS5 Server
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start SOCKS5 listener: %v", err)
	}
	defer socksListener.Close()

	go func() {
		conn, err := socksListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Perform handshake greetings
		buf := make([]byte, 256)
		_, _ = conn.Read(buf) // read greeting
		_, _ = conn.Write([]byte{0x05, 0x00}) // send no-auth reply

		_, _ = conn.Read(buf) // read cmd request (expect UDP Associate)
		if buf[1] == 0x03 {
			HandleSocksUDPAssociate(conn, "127.0.0.1")
		}
	}()

	// 3. Connect SOCKS5 Client
	clientConn, err := net.Dial("tcp", socksListener.Addr().String())
	if err != nil {
		t.Fatalf("client failed to dial SOCKS5 server: %v", err)
	}
	defer clientConn.Close()

	// SOCKS5 Greeting
	_, err = clientConn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		t.Fatalf("failed to write greeting: %v", err)
	}

	reply := make([]byte, 2)
	_, err = clientConn.Read(reply)
	if err != nil || reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("invalid greeting reply: %v", reply)
	}

	// SOCKS5 UDP Associate Request
	_, err = clientConn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.Fatalf("failed to send UDP Associate cmd: %v", err)
	}

	cmdReply := make([]byte, 10)
	_, err = clientConn.Read(cmdReply)
	if err != nil || cmdReply[1] != 0x00 {
		t.Fatalf("invalid cmd reply: %v", cmdReply)
	}

	// Server's bound UDP address and port
	serverUDPPort := binary.BigEndian.Uint16(cmdReply[8:10])

	// 4. Start client UDP socket and send mapped request
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to open client UDP: %v", err)
	}
	defer clientUDP.Close()

	serverUDPAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", serverUDPPort))
	if err != nil {
		t.Fatalf("resolve server UDP address failed: %v", err)
	}

	// Construct SOCKS5 UDP request: RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR(4) | DST.PORT(2) | DATA
	reqHeader := []byte{0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1}
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, targetPort)
	reqHeader = append(reqHeader, portBuf...)
	payload := []byte("hello-stun-ping")
	packet := append(reqHeader, payload...)

	_, err = clientUDP.WriteToUDP(packet, serverUDPAddr)
	if err != nil {
		t.Fatalf("failed to send UDP packet: %v", err)
	}

	// Read response
	_ = clientUDP.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 1024)
	n, _, err := clientUDP.ReadFromUDP(respBuf)
	if err != nil {
		t.Fatalf("failed to read UDP reply: %v", err)
	}

	if n < 10 {
		t.Fatalf("UDP reply too short: %d bytes", n)
	}

	respPayload := respBuf[10:n]
	if string(respPayload) != "hello-stun-ping" {
		t.Errorf("expected payload 'hello-stun-ping', got '%s'", string(respPayload))
	}
}
