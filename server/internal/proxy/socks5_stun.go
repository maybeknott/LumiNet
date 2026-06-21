package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

// DialWithMark establishes an outbound TCP/UDP connection with a specific socket mark (SO_MARK) applied.
// This is used on Linux to bypass virtual TUN routing tables and prevent routing loops.
func DialWithMark(ctx context.Context, network, address string, fwmark int) (net.Conn, error) {
	dialer := &net.Dialer{
		Control: func(netw, addr string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				applySocketMark(fd, fwmark)
			})
		},
	}
	return dialer.DialContext(ctx, network, address)
}

// HandleSocksUDPAssociate handles SOCKS5 UDP ASSOCIATE commands, relaying UDP datagrams
// between the SOCKS5 client and remote servers.
func HandleSocksUDPAssociate(client net.Conn, bindIP string) {
	// 1. Bind to an ephemeral UDP port
	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer udpListener.Close()

	// Get local port
	_, localPortStr, _ := net.SplitHostPort(udpListener.LocalAddr().String())
	var localPort uint16
	_, _ = fmt.Sscanf(localPortStr, "%d", &localPort)

	// Build SOCKS5 success reply
	bndIP := net.ParseIP(bindIP)
	if bndIP == nil {
		bndIP = net.ParseIP("127.0.0.1")
	}

	reply := make([]byte, 4)
	reply[0] = 0x05 // VER
	reply[1] = 0x00 // SUCCESS
	reply[2] = 0x00 // RSV
	if ip4 := bndIP.To4(); ip4 != nil {
		reply[3] = 0x01 // ATYP IPv4
		reply = append(reply, ip4...)
	} else if ip6 := bndIP.To16(); ip6 != nil {
		reply[3] = 0x04 // ATYP IPv6
		reply = append(reply, ip6...)
	} else {
		reply[3] = 0x01
		reply = append(reply, []byte{127, 0, 0, 1}...)
	}

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, localPort)
	reply = append(reply, portBuf...)

	if _, err := client.Write(reply); err != nil {
		return
	}

	// 2. Relay SOCKS5 UDP packets
	var clientUDPAddr *net.UDPAddr
	var clientUdpAddrMu sync.Mutex

	tcpClosed := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		_, _ = client.Read(buf)
		close(tcpClosed)
		_ = udpListener.Close() // break the ReadFromUDP loop
	}()

	buf := make([]byte, 65536)
	idleTimeout := 120 * time.Second
	timer := time.NewTimer(idleTimeout)
	defer timer.Stop()

	for {
		_ = udpListener.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, addr, err := udpListener.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-tcpClosed:
				return
			default:
			}
			select {
			case <-timer.C:
				return
			default:
				timer.Reset(idleTimeout)
				continue
			}
		}

		timer.Reset(idleTimeout)

		clientUdpAddrMu.Lock()
		isClientPacket := clientUDPAddr == nil || (addr.IP.Equal(clientUDPAddr.IP) && addr.Port == clientUDPAddr.Port)
		clientUdpAddrMu.Unlock()

		if isClientPacket {
			// Datagram from client: parse SOCKS5 UDP header
			if n < 10 {
				continue
			}
			if buf[2] != 0x00 {
				continue // fragments not supported
			}

			atyp := buf[3]
			var offset int
			var destHost string

			switch atyp {
			case 0x01: // IPv4
				destHost = net.IP(buf[4:8]).String()
				offset = 8
			case 0x03: // Domain
				domainLen := int(buf[4])
				destHost = string(buf[5 : 5+domainLen])
				offset = 5 + domainLen
			case 0x04: // IPv6
				destHost = net.IP(buf[4:20]).String()
				offset = 20
			default:
				continue
			}

			destPort := binary.BigEndian.Uint16(buf[offset : offset+2])
			payload := buf[offset+2 : n]

			clientUdpAddrMu.Lock()
			if clientUDPAddr == nil {
				clientUDPAddr = addr
			}
			clientUdpAddrMu.Unlock()

			destUDPAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(destHost, fmt.Sprintf("%d", destPort)))
			if err != nil {
				continue
			}

			_, _ = udpListener.WriteToUDP(payload, destUDPAddr)

		} else {
			// Datagram from remote destination: wrap and send to client
			clientUdpAddrMu.Lock()
			targetClient := clientUDPAddr
			clientUdpAddrMu.Unlock()

			if targetClient != nil {
				header := []byte{0, 0, 0}
				ip := addr.IP.To4()
				if ip != nil {
					header = append(header, 0x01)
					header = append(header, ip...)
				} else {
					ip = addr.IP.To16()
					if ip != nil {
						header = append(header, 0x04)
						header = append(header, ip...)
					} else {
						continue
					}
				}
				portBuf := make([]byte, 2)
				binary.BigEndian.PutUint16(portBuf, uint16(addr.Port))
				header = append(header, portBuf...)

				wrapped := append(header, buf[:n]...)
				_, _ = udpListener.WriteToUDP(wrapped, targetClient)
			}
		}
	}
}
