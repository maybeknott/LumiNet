//go:build linux

package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/maybeknott/luminet/internal/bridge"
)

// MacInfo caches Ethernet MAC addresses and interface index for a target IP address.
type MacInfo struct {
	SrcMAC  [6]byte
	DstMAC  [6]byte
	IfIndex int
}

var (
	macRegistry = make(map[string]MacInfo)
	macMu       sync.Mutex
)

// RegisterMacInfo registers MAC information for a destination IP
func RegisterMacInfo(ip string, info MacInfo) {
	macMu.Lock()
	defer macMu.Unlock()
	macRegistry[ip] = info
}

// GetMacInfo returns the cached MAC information for a destination IP
func GetMacInfo(ip string) (MacInfo, bool) {
	macMu.Lock()
	defer macMu.Unlock()
	info, found := macRegistry[ip]
	return info, found
}

// LinuxPacketInjector implements PacketInjector using raw AF_PACKET/NFQueue interfaces.
type LinuxPacketInjector struct {
	mu         sync.Mutex
	running    bool
	cancelFunc context.CancelFunc
}

func NewPacketInjector() PacketInjector {
	return &LinuxPacketInjector{}
}

func (l *LinuxPacketInjector) Start(ctx context.Context, listenPort int) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return nil
	}

	subCtx, cancel := context.WithCancel(ctx)
	l.cancelFunc = cancel
	l.running = true

	// Linux raw socket/nfqueue listener loop
	go func() {
		defer func() {
			l.mu.Lock()
			l.running = false
			l.mu.Unlock()
		}()

		// Open Linux raw AF_PACKET socket to capture outbound packet handshakes at device driver level
		fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))
		if err != nil {
			// Fallback to SOCK_RAW if non-root or missing capabilities
			fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
			if err != nil {
				for {
					select {
					case <-subCtx.Done():
						return
					default:
						time.Sleep(500 * time.Millisecond)
					}
				}
			}
		}
		defer syscall.Close(fd)

		buf := make([]byte, 65536)
		for {
			select {
			case <-subCtx.Done():
				return
			default:
				// Use non-blocking mode or small timeouts
				_ = syscall.SetNonblock(fd, true)
				
				var from syscall.Sockaddr
				n, err := syscall.Recvfrom(fd, buf, 0)
				if err != nil {
					time.Sleep(20 * time.Millisecond)
					continue
				}

				// If it's an AF_PACKET socket, the payload includes the 14-byte Ethernet header.
				// If it's a SOCK_RAW IP socket, it starts directly with the IP header.
				var ipPacket []byte
				var isEth bool
				var ifIndex int

				if sll, ok := from.(*syscall.SockaddrLinklayer); ok {
					ifIndex = sll.Ifindex
					isEth = true
				}

				if isEth {
					if n >= 14+20 {
						ethType := binary.BigEndian.Uint16(buf[12:14])
						if ethType == 0x0800 { // IPv4
							ipPacket = buf[14:n]
							
							// Extract MAC addresses and cache them under destination IP
							dstIP := net.IPv4(ipPacket[16], ipPacket[17], ipPacket[18], ipPacket[19])
							var sMac, dMac [6]byte
							copy(dMac[:], buf[0:6])
							copy(sMac[:], buf[6:12])

							RegisterMacInfo(dstIP.String(), MacInfo{
								SrcMAC:  sMac,
								DstMAC:  dMac,
								IfIndex: ifIndex,
							})
						}
					}
				} else {
					ipPacket = buf[:n]
				}

				if len(ipPacket) >= 20 {
					srcPort, dstPort, seq, isSyn := parseTCPHandshake(ipPacket)
					if isSyn {
						RegisterConnSeq(srcPort, dstPort, seq)
					}
				}
			}
		}
	}()

	return nil
}

func (l *LinuxPacketInjector) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.running {
		return nil
	}

	if l.cancelFunc != nil {
		l.cancelFunc()
	}
	l.running = false
	return nil
}

func (l *LinuxPacketInjector) IsRunning() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.running
}

// InstallRstDropRule adds an iptables rule to drop outbound TCP RST packets to a destination IP
func InstallRstDropRule(destination string) error {
	return exec.Command("iptables", "-A", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-d", destination, "-j", "DROP").Run()
}

// RemoveRstDropRule removes the iptables rule dropping outbound TCP RST packets
func RemoveRstDropRule(destination string) error {
	return exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-d", destination, "-j", "DROP").Run()
}

func injectLinkLayer(macInfo MacInfo, srcIP, dstIP net.IP, srcPort, dstPort uint16, ttl uint32, flags uint8, seq, ack uint32, payload []byte) error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))
	if err != nil {
		return fmt.Errorf("failed to open raw AF_PACKET socket: %w", err)
	}
	defer syscall.Close(fd)

	sll := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_IP),
		Ifindex:  macInfo.IfIndex,
	}

	ipTcpPacket := CraftTCPPacket(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload, ttl)

	// Build Ethernet frame
	ethFrame := make([]byte, 14+len(ipTcpPacket))
	copy(ethFrame[0:6], macInfo.DstMAC[:])
	copy(ethFrame[6:12], macInfo.SrcMAC[:])
	binary.BigEndian.PutUint16(ethFrame[12:14], 0x0800) // IPv4 EtherType
	copy(ethFrame[14:], ipTcpPacket)

	err = syscall.Sendto(fd, ethFrame, 0, sll)
	if err != nil {
		return fmt.Errorf("failed to send raw ethernet frame: %w", err)
	}
	return nil
}

func injectIPRaw(srcIP, dstIP net.IP, srcPort, dstPort uint16, ttl uint32, flags uint8, seq, ack uint32, payload []byte) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("failed to open raw IP socket: %w", err)
	}
	defer syscall.Close(fd)

	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return fmt.Errorf("failed to set IP_HDRINCL: %w", err)
	}

	packetBytes := CraftTCPPacket(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload, ttl)

	addr := &syscall.SockaddrInet4{
		Port: int(dstPort),
	}
	copy(addr.Addr[:], dstIP.To4())

	err = syscall.Sendto(fd, packetBytes, 0, addr)
	if err != nil {
		return fmt.Errorf("failed to send raw IP packet: %w", err)
	}
	return nil
}

// InjectWindowsDivertPacket is implemented using AF_PACKET link-layer injection (if MAC info is cached) or falling back to raw IP injection.
func InjectWindowsDivertPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, ttl uint32, flags uint8, seq, ack uint32, payload []byte) error {
	macInfo, found := GetMacInfo(dstIP.String())
	if found {
		err := injectLinkLayer(macInfo, srcIP, dstIP, srcPort, dstPort, ttl, flags, seq, ack, payload)
		if err == nil {
			return nil
		}
	}
	return injectIPRaw(srcIP, dstIP, srcPort, dstPort, ttl, flags, seq, ack, payload)
}

// InjectTCPDecoy wrong-sequence injection helper
func InjectTCPDecoy(destIP string, destPort uint16, synSeq uint32, ttl uint32, payloadHex string, payloadLen int) error {
	wrongSeq := (synSeq + 1 - uint32(payloadLen)) & 0xFFFFFFFF
	flags := uint8(0x18) // PSH, ACK
	ack := synSeq + 1
	return bridge.InjectFakePacket(destIP, destPort, ttl, &flags, &wrongSeq, &ack, payloadHex)
}

// StartBypassSniffer starts a raw socket sniffer loop for the specific bypass connection on Linux
func StartBypassSniffer(conn *rawBypassConn) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return
	}

	go func() {
		defer syscall.Close(fd)
		buf := make([]byte, 65536)
		for {
			select {
			case <-conn.closed:
				return
			default:
				_ = syscall.SetNonblock(fd, true)
				n, _, err := syscall.Recvfrom(fd, buf, 0)
				if err != nil {
					time.Sleep(20 * time.Millisecond)
					continue
				}
				if n >= 20 {
					version := buf[0] >> 4
					if version != 4 {
						continue
					}
					ihl := int(buf[0]&0x0F) * 4
					if n < ihl+20 {
						continue
					}
					
					srcIP := net.IPv4(buf[12], buf[13], buf[14], buf[15])
					if !srcIP.Equal(conn.remoteIP) {
						continue
					}
					
					tcpSegment := buf[ihl:n]
					srcPort := binary.BigEndian.Uint16(tcpSegment[0:2])
					dstPort := binary.BigEndian.Uint16(tcpSegment[2:4])
					if srcPort != conn.remotePort || dstPort != conn.localPort {
						continue
					}

					dataOffset := int(tcpSegment[12]>>4) * 4
					payload := tcpSegment[dataOffset:]
					
					recvSeq := binary.BigEndian.Uint32(tcpSegment[4:8])
					conn.ack = (recvSeq + uint32(len(payload))) & 0xFFFFFFFF

					if len(payload) > 0 {
						select {
						case conn.readChan <- append([]byte(nil), payload...):
						case <-conn.closed:
							return
						}
					}
				}
			}
		}
	}()
}
