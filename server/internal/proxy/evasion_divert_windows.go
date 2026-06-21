//go:build windows

package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"unsafe"

	"github.com/maybeknott/luminet/internal/bridge"
)

// WinDivert DLL bindings
var (
	modWinDivert                     = syscall.NewLazyDLL("WinDivert.dll")
	procWinDivertOpen                = modWinDivert.NewProc("WinDivertOpen")
	procWinDivertRecv                = modWinDivert.NewProc("WinDivertRecv")
	procWinDivertSend                = modWinDivert.NewProc("WinDivertSend")
	procWinDivertClose               = modWinDivert.NewProc("WinDivertClose")
	procWinDivertHelperCalcChecksums = modWinDivert.NewProc("WinDivertHelperCalcChecksums")
)

const (
	WINDIVERT_LAYER_NETWORK = 0
	WINDIVERT_FLAG_NO_RECV  = 1
)

// WinDivertAddress matches the C memory layout of WINDIVERT_ADDRESS
type WinDivertAddress struct {
	Timestamp int64
	IfIdx     uint32
	SubIfIdx  uint32
	Data      uint8
}

// WindowsPacketInjector implements PacketInjector using native WinDivert DLL calls.
type WindowsPacketInjector struct {
	mu         sync.Mutex
	running    bool
	handle     uintptr
	cancelFunc context.CancelFunc
}

func NewPacketInjector() PacketInjector {
	return &WindowsPacketInjector{
		handle: ^uintptr(0), // INVALID_HANDLE_VALUE
	}
}

// RST Drop registry for Windows
var (
	rstDropRegistry = make(map[string]bool)
	rstDropMu       sync.Mutex
)

// InstallRstDropRule registers a destination IP for RST blocking
func InstallRstDropRule(ip string) error {
	rstDropMu.Lock()
	defer rstDropMu.Unlock()
	rstDropRegistry[ip] = true
	return nil
}

// RemoveRstDropRule unregisters a destination IP for RST blocking
func RemoveRstDropRule(ip string) error {
	rstDropMu.Lock()
	defer rstDropMu.Unlock()
	delete(rstDropRegistry, ip)
	return nil
}

func shouldDropRst(ip string) bool {
	rstDropMu.Lock()
	defer rstDropMu.Unlock()
	return rstDropRegistry[ip]
}

func (w *WindowsPacketInjector) Start(ctx context.Context, listenPort int) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.running {
		return nil
	}

	// Try loading WinDivert.dll to fail fast if missing
	if err := modWinDivert.Load(); err != nil {
		return fmt.Errorf("WinDivert.dll not found: %w", err)
	}

	// Capture outbound TCP handshakes (SYN packets) targeting standard HTTP/HTTPS ports or outbound TCP RST packets
	filterStr := fmt.Sprintf("outbound and tcp and ( (tcp.Syn and not tcp.Ack and (tcp.DstPort == 80 or tcp.DstPort == 443)) or tcp.Rst )")
	filterBytes := append([]byte(filterStr), 0)

	// Open WinDivert handle (Layer=Network, Priority=0, Flags=0)
	handle, _, err := procWinDivertOpen.Call(
		uintptr(unsafe.Pointer(&filterBytes[0])),
		WINDIVERT_LAYER_NETWORK,
		0,
		0,
	)
	if handle == ^uintptr(0) {
		return fmt.Errorf("failed to open WinDivert handle (requires Admin privileges): %w", err)
	}

	w.handle = handle
	subCtx, cancel := context.WithCancel(ctx)
	w.cancelFunc = cancel
	w.running = true

	// Sniffer capture and forward loop
	go func() {
		defer func() {
			w.mu.Lock()
			procWinDivertClose.Call(w.handle)
			w.handle = ^uintptr(0)
			w.running = false
			w.mu.Unlock()
		}()

		packetBuf := make([]byte, 65536)
		var addr WinDivertAddress

		for {
			select {
			case <-subCtx.Done():
				return
			default:
				var readLen uint32
				ok, _, _ := procWinDivertRecv.Call(
					w.handle,
					uintptr(unsafe.Pointer(&packetBuf[0])),
					uintptr(len(packetBuf)),
					uintptr(unsafe.Pointer(&readLen)),
					uintptr(unsafe.Pointer(&addr)),
				)
				if ok == 0 {
					// Timeout or read failure
					continue
				}

				// Succeeded in capturing a packet
				packetBytes := packetBuf[:readLen]
				if len(packetBytes) >= 20 {
					// Check if this is a RST packet we should drop
					proto := packetBytes[9]
					if proto == 6 {
						ihl := int(packetBytes[0]&0x0F) * 4
						if len(packetBytes) >= ihl+20 {
							tcpSegment := packetBytes[ihl:]
							flags := tcpSegment[13]
							isRst := (flags & 0x04) != 0
							if isRst {
								dstIP := net.IPv4(packetBytes[16], packetBytes[17], packetBytes[18], packetBytes[19]).String()
								if shouldDropRst(dstIP) {
									// Drop the RST packet by not forwarding it!
									continue
								}
							}
						}
					}
				}

				srcPort, dstPort, seq, isSyn := parseTCPHandshake(packetBytes)
				if isSyn {
					RegisterConnSeq(srcPort, dstPort, seq)
				}

				// Forward the intercepted packet unchanged
				var writeLen uint32
				_, _, _ = procWinDivertSend.Call(
					w.handle,
					uintptr(unsafe.Pointer(&packetBytes[0])),
					uintptr(len(packetBytes)),
					uintptr(unsafe.Pointer(&writeLen)),
					uintptr(unsafe.Pointer(&addr)),
				)
			}
		}
	}()

	return nil
}

func (w *WindowsPacketInjector) Stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.running {
		return nil
	}

	if w.cancelFunc != nil {
		w.cancelFunc()
	}
	return nil
}

func (w *WindowsPacketInjector) IsRunning() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.running
}

// InjectWindowsDivertPacket crafts and injects a raw TCP packet using WinDivert driver directly.
func InjectWindowsDivertPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, ttl uint32, flags uint8, seq, ack uint32, payload []byte) error {
	if err := modWinDivert.Load(); err != nil {
		return fmt.Errorf("WinDivert.dll not found: %w", err)
	}

	// Open a send-only handle
	filterBytes := []byte("false\x00")
	handle, _, err := procWinDivertOpen.Call(
		uintptr(unsafe.Pointer(&filterBytes[0])),
		WINDIVERT_LAYER_NETWORK,
		0,
		WINDIVERT_FLAG_NO_RECV,
	)
	if handle == ^uintptr(0) {
		return fmt.Errorf("failed to open WinDivert for packet injection: %w", err)
	}
	defer procWinDivertClose.Call(handle)

	// Craft raw IP+TCP packet bytes (using the cross-platform CraftTCPPacket function)
	packet := CraftTCPPacket(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload, ttl)

	var addr WinDivertAddress
	addr.Data = 1 // Outbound flag
	addr.IfIdx = 0
	addr.SubIfIdx = 0

	var writeLen uint32
	ok, _, err := procWinDivertSend.Call(
		handle,
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&writeLen)),
		uintptr(unsafe.Pointer(&addr)),
	)
	if ok == 0 {
		return fmt.Errorf("WinDivertSend packet injection failed: %w", err)
	}

	return nil
}

// InjectTCPDecoy Windows wrong-sequence injection helper
func InjectTCPDecoy(destIP string, destPort uint16, synSeq uint32, ttl uint32, payloadHex string, payloadLen int) error {
	wrongSeq := (synSeq + 1 - uint32(payloadLen)) & 0xFFFFFFFF
	flags := uint8(0x18) // PSH, ACK
	ack := synSeq + 1
	return bridge.InjectFakePacket(destIP, destPort, ttl, &flags, &wrongSeq, &ack, payloadHex)
}

// StartBypassSniffer starts a dynamic WinDivert sniffer for the specific Raw Handshake Bypass connection
func StartBypassSniffer(conn *rawBypassConn) {
	filterStr := fmt.Sprintf("inbound and tcp and ip.SrcAddr == %s and tcp.SrcPort == %d and tcp.DstPort == %d\x00", conn.remoteIP.String(), conn.remotePort, conn.localPort)
	
	if err := modWinDivert.Load(); err != nil {
		return
	}

	handle, _, _ := procWinDivertOpen.Call(
		uintptr(unsafe.Pointer(&[]byte(filterStr)[0])),
		WINDIVERT_LAYER_NETWORK,
		0,
		0,
	)
	if handle == ^uintptr(0) {
		return
	}

	go func() {
		defer procWinDivertClose.Call(handle)
		packetBuf := make([]byte, 65536)
		var addr WinDivertAddress

		for {
			select {
			case <-conn.closed:
				return
			default:
				var readLen uint32
				ok, _, _ := procWinDivertRecv.Call(
					handle,
					uintptr(unsafe.Pointer(&packetBuf[0])),
					uintptr(len(packetBuf)),
					uintptr(unsafe.Pointer(&readLen)),
					uintptr(unsafe.Pointer(&addr)),
				)
				if ok == 0 {
					continue
				}

				packetBytes := packetBuf[:readLen]
				if len(packetBytes) >= 20 {
					ihl := int(packetBytes[0]&0x0F) * 4
					if len(packetBytes) > ihl+20 {
						tcpSegment := packetBytes[ihl:]
						dataOffset := int(tcpSegment[12]>>4) * 4
						payload := tcpSegment[dataOffset:]
						
						// In Windows raw TCP, the sequence number is 32-bit big-endian at offset 4 of the TCP header.
						// Wait, let's extract it safely:
						if len(tcpSegment) >= 8 {
							recvSeq := binary.BigEndian.Uint32(tcpSegment[4:8])
							conn.ack = (recvSeq + uint32(len(payload))) & 0xFFFFFFFF
						}

						if len(payload) > 0 {
							select {
							case conn.readChan <- append([]byte(nil), payload...):
							case <-conn.closed:
								return
							}
						}
					}
				}
				// We consume and drop the incoming packet so the OS TCP stack doesn't see it and send a RST.
			}
		}
	}()
}
