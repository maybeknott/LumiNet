package proxy

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/maybeknott/luminet/internal/bridge"
)

// ponytail: connection wrapper decomposed from evasion_tunnel.go.
type evasionTunnelConn struct {
	net.Conn
	splitBytes         int
	delayMs            int
	mutateHost         bool
	mutateHeaderSpace  bool
	autoSni            bool
	precisionSniSplits bool
	sniSplitOffset     int // Hostname-level split offset inside TLS ClientHello Server Name Indication
	packets            string
	minLength          int
	maxLength          int
	tlsRecordSplit     bool
	sniSpoof           string // SNI spoofing target (optional)
	clientHelloPadding int    // TLS ClientHello padding size (optional)
	delayJitter        bool
	tcpWindowClamp      int
	customUserAgent    string
	fakePacketInject   bool
	fakePacketTtl      int
	firstWrite         bool

	// New advanced evasion features
	mutateSniCase      bool
	mutateMethod       bool
	mutateAbsoluteUri  bool
	httpPadding        int
	preflightSignature string
	preflightDelayMs    int

	// Session-level write fragmentation (adapted from Psiphon's fragmentor)
	sessionFrag           bool
	sessionFragProb       float64
	sessionFragMinTotal   int
	sessionFragMaxTotal   int
	sessionFragMinChunk   int
	sessionFragMaxChunk   int
	sessionFragMinDelayMs int
	sessionFragMaxDelayMs int

	ipSpoofingEnabled bool
	ipSpoofingDecoyIP string
	ipSpoofingDstReal string

	outOfWindowEnabled   bool
	outOfWindowSeqOffset int
	decoySniPool         string

	// Session-level fragmentation state
	sessionFragDetermined bool
	sessionFragTotalBytes int
	sessionFragBytesCount int

	oobEnabled   bool
	oobexEnabled bool
	oobSent      bool
}

// SyscallConn implements syscall.Conn to expose the underlying raw socket connection.
func (c *evasionTunnelConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := c.Conn.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, fmt.Errorf("underlying connection does not support SyscallConn")
}


func (c *evasionTunnelConn) sleepWithJitter() {
	if c.delayMs <= 0 {
		return
	}
	delay := c.delayMs
	if c.delayJitter {
		minD := c.delayMs / 2
		if minD < 1 {
			minD = 1
		}
		maxD := c.delayMs * 3 / 2
		delay = minD + rand.Intn(maxD-minD+1)
	}
	time.Sleep(time.Duration(delay) * time.Millisecond)
}

func (c *evasionTunnelConn) writeRaw(b []byte) (int, error) {
	var n int
	var err error
	if c.oobEnabled && !c.oobSent {
		c.oobSent = true
		err = sendWithOOB(c.Conn, b, 0x0)
		if err == nil {
			n = len(b)
		}
	} else {
		n, err = c.Conn.Write(b)
	}
	if err == nil && n > 0 {
		AddUploadBytes(uint64(n))
	}
	return n, err
}

func (c *evasionTunnelConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err == nil && n > 0 {
		AddDownloadBytes(uint64(n))
	}
	return n, err
}

func (c *evasionTunnelConn) Write(b []byte) (int, error) {
	// 1. First write mutations and injections
	payload := b
	if c.firstWrite {
		c.firstWrite = false

		if c.oobexEnabled && len(payload) >= 20 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01 {
			c.oobSent = true
			err1 := sendWithOOB(c.Conn, payload[:15], payload[15])
			if err1 != nil {
				return 0, err1
			}
			err2 := sendWithOOB(c.Conn, payload[16:20], 0x0)
			if err2 != nil {
				return 15, err2
			}
			c.sleepWithJitter()
			payload = payload[20:]
		}

		// Inject preflight signature if specified
		if c.preflightSignature != "" {
			sigBytes, err := parseCPSPacket(c.preflightSignature)
			if err == nil && len(sigBytes) > 0 {
				if _, err := c.writeRaw(sigBytes); err != nil {
					return 0, err
				}
				if c.preflightDelayMs > 0 {
					time.Sleep(time.Duration(c.preflightDelayMs) * time.Millisecond)
				}
			}
		}

		// Perform fake packet injection if enabled
		if c.fakePacketInject {
			remoteAddr := c.RemoteAddr().String()
			if host, portStr, err := net.SplitHostPort(remoteAddr); err == nil {
				var portVal uint16
				fmt.Sscanf(portStr, "%d", &portVal)
				if portVal > 0 {
					decoySNI := "blocked-website-check.com"
					if c.decoySniPool != "" {
						pool := strings.Split(c.decoySniPool, ",")
						var cleanPool []string
						for _, item := range pool {
							item = strings.TrimSpace(item)
							if item != "" {
								cleanPool = append(cleanPool, item)
							}
						}
						if len(cleanPool) > 0 {
							// Pick a random decoy SNI from pool
							decoySNI = cleanPool[rand.Intn(len(cleanPool))]
						}
					}

					// Apply casing mutation to decoy SNI if enabled
					if c.mutateSniCase {
						decoySNI = mutateStringCasing(decoySNI)
					}

					var fakePayloadHex string
					var payloadLen int
					var payloadBytes []byte
					if portVal == 80 {
						// HTTP GET request to a fake domain
						payloadBytes = []byte("GET / HTTP/1.1\r\nHost: " + decoySNI + "\r\n\r\n")
						payloadLen = len(payloadBytes)
						fakePayloadHex = hex.EncodeToString(payloadBytes)
					} else {
						// Fake TLS ClientHello with decoy SNI
						templateBytes, _ := hex.DecodeString("16030100ba010000b60303" + // Record header & Handshake header & version
							"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" + // Random bytes
							"00" + // Session ID length (0)
							"0002002f" + // Cipher Suites length & cipher (TLS_RSA_WITH_AES_128_CBC_SHA)
							"0100" + // Compression methods length & null
							"0087" + // Extensions length (135 bytes)
							"0000" + // Extension: Server Name
							"0020001e00001b626c6f636b65642d776562736974652d636865636b2e636f6d") // Server Name "blocked-website-check.com"
						payloadBytes = ReplaceSniInHello(templateBytes, decoySNI)
						payloadLen = len(payloadBytes)
						fakePayloadHex = hex.EncodeToString(payloadBytes)
					}

					var flagsVal uint8 = 0x18
					var seqVal uint32
					var ackVal uint32
					var hasSeqInfo bool

					localTCP, okLocal := c.LocalAddr().(*net.TCPAddr)
					remoteTCP, okRemote := c.RemoteAddr().(*net.TCPAddr)

					if okLocal && okRemote {
						localPort := uint16(localTCP.Port)
						remotePort := uint16(remoteTCP.Port)
						if synSeq, found := GetConnSeq(localPort, remotePort); found {
							hasSeqInfo = true
							if c.outOfWindowEnabled {
								seqVal = (synSeq + 1 - uint32(payloadLen) + uint32(c.outOfWindowSeqOffset)) & 0xFFFFFFFF
							} else {
								seqVal = synSeq + 1
							}
							ackVal = synSeq + 1
							// Cleanup registered sequence number after consumption
							ClearConnSeq(localPort, remotePort)
						} else {
							// If SYN was not captured, default fallback values
							seqVal = 1000
							ackVal = 1
						}
					}

					var injectErr error
					if okLocal && okRemote {
						injectErr = InjectWindowsDivertPacket(
							localTCP.IP,
							remoteTCP.IP,
							uint16(localTCP.Port),
							uint16(remoteTCP.Port),
							uint32(c.fakePacketTtl),
							flagsVal,
							seqVal,
							ackVal,
							payloadBytes,
						)
					} else {
						injectErr = fmt.Errorf("local/remote addresses are not TCP")
					}

					if injectErr != nil {
						// Fallback to Rust-based bridge injection
						var flagsPtr *uint8
						var seqPtr *uint32
						var ackPtr *uint32

						if hasSeqInfo && c.outOfWindowEnabled {
							flagsPtr = &flagsVal
							seqPtr = &seqVal
							ackPtr = &ackVal
						}

						_ = bridge.InjectFakePacket(host, portVal, uint32(c.fakePacketTtl), flagsPtr, seqPtr, ackPtr, fakePayloadHex)
					}
				}
			}
		}

		if c.sniSpoof != "" && len(payload) >= 5 && payload[0] == 0x16 && payload[1] == 0x03 {
			payload = ReplaceSniInHello(payload, c.sniSpoof)
		}

		if c.mutateSniCase && len(payload) >= 5 && payload[0] == 0x16 && payload[1] == 0x03 {
			payload = MutateSniCaseInHello(payload)
		}

		if c.clientHelloPadding > 0 && len(payload) >= 5 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01 {
			if padded, err := padClientHelloBytes(payload, c.clientHelloPadding); err == nil {
				payload = padded
			}
		}

		if c.mutateHost || c.mutateHeaderSpace || c.mutateMethod || c.mutateAbsoluteUri || c.httpPadding > 0 {
			payload = normalizeHttpHeaders(payload, c.customUserAgent, c.mutateMethod, c.mutateAbsoluteUri, c.httpPadding)
			str := string(payload)
			if c.mutateHost && c.mutateHeaderSpace {
				str = strings.Replace(str, "Host:", "hOsT :", 1)
			} else if c.mutateHost {
				str = strings.Replace(str, "Host:", "hOsT:", 1)
			} else if c.mutateHeaderSpace {
				str = strings.Replace(str, "Host:", "Host :", 1)
			}
			payload = []byte(str)
		}
	}

	// 2. Psiphon-style session-level write fragmentation
	if c.sessionFrag {
		if !c.sessionFragDetermined {
			c.sessionFragDetermined = true
			if rand.Float64() < c.sessionFragProb {
				if c.sessionFragMaxTotal > c.sessionFragMinTotal {
					c.sessionFragTotalBytes = c.sessionFragMinTotal + rand.Intn(c.sessionFragMaxTotal-c.sessionFragMinTotal+1)
				} else {
					c.sessionFragTotalBytes = c.sessionFragMinTotal
				}
			} else {
				c.sessionFragTotalBytes = 0
			}
		}

		if c.sessionFragTotalBytes > 0 && c.sessionFragBytesCount < c.sessionFragTotalBytes {
			totalWritten := 0
			buffer := payload
			for len(buffer) > 0 {
				minChunk := c.sessionFragMinChunk
				if minChunk > len(buffer) {
					minChunk = len(buffer)
				}
				maxChunk := c.sessionFragMaxChunk
				if maxChunk > len(buffer) {
					maxChunk = len(buffer)
				}
				var chunkSize int
				if maxChunk > minChunk {
					chunkSize = minChunk + rand.Intn(maxChunk-minChunk+1)
				} else {
					chunkSize = minChunk
				}
				if chunkSize <= 0 {
					chunkSize = 1
				}

				var delayMs int
				if c.sessionFragMaxDelayMs > c.sessionFragMinDelayMs {
					delayMs = c.sessionFragMinDelayMs + rand.Intn(c.sessionFragMaxDelayMs-c.sessionFragMinDelayMs+1)
				} else {
					delayMs = c.sessionFragMinDelayMs
				}
				if delayMs > 0 {
					time.Sleep(time.Duration(delayMs) * time.Millisecond)
				}

				n, err := c.writeRaw(buffer[:chunkSize])
				totalWritten += n
				c.sessionFragBytesCount += n
				if err != nil {
					return totalWritten, err
				}

				buffer = buffer[chunkSize:]

				// Once we have satisfied the total bytes, write the rest directly
				if c.sessionFragBytesCount >= c.sessionFragTotalBytes && len(buffer) > 0 {
					nRest, err := c.writeRaw(buffer)
					totalWritten += nRest
					return totalWritten, err
				}
			}
			return totalWritten, nil
		}
	}

	// 3. Fallback to normal write-level fragmentations (only for first-write target packets, or general split)
	isTarget := false
	if c.packets == "all" {
		isTarget = true
	} else {
		// default to tlshello
		if len(payload) >= 5 && payload[0] == 0x16 && payload[1] == 0x03 {
			isTarget = true
		}
	}

	if !isTarget {
		return c.writeRaw(payload)
	}

	// User-space TCP segment size clamping (active fragmentation)
	if c.tcpWindowClamp > 0 && len(payload) > c.tcpWindowClamp {
		idx := 0
		totalWritten := 0
		for idx < len(payload) {
			chunkSize := c.tcpWindowClamp
			if idx+chunkSize > len(payload) {
				chunkSize = len(payload) - idx
			}

			n, err := c.writeRaw(payload[idx : idx+chunkSize])
			totalWritten += n
			if err != nil {
				return totalWritten, err
			}
			idx += chunkSize
			if idx < len(payload) {
				c.sleepWithJitter()
			}
		}
		return totalWritten, nil
	}

	// TLS Record-layer fragmentation (splits ClientHello handshake body into 2 records)
	if c.tlsRecordSplit && len(payload) >= 10 && payload[0] == 0x16 && payload[1] == 0x03 {
		recLen := int(binary.BigEndian.Uint16(payload[3:5]))
		if recLen > 5 && recLen+5 <= len(payload) {
			handshakeBody := payload[5 : 5+recLen]
			
			// Split the handshake body at a randomized offset (5 to 15 bytes) to prevent static signature detection
			splitLen := 5 + rand.Intn(11)
			if splitLen >= len(handshakeBody) {
				splitLen = 5
			}
			if splitLen < len(handshakeBody) {
				// Record 1
				header1 := []byte{0x16, payload[1], payload[2], 0, byte(splitLen)}
				if _, err := c.writeRaw(header1); err != nil {
					return 0, err
				}
				if _, err := c.writeRaw(handshakeBody[:splitLen]); err != nil {
					return splitLen, err
				}
				c.sleepWithJitter()
				
				// Record 2
				remLen := recLen - splitLen
				header2 := []byte{0x16, payload[1], payload[2], byte(remLen >> 8), byte(remLen & 0xff)}
				if _, err := c.writeRaw(header2); err != nil {
					return splitLen, err
				}
				if _, err := c.writeRaw(handshakeBody[splitLen:]); err != nil {
					return splitLen + remLen, err
				}
				
				// Remaining data in packet (if any)
				var remErr error
				if 5+recLen < len(payload) {
					_, remErr = c.writeRaw(payload[5+recLen:])
				}
				return len(payload), remErr
			}
		}
	}

	// Range-based fragmentation or simple split
	if c.minLength > 0 && c.maxLength >= c.minLength {
		idx := 0
		totalWritten := 0
		for idx < len(payload) {
			chunkSize := c.minLength + rand.Intn(c.maxLength-c.minLength+1)
			if chunkSize <= 0 {
				chunkSize = 2
			}
			if idx+chunkSize > len(payload) {
				chunkSize = len(payload) - idx
			}

			n, err := c.writeRaw(payload[idx : idx+chunkSize])
			totalWritten += n
			if err != nil {
				return totalWritten, err
			}
			idx += chunkSize
			if idx < len(payload) {
				c.sleepWithJitter()
			}
		}
		return totalWritten, nil
	}

	// Precision SNI multi-fragment splitting (from ZRLYN)
	if c.precisionSniSplits && len(payload) >= 5 && payload[0] == 0x16 && payload[1] == 0x03 {
		splits := SniSplits(payload)
		if len(splits) > 0 {
			written := 0
			prev := 0
			for _, s := range splits {
				if s > prev && s < len(payload) {
					nw, err := c.writeRaw(payload[prev:s])
					written += nw
					if err != nil {
						return written, err
					}
					prev = s
					c.sleepWithJitter()
				}
			}
			nw, err := c.writeRaw(payload[prev:])
			written += nw
			return written, err
		}
	}

	// Fallback to simple split logic
	splitAt := c.splitBytes
	if c.autoSni {
		if sniIdx := findEvasionSNIOffset(payload); sniIdx > 0 {
			if c.sniSplitOffset > 0 && sniIdx+9+c.sniSplitOffset < len(payload) {
				splitAt = sniIdx + 9 + c.sniSplitOffset
			} else {
				splitAt = sniIdx
			}
		}
	}

	if splitAt <= 0 || splitAt >= len(payload) {
		return c.writeRaw(payload)
	}

	n1, err := c.writeRaw(payload[:splitAt])
	if err != nil {
		return n1, err
	}
	c.sleepWithJitter()
	n2, err := c.writeRaw(payload[splitAt:])
	return n1 + n2, err
}

