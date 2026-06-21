package proxy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/crypto"
)

// dialWithEvasion establishes an outbound connection using configured covert tunnels or evasion strategies.
func (m *EvasionTunnelManager) dialWithEvasion(host string, port uint16, splitBytes int, delayMs int, mutateHost bool, mutateHeaderSpace bool, autoSni bool, sniSplitOffset int, packets string, minLen, maxLen int, tlsRecordSplit bool, dnsResolver string, sniSpoof string, clientHelloPadding int, delayJitter bool, tcpWindowClamp int, customUserAgent string) (net.Conn, error) {
	t0 := time.Now()

	m.mu.Lock()
	covertMode := m.covertMode
	covertServerlessUrl := m.covertServerlessUrl
	covertDnsDomain := m.covertDnsDomain
	covertGsaUrl := m.covertGsaUrl
	covertGsaKey := m.covertGsaKey
	covertGdocsFolderId := m.covertGdocsFolderId
	covertGdocsAccessToken := m.covertGdocsAccessToken
	fakePacketInject := m.fakePacketInject
	fakePacketTtl := m.fakePacketTtl
	mutateSniCase := m.mutateSniCase
	mutateMethod := m.mutateMethod
	mutateAbsoluteUri := m.mutateAbsoluteUri
	httpPadding := m.httpPadding
	preflightSignature := m.preflightSignature
	preflightDelayMs := m.preflightDelayMs
	sessionFrag := m.sessionFrag
	sessionFragProb := m.sessionFragProb
	sessionFragMinTotal := m.sessionFragMinTotal
	sessionFragMaxTotal := m.sessionFragMaxTotal
	sessionFragMinChunk := m.sessionFragMinChunk
	sessionFragMaxChunk := m.sessionFragMaxChunk
	sessionFragMinDelayMs := m.sessionFragMinDelayMs
	sessionFragMaxDelayMs := m.sessionFragMaxDelayMs
	ipSpoofingEnabled := m.ipSpoofingEnabled
	ipSpoofingDecoyIP := m.ipSpoofingDecoyIP
	ipSpoofingDstReal := m.ipSpoofingDstReal
	outOfWindowEnabled := m.outOfWindowEnabled
	outOfWindowSeqOffset := m.outOfWindowSeqOffset
	decoySniPool := m.decoySniPool
	oobEnabled := m.oobEnabled
	oobexEnabled := m.oobexEnabled
	lossRate := m.lossRate
	emulatedLatency := m.emulatedLatency
	emulatedJitter := m.emulatedJitter
	shaperReadRate := m.shaperReadRate
	shaperWriteRate := m.shaperWriteRate
	precisionSniSplits := m.precisionSniSplits
	m.mu.Unlock()

	var conn net.Conn
	var dialErr error

	switch covertMode {
	case "paqet":
		m.log("Routing connection to %s:%d over GFW Raw Handshake Bypass (paqet)", host, port)
		conn, dialErr = DialRawBypass(context.Background(), host, port)
	case "serverless":
		if covertServerlessUrl != "" {
			m.log("Routing connection to %s:%d over Serverless WebSocket Relay: %s", host, port, covertServerlessUrl)
			dialer := NewServerlessDialer(covertServerlessUrl)
			conn, dialErr = dialer.DialTarget(context.Background(), host, int(port))
		} else {
			dialErr = fmt.Errorf("covert serverless relay URL is empty")
		}
	case "edge":
		if covertServerlessUrl != "" {
			m.log("Routing connection to %s:%d over Edge Worker Relay: %s", host, port, covertServerlessUrl)
			cfg, err := ParseProxyURI(covertServerlessUrl)
			if err != nil {
				dialErr = fmt.Errorf("failed to parse edge proxy URI: %w", err)
			} else {
				dialer := NewEdgeDialer(cfg)
				conn, dialErr = dialer.DialTarget(context.Background(), host, int(port))
			}
		} else {
			dialErr = fmt.Errorf("covert serverless relay URL (used for edge proxy) is empty")
		}
	case "dnstunnel":
		if covertDnsDomain != "" {
			m.log("Routing connection to %s:%d over DNS Covert Tunnel: %s", host, port, covertDnsDomain)
			sessID := fmt.Sprintf("sess-%d", time.Now().UnixNano())
			transport := NewDnsTunnelTransport(covertDnsDomain, sessID)
			conn = transport.VirtualConnection()
		} else {
			dialErr = fmt.Errorf("covert DNS tunnel domain is empty")
		}
	case "gsa":
		if covertGsaUrl != "" {
			m.log("Routing connection to %s:%d over GSA Web App Relay: %s", host, port, covertGsaUrl)
			addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
			conn = NewGsaTunnelConn(covertGsaUrl, covertGsaKey, addr)
		} else {
			dialErr = fmt.Errorf("covert GSA relay URL is empty")
		}
	case "gdocs":
		if covertGdocsFolderId != "" {
			m.log("Routing connection to %s:%d over Google Docs Covert Channel: %s", host, port, covertGdocsFolderId)
			sessID := fmt.Sprintf("sess-%d", time.Now().UnixNano())
			transport := NewGDocsTransport(covertGdocsFolderId, covertGdocsAccessToken)
			conn = transport.VirtualConnection(sessID)
		} else {
			dialErr = fmt.Errorf("covert GDocs folder ID is empty")
		}
	case "gdrive":
		if covertGdocsFolderId != "" {
			m.log("Routing connection to %s:%d over Google Drive Covert Channel (Zephyr Mode): %s", host, port, covertGdocsFolderId)
			sessID := fmt.Sprintf("sess-%d", time.Now().UnixNano())
			transport := NewGDriveMailbox(covertGdocsFolderId, sessID)
			transport.AccessToken = covertGdocsAccessToken
			if transport.AccessToken != "" {
				transport.UseSimulator = false
			}
			conn = transport.VirtualConnection()
		} else {
			dialErr = fmt.Errorf("covert GDrive folder ID is empty")
		}
	case "wstunnel":
		m.mu.Lock()
		wsEnd := m.covertCfg.WsEndpoint
		wsHeadersStr := m.covertCfg.WsHeaders
		useUtls := m.covertCfg.WsUseUtls
		fingerprint := m.covertCfg.WsFingerprint
		extraPad := m.covertCfg.WsPadding
		tunnelType := m.covertCfg.WsTunnelType
		protectPath := m.covertSocketProtectPath
		m.mu.Unlock()

		if wsEnd != "" {
			m.log("Routing connection to %s:%d over WebTunnel: %s (Type: %d)", host, port, wsEnd, tunnelType)
			client := NewWsTunnelClient(wsEnd)
			client.UseUTLS = useUtls
			client.Fingerprint = fingerprint
			client.ExtraPadding = extraPad
			client.TunnelType = tunnelType
			if protectPath != "" {
				client.SocketProtect = func(fd int) {
					_ = protectViaUnixSocket(protectPath, fd)
				}
			}
			if wsHeadersStr != "" {
				for _, line := range strings.Split(wsHeadersStr, ",") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						client.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
					}
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, dialErr = client.EstablishTunnel(ctx)
		} else {
			dialErr = fmt.Errorf("wstunnel endpoint URL is empty")
		}
	case "ssh":
		m.mu.Lock()
		sshH := m.covertCfg.SshHost
		sshU := m.covertCfg.SshUser
		sshP := m.covertCfg.SshPass
		sshK := m.covertCfg.SshKey
		m.mu.Unlock()

		if sshH != "" {
			m.log("Routing connection to %s:%d over SSH Tunnel: %s", host, port, sshH)
			client := NewSshTunnelClient(sshH, sshU, sshP, sshK)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			targetAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
			conn, dialErr = client.DialTarget(ctx, targetAddr)
		} else {
			dialErr = fmt.Errorf("SSH tunnel host is empty")
		}
	case "kcp":
		m.mu.Lock()
		kcpH := m.covertCfg.SshHost
		pass := m.covertCfg.SshPass
		noDelay := m.covertCfg.KcpNoDelay
		interval := m.covertCfg.KcpInterval
		resend := m.covertCfg.KcpResend
		noCongest := m.covertCfg.KcpNoCongestion
		sndWnd := m.covertCfg.KcpSendWnd
		rcvWnd := m.covertCfg.KcpRecvWnd
		mtu := m.covertCfg.KcpMtu
		m.mu.Unlock()

		if kcpH != "" {
			m.log("Routing connection to %s:%d over KCP Transport to: %s", host, port, kcpH)
			kcpAddr, kcpPortStr, err := net.SplitHostPort(kcpH)
			var kcpPort int
			if err == nil {
				fmt.Sscanf(kcpPortStr, "%d", &kcpPort)
			} else {
				kcpAddr = kcpH
				kcpPort = 29900
			}
			cfg := &ProxyConfig{
				Protocol:         ProtocolKCP,
				Address:          kcpAddr,
				Port:             kcpPort,
				Password:         pass,
				Method:           "aes-128",
				KCPNoDelay:       noDelay,
				KCPInterval:      interval,
				KCPResend:        resend,
				KCPNoCongestion:  noCongest,
				KCPSendWindow:    sndWnd,
				KCPReceiveWindow: rcvWnd,
				KCPMTU:           mtu,
			}
			mgr := NewKcpTransportManager()
			conn, dialErr = mgr.Dial(cfg)
		} else {
			dialErr = fmt.Errorf("KCP server host is empty")
		}
	case "tuic":
		m.mu.Lock()
		sshH := m.covertCfg.SshHost
		uuidStr := m.covertCfg.TuicUuid
		tokenStr := m.covertCfg.TuicToken
		m.mu.Unlock()

		if sshH != "" {
			m.log("Routing connection to %s:%d over TUIC v5: %s", host, port, sshH)
			var d net.Dialer
			c, err := d.DialContext(context.Background(), "tcp", sshH)
			if err != nil {
				dialErr = err
			} else {
				var uuid [16]byte
				copy(uuid[:], []byte(uuidStr))
				var token [32]byte
				copy(token[:], []byte(tokenStr))
				session := NewTuicSession(c, uuid, token)
				dialErr = session.WriteAuthenticate()
				if dialErr == nil {
					dialErr = session.WriteConnect(TuicAddrTypeDomain, host, port)
					if dialErr == nil {
						conn = c
					}
				}
				if dialErr != nil {
					c.Close()
				}
			}
		} else {
			dialErr = fmt.Errorf("TUIC server address is empty")
		}
	default:
		resolvedIPs, err := resolveHostsSecurely(host, dnsResolver)
		if err != nil {
			m.log("DNS resolve failed for %s: %v. Falling back to direct dial.", host, err)
			resolvedIPs = []string{host}
		} else {
			m.log("Resolved %s -> %v securely via custom DNS", host, resolvedIPs)
		}

		for _, ip := range resolvedIPs {
			addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
			conn, dialErr = dialTimeoutProtected("tcp", addr, 3*time.Second)
			if dialErr == nil {
				break
			}
			m.log("Failed to connect to %s: %v. Trying next IP...", addr, dialErr)
		}
	}

	if dialErr != nil && conn == nil {
		return nil, dialErr
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok && tcpWindowClamp > 0 {
		_ = tcpConn.SetReadBuffer(tcpWindowClamp)
		_ = tcpConn.SetWriteBuffer(tcpWindowClamp)
		m.log("Clamped TCP read/write buffer sizes to %d bytes", tcpWindowClamp)
	}

	// Apply dynamic steganography or CFG obfuscation wrap if enabled
	m.mu.Lock()
	upgenEn := m.upgenEnabled
	upgenSeed := m.upgenSeedHex
	upgenEntropy := m.upgenEntropyMatch
	stegoEn := m.stegoEnabled
	stegoM := m.stegoMode
	stegoDecoy := m.stegoDecoyImagePath
	m.mu.Unlock()

	if upgenEn {
		mimic := "default"
		if upgenEntropy {
			if port == 443 {
				mimic = "https"
			} else if port == 53 {
				mimic = "dns"
			} else if port == 3478 {
				mimic = "stun"
			}
		}
		m.log("Wrapping connection in CFG Compiler dynamic layout obfuscation (mimic: %s)", mimic)
		conn = crypto.NewCFGConn(conn, []byte(upgenSeed), mimic)
	}

	if stegoEn {
		if stegoM == "webrtc_voip" {
			m.log("Wrapping connection in WebRTC steganographic VP8 camouflage")
			var secretToken []byte
			if stegoDecoy != "" {
				secretToken = DeriveSecretFromJoinLink(stegoDecoy)
			}
			if len(secretToken) == 0 {
				secretToken = []byte("default_webrtc_stego_secret")
			}
			stegoConn, err := NewWebRTCStegoConn(conn, secretToken)
			if err != nil {
				m.log("Failed to wrap connection in WebRTC Stego: %v", err)
			} else {
				conn = stegoConn
			}
		} else if stegoM == "pixel" {
			m.log("Wrapping connection in LSB pixel steganographic image camouflage (decoy: %s)", stegoDecoy)
			conn = NewPixelStegoConn(conn, stegoDecoy)
		}
	}

	if lossRate > 0 || emulatedLatency > 0 || emulatedJitter > 0 {
		m.log("Wrapping connection to %s:%d with LossyConn (loss: %.2f%%, latency: %dms, jitter: %dms)", host, port, lossRate*100.0, emulatedLatency, emulatedJitter)
		ratio := lossRate
		if ratio > 1.0 {
			ratio = ratio / 100.0
		}
		conn = NewLossyConn(conn, ratio, time.Duration(emulatedLatency)*time.Millisecond, time.Duration(emulatedJitter)*time.Millisecond)
	}

	if shaperReadRate > 0 || shaperWriteRate > 0 {
		m.log("Wrapping connection to %s:%d with ShapedConn (read: %d B/s, write: %d B/s)", host, port, shaperReadRate, shaperWriteRate)
		conn = NewShapedConn(conn, shaperReadRate, shaperWriteRate)
	}

	dialDuration := time.Since(t0)
	m.log("Established connection to %s:%d (RTT: %dms)", host, port, dialDuration.Milliseconds())

	return &evasionTunnelConn{
		Conn:                  conn,
		splitBytes:            splitBytes,
		delayMs:               delayMs,
		mutateHost:            mutateHost,
		mutateHeaderSpace:     mutateHeaderSpace,
		autoSni:               autoSni,
		precisionSniSplits:    precisionSniSplits,
		sniSplitOffset:        sniSplitOffset,
		packets:               packets,
		minLength:             minLen,
		maxLength:             maxLen,
		tlsRecordSplit:        tlsRecordSplit,
		sniSpoof:              sniSpoof,
		clientHelloPadding:    clientHelloPadding,
		delayJitter:           delayJitter,
		tcpWindowClamp:        tcpWindowClamp,
		customUserAgent:       customUserAgent,
		fakePacketInject:      fakePacketInject,
		fakePacketTtl:         fakePacketTtl,
		firstWrite:            true,
		mutateSniCase:         mutateSniCase,
		mutateMethod:          mutateMethod,
		mutateAbsoluteUri:     mutateAbsoluteUri,
		httpPadding:           httpPadding,
		preflightSignature:    preflightSignature,
		preflightDelayMs:      preflightDelayMs,
		sessionFrag:           sessionFrag,
		sessionFragProb:       sessionFragProb,
		sessionFragMinTotal:   sessionFragMinTotal,
		sessionFragMaxTotal:   sessionFragMaxTotal,
		sessionFragMinChunk:   sessionFragMinChunk,
		sessionFragMaxChunk:   sessionFragMaxChunk,
		sessionFragMinDelayMs: sessionFragMinDelayMs,
		sessionFragMaxDelayMs: sessionFragMaxDelayMs,
		ipSpoofingEnabled:     ipSpoofingEnabled,
		ipSpoofingDecoyIP:     ipSpoofingDecoyIP,
		ipSpoofingDstReal:     ipSpoofingDstReal,
		outOfWindowEnabled:    outOfWindowEnabled,
		outOfWindowSeqOffset:  outOfWindowSeqOffset,
		decoySniPool:          decoySniPool,
		oobEnabled:            oobEnabled,
		oobexEnabled:          oobexEnabled,
	}, nil
}
