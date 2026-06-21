package proxy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/maybeknott/luminet/internal/crypto"
	"github.com/maybeknott/luminet/internal/system"
)

type EvasionTunnelManager struct {
	mu                  sync.Mutex
	listener            net.Listener
	running             bool
	cancel              context.CancelFunc
	port                int
	splitBytes          int
	delayMs             int
	mutateHost          bool
	mutateHeaderSpace   bool
	autoSni             bool
	precisionSniSplits  bool // Precise multi-segment SNI splits from ZRLYN
	sniSplitOffset      int // Hostname-level split offset inside TLS ClientHello Server Name Indication
	packets             string
	minLength           int
	maxLength           int
	tlsRecordSplit      bool
	dnsResolver         string
	dnsForwarderPort    int
	dnsForwarderEnabled bool
	systemProxyEnabled  bool // Route all OS system traffic through this proxy via system settings
	sniSpoof            string // SNI spoofing target (optional)
	clientHelloPadding  int    // TLS ClientHello padding size in bytes (optional)
	delayJitter         bool
	tcpWindowClamp      int
	customUserAgent     string
	covertMode          string // Covert tunnel mode: "direct", "serverless", "dnstunnel", "gsa"
	covertServerlessUrl string // Covert serverless WebSocket URL
	covertDnsDomain     string // Covert DNS tunnel base domain
	covertGsaUrl        string // Covert GSA Web App URL
	covertGsaKey        string // Covert GSA Auth Key
	covertGdocsFolderId   string // Covert GDocs folder ID
	covertGdocsAccessToken string // Covert GDocs access token
	covertCfg              CovertTransportConfig // Session 6 client transport configurations
	fakePacketInject    bool
	fakePacketTtl       int
	onLog               func(string)
	logs                []string
	logMu               sync.RWMutex

	// New fields
	mutateSniCase       bool
	mutateMethod        bool
	mutateAbsoluteUri   bool
	httpPadding         int
	preflightSignature  string
	preflightDelayMs    int

	sessionFrag           bool
	sessionFragProb       float64
	sessionFragMinTotal   int
	sessionFragMaxTotal   int
	sessionFragMinChunk   int
	sessionFragMaxChunk   int
	sessionFragMinDelayMs int
	sessionFragMaxDelayMs int

	// IP Spoofing fields
	ipSpoofingEnabled bool
	ipSpoofingDecoyIP string
	ipSpoofingDstReal string

	// Out-of-Window & Decoy SNI Pool fields
	outOfWindowEnabled   bool
	outOfWindowSeqOffset int
	decoySniPool         string

	oobEnabled   bool
	oobexEnabled bool

	asyncReactorEnabled bool
	lossRate            float64
	emulatedLatency     int
	emulatedJitter      int
	circularCacheCap    int
	shaperReadRate      int64
	shaperWriteRate     int64

	reactor       *AsyncReactor
	circularCache *CircularCache

	packetInjector PacketInjector

	// Mobile shielding settings
	covertSocketProtectPath string
	mobileAssetsEnabled     bool
	zygiskHideEnabled       bool
	hardenedTlsEnabled      bool

	// Session 9 UPGen & Session 10 Steganography settings
	upgenEnabled            bool
	upgenSeedHex            string
	upgenEntropyMatch       bool
	upgenQuicExhaustionRate int
	stegoEnabled            bool
	stegoMode               string
	stegoDecoyImagePath     string
	stegoWebRTCSDPSpoof     bool
	hostsOverride           bool
}

const (
	DefaultEvasionPort                = 10888
	DefaultEvasionSplitBytes          = 2
	DefaultEvasionDelayMs             = 20
	DefaultEvasionMutateHost          = true
	DefaultEvasionMutateHeaderSpace   = false
	DefaultEvasionAutoSni             = true
	DefaultEvasionSniSplitOffset      = 0
	DefaultEvasionPackets             = "tlshello"
	DefaultEvasionMinLength           = 0
	DefaultEvasionMaxLength           = 0
	DefaultEvasionTlsRecordSplit      = true
	DefaultEvasionDnsResolver         = "https://dns.quad9.net/dns-query"
	DefaultEvasionDnsForwarderPort    = 10053
	DefaultEvasionDnsForwarderEnabled = true
	DefaultEvasionSystemProxyEnabled  = false
	DefaultEvasionSniSpoof            = ""
	DefaultEvasionClientHelloPadding  = 0
	DefaultEvasionDelayJitter          = false
	DefaultEvasionTcpWindowClamp       = 0
	DefaultEvasionCustomUserAgent      = ""
	DefaultEvasionCovertMode          = "direct"
	DefaultEvasionCovertServerlessURL = ""
	DefaultEvasionCovertDNSDomain     = ""
	DefaultEvasionCovertGsaURL        = ""
	DefaultEvasionCovertGsaKey        = ""
	DefaultEvasionCovertGdocsFolderId   = ""
	DefaultEvasionCovertGdocsAccessToken = ""
	DefaultEvasionFakePacketInject    = false
	DefaultEvasionFakePacketTtl       = 4
	DefaultEvasionPrecisionSniSplits  = true

	// New advanced evasion defaults
	DefaultEvasionMutateSniCase       = false
	DefaultEvasionMutateMethod        = false
	DefaultEvasionMutateAbsoluteUri   = false
	DefaultEvasionHttpPadding         = 0
	DefaultEvasionPreflightSignature  = ""
	DefaultEvasionPreflightDelayMs    = 0

	DefaultEvasionSessionFrag           = false
	DefaultEvasionSessionFragProb       = 1.0
	DefaultEvasionSessionFragMinTotal   = 5000
	DefaultEvasionSessionFragMaxTotal   = 10000
	DefaultEvasionSessionFragMinChunk   = 100
	DefaultEvasionSessionFragMaxChunk   = 1000
	DefaultEvasionSessionFragMinDelayMs = 10
	DefaultEvasionSessionFragMaxDelayMs = 100

	DefaultEvasionIpSpoofingEnabled   = false
	DefaultEvasionIpSpoofingDecoyIP   = ""
	DefaultEvasionIpSpoofingDstReal   = ""

	DefaultEvasionOutOfWindowEnabled   = false
	DefaultEvasionOutOfWindowSeqOffset = 0
	DefaultEvasionDecoySniPool         = ""

	DefaultEvasionOobEnabled   = false
	DefaultEvasionOobexEnabled = false

	DefaultEvasionAsyncReactorEnabled = false
	DefaultEvasionLossRate            = 0.0
	DefaultEvasionEmulatedLatency     = 0
	DefaultEvasionEmulatedJitter      = 0
	DefaultEvasionCircularCacheCap    = 500
	DefaultEvasionShaperReadRate      = int64(0)
	DefaultEvasionShaperWriteRate     = int64(0)

	DefaultEvasionCovertSocketProtectPath = ""
	DefaultEvasionMobileAssetsEnabled     = true
	DefaultEvasionZygiskHideEnabled       = false
	DefaultEvasionHardenedTlsEnabled      = true

	DefaultEvasionUpgenEnabled            = false
	DefaultEvasionUpgenSeedHex            = "4a7b9e02c1f8d4"
	DefaultEvasionUpgenEntropyMatch       = true
	DefaultEvasionUpgenQuicExhaustionRate = 50
	DefaultEvasionStegoEnabled            = false
	DefaultEvasionStegoMode               = "webrtc_voip"
	DefaultEvasionStegoDecoyImagePath     = "/var/lib/luminet/decoy.png"
	DefaultEvasionStegoWebRTCSDPSpoof     = true
)

var globalEvasionManager *EvasionTunnelManager
var globalEvasionOnce sync.Once

func GetEvasionManager() *EvasionTunnelManager {
	globalEvasionOnce.Do(func() {
		globalEvasionManager = &EvasionTunnelManager{
			port:                DefaultEvasionPort,
			splitBytes:          DefaultEvasionSplitBytes,
			delayMs:             DefaultEvasionDelayMs,
			mutateHost:          DefaultEvasionMutateHost,
			mutateHeaderSpace:   DefaultEvasionMutateHeaderSpace,
			autoSni:             DefaultEvasionAutoSni,
			precisionSniSplits:  DefaultEvasionPrecisionSniSplits,
			sniSplitOffset:      DefaultEvasionSniSplitOffset,
			packets:             DefaultEvasionPackets,
			minLength:           DefaultEvasionMinLength,
			maxLength:           DefaultEvasionMaxLength,
			tlsRecordSplit:      DefaultEvasionTlsRecordSplit,
			dnsResolver:         DefaultEvasionDnsResolver,
			dnsForwarderPort:    DefaultEvasionDnsForwarderPort,
			dnsForwarderEnabled: DefaultEvasionDnsForwarderEnabled,
			systemProxyEnabled:  DefaultEvasionSystemProxyEnabled,
			sniSpoof:            DefaultEvasionSniSpoof,
			clientHelloPadding:  DefaultEvasionClientHelloPadding,
			delayJitter:         DefaultEvasionDelayJitter,
			tcpWindowClamp:      DefaultEvasionTcpWindowClamp,
			customUserAgent:     DefaultEvasionCustomUserAgent,
			covertMode:          DefaultEvasionCovertMode,
			covertServerlessUrl: DefaultEvasionCovertServerlessURL,
			covertGsaUrl:        DefaultEvasionCovertGsaURL,
			covertGsaKey:        DefaultEvasionCovertGsaKey,
			covertGdocsFolderId:   DefaultEvasionCovertGdocsFolderId,
			covertGdocsAccessToken: DefaultEvasionCovertGdocsAccessToken,
			fakePacketInject:    DefaultEvasionFakePacketInject,
			fakePacketTtl:       DefaultEvasionFakePacketTtl,
			mutateSniCase:       DefaultEvasionMutateSniCase,
			mutateMethod:        DefaultEvasionMutateMethod,
			mutateAbsoluteUri:   DefaultEvasionMutateAbsoluteUri,
			httpPadding:         DefaultEvasionHttpPadding,
			preflightSignature:  DefaultEvasionPreflightSignature,
			preflightDelayMs:    DefaultEvasionPreflightDelayMs,
			sessionFrag:           DefaultEvasionSessionFrag,
			sessionFragProb:       DefaultEvasionSessionFragProb,
			sessionFragMinTotal:   DefaultEvasionSessionFragMinTotal,
			sessionFragMaxTotal:   DefaultEvasionSessionFragMaxTotal,
			sessionFragMinChunk:   DefaultEvasionSessionFragMinChunk,
			sessionFragMaxChunk:   DefaultEvasionSessionFragMaxChunk,
			sessionFragMinDelayMs: DefaultEvasionSessionFragMinDelayMs,
			sessionFragMaxDelayMs: DefaultEvasionSessionFragMaxDelayMs,
			ipSpoofingEnabled:     DefaultEvasionIpSpoofingEnabled,
			ipSpoofingDecoyIP:     DefaultEvasionIpSpoofingDecoyIP,
			ipSpoofingDstReal:     DefaultEvasionIpSpoofingDstReal,
			outOfWindowEnabled:    DefaultEvasionOutOfWindowEnabled,
			outOfWindowSeqOffset:  DefaultEvasionOutOfWindowSeqOffset,
			decoySniPool:          DefaultEvasionDecoySniPool,
			oobEnabled:            DefaultEvasionOobEnabled,
			oobexEnabled:          DefaultEvasionOobexEnabled,
			asyncReactorEnabled:   DefaultEvasionAsyncReactorEnabled,
			lossRate:              DefaultEvasionLossRate,
			emulatedLatency:       DefaultEvasionEmulatedLatency,
			emulatedJitter:        DefaultEvasionEmulatedJitter,
			circularCacheCap:      DefaultEvasionCircularCacheCap,
			shaperReadRate:        DefaultEvasionShaperReadRate,
			shaperWriteRate:       DefaultEvasionShaperWriteRate,
			covertSocketProtectPath: DefaultEvasionCovertSocketProtectPath,
			mobileAssetsEnabled:     DefaultEvasionMobileAssetsEnabled,
			zygiskHideEnabled:       DefaultEvasionZygiskHideEnabled,
			hardenedTlsEnabled:      DefaultEvasionHardenedTlsEnabled,

			upgenEnabled:            DefaultEvasionUpgenEnabled,
			upgenSeedHex:            DefaultEvasionUpgenSeedHex,
			upgenEntropyMatch:       DefaultEvasionUpgenEntropyMatch,
			upgenQuicExhaustionRate: DefaultEvasionUpgenQuicExhaustionRate,
			stegoEnabled:            DefaultEvasionStegoEnabled,
			stegoMode:               DefaultEvasionStegoMode,
			stegoDecoyImagePath:     DefaultEvasionStegoDecoyImagePath,
			stegoWebRTCSDPSpoof:     DefaultEvasionStegoWebRTCSDPSpoof,
			hostsOverride:           true,
		}
	})
	return globalEvasionManager
}

// ApplyBypassMode configures the evasion manager based on predefined stealth profiles (from UAC-SNI).
func (m *EvasionTunnelManager) ApplyBypassMode(mode string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch mode {
	case "Fast":
		m.splitBytes = 2
		m.delayMs = 10
		m.autoSni = true
		m.tlsRecordSplit = false
		m.delayJitter = false
		m.fakePacketInject = false
	case "Balanced":
		m.splitBytes = 5
		m.delayMs = 25
		m.autoSni = true
		m.tlsRecordSplit = true
		m.delayJitter = true
		m.fakePacketInject = false
	case "Stealth":
		m.splitBytes = 1
		m.delayMs = 40
		m.autoSni = true
		m.tlsRecordSplit = true
		m.delayJitter = true
		m.fakePacketInject = true
		m.fakePacketTtl = 4
		m.mutateSniCase = true
		m.sessionFrag = true
		m.sessionFragProb = 1.0
		m.sessionFragMinChunk = 50
		m.sessionFragMaxChunk = 200
		m.oobEnabled = true
	case "Custom":
		// Do nothing, respect user's explicit flags
	}
}

func (m *EvasionTunnelManager) Start(port int, splitBytes int, delayMs int, mutateHost bool, mutateHeaderSpace bool, autoSni bool, sniSplitOffset int, packets string, minLen, maxLen int, tlsRecordSplit bool, dnsResolver string, dnsForwarderPort int, dnsForwarderEnabled bool, systemProxyEnabled bool, sniSpoof string, clientHelloPadding int, delayJitter bool, tcpWindowClamp int, customUserAgent string, covertMode string, covertServerlessUrl string, covertDnsDomain string, covertGsaUrl string, covertGsaKey string, covertGdocsFolderId string, covertGdocsAccessToken string, fakePacketInject bool, fakePacketTtl int, mutateSniCase bool, mutateMethod bool, mutateAbsoluteUri bool, httpPadding int, preflightSignature string, preflightDelayMs int, sessionFrag bool, sessionFragProb float64, sessionFragMinTotal int, sessionFragMaxTotal int, sessionFragMinChunk int, sessionFragMaxChunk int, sessionFragMinDelayMs int, sessionFragMaxDelayMs int, ipSpoofingEnabled bool, ipSpoofingDecoyIP string, ipSpoofingDstReal string, outOfWindowEnabled bool, outOfWindowSeqOffset int, decoySniPool string, oobEnabled bool, oobexEnabled bool, asyncReactorEnabled bool, lossRate float64, emulatedLatency int, emulatedJitter int, circularCacheCap int, shaperReadRate int64, shaperWriteRate int64, covertSocketProtectPath string, mobileAssetsEnabled bool, zygiskHideEnabled bool, hardenedTlsEnabled bool, upgenEnabled bool, upgenSeedHex string, upgenEntropyMatch bool, upgenQuicExhaustionRate int, stegoEnabled bool, stegoMode string, stegoDecoyImagePath string, stegoWebRTCSDPSpoof bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		m.stopUnlocked()
	}

	addr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port))
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.listener = l
	m.running = true
	m.cancel = cancel
	m.port = l.Addr().(*net.TCPAddr).Port
	m.splitBytes = splitBytes
	m.delayMs = delayMs
	m.mutateHost = mutateHost
	m.mutateHeaderSpace = mutateHeaderSpace
	m.autoSni = autoSni
	m.sniSplitOffset = sniSplitOffset
	m.packets = packets
	m.minLength = minLen
	m.maxLength = maxLen
	m.tlsRecordSplit = tlsRecordSplit
	m.dnsResolver = GetSecureResolverURL(dnsResolver)
	m.dnsForwarderPort = dnsForwarderPort
	m.dnsForwarderEnabled = dnsForwarderEnabled
	m.systemProxyEnabled = systemProxyEnabled
	m.sniSpoof = sniSpoof
	m.clientHelloPadding = clientHelloPadding
	m.delayJitter = delayJitter
	m.tcpWindowClamp = tcpWindowClamp
	m.customUserAgent = customUserAgent
	m.covertMode = covertMode
	m.covertServerlessUrl = covertServerlessUrl
	m.covertDnsDomain = covertDnsDomain
	m.covertGsaUrl = covertGsaUrl
	m.covertGsaKey = covertGsaKey
	m.covertGdocsFolderId = covertGdocsFolderId
	m.covertGdocsAccessToken = covertGdocsAccessToken
	m.fakePacketInject = fakePacketInject
	m.fakePacketTtl = fakePacketTtl
	m.mutateSniCase = mutateSniCase
	m.mutateMethod = mutateMethod
	m.mutateAbsoluteUri = mutateAbsoluteUri
	m.httpPadding = httpPadding
	m.preflightSignature = preflightSignature
	m.preflightDelayMs = preflightDelayMs
	m.sessionFrag = sessionFrag
	m.sessionFragProb = sessionFragProb
	m.sessionFragMinTotal = sessionFragMinTotal
	m.sessionFragMaxTotal = sessionFragMaxTotal
	m.sessionFragMinChunk = sessionFragMinChunk
	m.sessionFragMaxChunk = sessionFragMaxChunk
	m.sessionFragMinDelayMs = sessionFragMinDelayMs
	m.sessionFragMaxDelayMs = sessionFragMaxDelayMs
	m.ipSpoofingEnabled = ipSpoofingEnabled
	m.ipSpoofingDecoyIP = ipSpoofingDecoyIP
	m.ipSpoofingDstReal = ipSpoofingDstReal
	m.outOfWindowEnabled = outOfWindowEnabled
	m.outOfWindowSeqOffset = outOfWindowSeqOffset
	m.decoySniPool = decoySniPool
	m.oobEnabled = oobEnabled
	m.oobexEnabled = oobexEnabled
	m.asyncReactorEnabled = asyncReactorEnabled
	m.lossRate = lossRate
	m.emulatedLatency = emulatedLatency
	m.emulatedJitter = emulatedJitter
	m.circularCacheCap = circularCacheCap
	m.shaperReadRate = shaperReadRate
	m.shaperWriteRate = shaperWriteRate
	m.covertSocketProtectPath = covertSocketProtectPath
	m.mobileAssetsEnabled = mobileAssetsEnabled
	m.zygiskHideEnabled = zygiskHideEnabled
	m.hardenedTlsEnabled = hardenedTlsEnabled

	m.upgenEnabled = upgenEnabled
	m.upgenSeedHex = upgenSeedHex
	m.upgenEntropyMatch = upgenEntropyMatch
	m.upgenQuicExhaustionRate = upgenQuicExhaustionRate
	m.stegoEnabled = stegoEnabled
	m.stegoMode = stegoMode
	m.stegoDecoyImagePath = stegoDecoyImagePath
	m.stegoWebRTCSDPSpoof = stegoWebRTCSDPSpoof

	if m.circularCache == nil || m.circularCacheCap != circularCacheCap {
		if circularCacheCap > 0 {
			m.circularCache = NewCircularCache(circularCacheCap)
		} else {
			m.circularCache = nil
		}
	}

	if asyncReactorEnabled {
		var err error
		m.reactor, err = NewAsyncReactor()
		if err != nil {
			m.log("Failed to start AsyncReactor: %v", err)
		} else {
			m.log("AsyncReactor started successfully.")
		}
	} else {
		if m.reactor != nil {
			_ = m.reactor.Close()
			m.reactor = nil
		}
	}

	m.ClearLogs()
	m.log("SOCKS5 Evasion Tunnel started on 127.0.0.1:%d (Packets: %s, Split: %d bytes, Range: %d-%d bytes, Delay: %dms, Host Mutation: %v, Header Space: %v, Auto SNI: %v, SNI Split Offset: %d, TLS Record Split: %v, DNS: %s, DNS Fwd Port: %d, DNS Fwd: %v, System Proxy: %v, SNI Spoof: %q, Padding: %d, Jitter: %v, Clamp: %d, UA: %q, CovertMode: %s, CovertURL: %q, CovertDomain: %q, CovertGsaURL: %q, CovertGsaKey: %q, CovertGdocsFolderId: %q, FakeInject: %v, FakeTTL: %d, SNICaseMut: %v, MethodMut: %v, AbsURI: %v, HttpPadding: %d, PreflightSig: %q, PreflightDelay: %d, SessionFrag: %v, SessionFragProb: %.2f, SessionFragMinTotal: %d, SessionFragMaxTotal: %d, SessionFragMinChunk: %d, SessionFragMaxChunk: %d, SessionFragMinDelayMs: %d, SessionFragMaxDelayMs: %d, IPSpoofing: %v, DecoyIP: %q, DstReal: %v, OutOfWindow: %v, OutOfWindowOffset: %d, DecoyPool: %q, OOB: %v, OOBEx: %v, AsyncReactor: %v, LossRate: %.2f%%, Latency: %dms, Jitter: %dms, CircularCacheCap: %d, ShaperReadRate: %d, ShaperWriteRate: %d, ProtectPath: %q, Assets: %v, Zygisk: %v, HardenedTLS: %v, UPGen: %v, Stego: %v)", port, packets, splitBytes, minLen, maxLen, delayMs, mutateHost, mutateHeaderSpace, autoSni, sniSplitOffset, tlsRecordSplit, m.dnsResolver, dnsForwarderPort, dnsForwarderEnabled, systemProxyEnabled, sniSpoof, clientHelloPadding, delayJitter, tcpWindowClamp, customUserAgent, covertMode, covertServerlessUrl, covertDnsDomain, covertGsaUrl, covertGsaKey, covertGdocsFolderId, fakePacketInject, fakePacketTtl, mutateSniCase, mutateMethod, mutateAbsoluteUri, httpPadding, preflightSignature, preflightDelayMs, sessionFrag, sessionFragProb, sessionFragMinTotal, sessionFragMaxTotal, sessionFragMinChunk, sessionFragMaxChunk, sessionFragMinDelayMs, sessionFragMaxDelayMs, ipSpoofingEnabled, ipSpoofingDecoyIP, ipSpoofingDstReal, outOfWindowEnabled, outOfWindowSeqOffset, decoySniPool, oobEnabled, oobexEnabled, asyncReactorEnabled, lossRate, emulatedLatency, emulatedJitter, circularCacheCap, shaperReadRate, shaperWriteRate, covertSocketProtectPath, mobileAssetsEnabled, zygiskHideEnabled, hardenedTlsEnabled, upgenEnabled, stegoEnabled)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					m.log("Accept error: %v", err)
					time.Sleep(100 * time.Millisecond)
					continue
				}
			}
			go m.handleSocksConnection(conn, m.splitBytes, m.delayMs, m.mutateHost, m.mutateHeaderSpace, m.autoSni, m.sniSplitOffset, m.packets, m.minLength, m.maxLength, m.tlsRecordSplit, m.dnsResolver, m.sniSpoof, m.clientHelloPadding, m.delayJitter, m.tcpWindowClamp, m.customUserAgent)
		}
	}()

	if dnsForwarderEnabled {
		go m.startDNSForwarder(dnsForwarderPort, dnsResolver, ctx)
	}

	if systemProxyEnabled {
		err := system.SetSystemProxy(context.Background(), &system.ProxySettings{
			Enabled: true,
			Server:  fmt.Sprintf("socks=127.0.0.1:%d", port),
			Bypass:  "<local>",
		})
		if err != nil {
			m.log("Failed to enable system-wide proxy settings: %v", err)
		} else {
			m.log("System-wide SOCKS5 proxy successfully configured pointing to 127.0.0.1:%d", port)
		}
	}

	if m.fakePacketInject {
		m.packetInjector = NewPacketInjector()
		if err := m.packetInjector.Start(ctx, m.port); err != nil {
			m.log("Failed to start packet injector: %v", err)
		} else {
			m.log("Packet injector started successfully capturing TCP SYN handshakes.")
		}
	}

	if m.upgenEnabled && m.upgenQuicExhaustionRate > 0 {
		targetHost := "1.1.1.1:443"
		if m.decoySniPool != "" {
			hosts := strings.Split(m.decoySniPool, ",")
			if len(hosts) > 0 && hosts[0] != "" {
				if !strings.Contains(hosts[0], ":") {
					targetHost = net.JoinHostPort(hosts[0], "443")
				} else {
					targetHost = hosts[0]
				}
			}
		}
		go func() {
			m.log("Starting background QUIC decryption queue exhaustion loop targeting %s at %d pps", targetHost, m.upgenQuicExhaustionRate)
			err := crypto.StartQUICExhaustionLoop(ctx, targetHost, m.upgenQuicExhaustionRate)
			if err != nil && err != context.Canceled {
				m.log("QUIC exhaustion loop error: %v", err)
			}
		}()
	}

	return nil
}

func (m *EvasionTunnelManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopUnlocked()
}

func (m *EvasionTunnelManager) stopUnlocked() {
	if m.running {
		m.running = false
		if m.systemProxyEnabled {
			err := system.DisableSystemProxy(context.Background())
			if err != nil {
				m.log("Failed to disable system-wide proxy settings: %v", err)
			} else {
				m.log("System-wide SOCKS5 proxy configuration disabled.")
			}
			m.systemProxyEnabled = false
		}
		if m.cancel != nil {
			m.cancel()
		}
		if m.listener != nil {
			_ = m.listener.Close()
		}
		if m.packetInjector != nil {
			_ = m.packetInjector.Stop()
			m.packetInjector = nil
		}
		if m.reactor != nil {
			_ = m.reactor.Close()
			m.reactor = nil
		}
		m.log("SOCKS5 Evasion Tunnel stopped.")
	}
}

func (m *EvasionTunnelManager) Status() (running bool, port int, splitBytes int, delayMs int, mutateHost bool, mutateHeaderSpace bool, autoSni bool, sniSplitOffset int, packets string, minLen, maxLen int, tlsRecordSplit bool, dnsResolver string, dnsForwarderPort int, dnsForwarderEnabled bool, systemProxyEnabled bool, sniSpoof string, clientHelloPadding int, delayJitter bool, tcpWindowClamp int, customUserAgent string, covertMode string, covertServerlessUrl string, covertDnsDomain string, covertGsaUrl string, covertGsaKey string, covertGdocsFolderId string, covertGdocsAccessToken string, fakePacketInject bool, fakePacketTtl int, mutateSniCase bool, mutateMethod bool, mutateAbsoluteUri bool, httpPadding int, preflightSignature string, preflightDelayMs int, sessionFrag bool, sessionFragProb float64, sessionFragMinTotal int, sessionFragMaxTotal int, sessionFragMinChunk int, sessionFragMaxChunk int, sessionFragMinDelayMs int, sessionFragMaxDelayMs int, ipSpoofingEnabled bool, ipSpoofingDecoyIP string, ipSpoofingDstReal string, outOfWindowEnabled bool, outOfWindowSeqOffset int, decoySniPool string, oobEnabled bool, oobexEnabled bool, asyncReactorEnabled bool, lossRate float64, emulatedLatency int, emulatedJitter int, circularCacheCap int, shaperReadRate int64, shaperWriteRate int64, covertSocketProtectPath string, mobileAssetsEnabled bool, zygiskHideEnabled bool, hardenedTlsEnabled bool, upgenEnabled bool, upgenSeedHex string, upgenEntropyMatch bool, upgenQuicExhaustionRate int, stegoEnabled bool, stegoMode string, stegoDecoyImagePath string, stegoWebRTCSDPSpoof bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running, m.port, m.splitBytes, m.delayMs, m.mutateHost, m.mutateHeaderSpace, m.autoSni, m.sniSplitOffset, m.packets, m.minLength, m.maxLength, m.tlsRecordSplit, m.dnsResolver, m.dnsForwarderPort, m.dnsForwarderEnabled, m.systemProxyEnabled, m.sniSpoof, m.clientHelloPadding, m.delayJitter, m.tcpWindowClamp, m.customUserAgent, m.covertMode, m.covertServerlessUrl, m.covertDnsDomain, m.covertGsaUrl, m.covertGsaKey, m.covertGdocsFolderId, m.covertGdocsAccessToken, m.fakePacketInject, m.fakePacketTtl, m.mutateSniCase, m.mutateMethod, m.mutateAbsoluteUri, m.httpPadding, m.preflightSignature, m.preflightDelayMs, m.sessionFrag, m.sessionFragProb, m.sessionFragMinTotal, m.sessionFragMaxTotal, m.sessionFragMinChunk, m.sessionFragMaxChunk, m.sessionFragMinDelayMs, m.sessionFragMaxDelayMs, m.ipSpoofingEnabled, m.ipSpoofingDecoyIP, m.ipSpoofingDstReal, m.outOfWindowEnabled, m.outOfWindowSeqOffset, m.decoySniPool, m.oobEnabled, m.oobexEnabled, m.asyncReactorEnabled, m.lossRate, m.emulatedLatency, m.emulatedJitter, m.circularCacheCap, m.shaperReadRate, m.shaperWriteRate, m.covertSocketProtectPath, m.mobileAssetsEnabled, m.zygiskHideEnabled, m.hardenedTlsEnabled, m.upgenEnabled, m.upgenSeedHex, m.upgenEntropyMatch, m.upgenQuicExhaustionRate, m.stegoEnabled, m.stegoMode, m.stegoDecoyImagePath, m.stegoWebRTCSDPSpoof
}

func (m *EvasionTunnelManager) GetLogs() []string {
	m.logMu.RLock()
	defer m.logMu.RUnlock()
	res := make([]string, len(m.logs))
	copy(res, m.logs)
	return res
}

func (m *EvasionTunnelManager) ClearLogs() {
	m.logMu.Lock()
	defer m.logMu.Unlock()
	m.logs = nil
}

func (m *EvasionTunnelManager) SetOnLog(f func(string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onLog = f
}

func (m *EvasionTunnelManager) log(format string, args ...interface{}) {
	msg := fmt.Sprintf("[%s] ", time.Now().Format("15:04:05")) + fmt.Sprintf(format, args...)
	m.logMu.Lock()
	m.logs = append(m.logs, msg)
	if len(m.logs) > 200 {
		m.logs = m.logs[1:]
	}
	onLog := m.onLog
	m.logMu.Unlock()
	if onLog != nil {
		onLog(msg)
	}
}

// CovertTransportConfig defines settings for Session 6 client transport layers.
type CovertTransportConfig struct {
	WsEndpoint      string `json:"ws_endpoint"`
	WsHeaders       string `json:"ws_headers"`
	WsUseUtls       bool   `json:"ws_use_utls"`
	WsFingerprint   string `json:"ws_fingerprint"`
	WsPadding       bool   `json:"ws_padding"`
	WsTunnelType    int    `json:"ws_tunnel_type"` // 1 = WSTunnel (WebSocket), 2 = Stunnel (TCP/TLS)

	SshHost         string `json:"ssh_host"`
	SshUser         string `json:"ssh_user"`
	SshPass         string `json:"ssh_pass"`
	SshKey          string `json:"ssh_key"`

	KcpNoDelay      int    `json:"kcp_nodelay"`
	KcpInterval     int    `json:"kcp_interval"`
	KcpResend       int    `json:"kcp_resend"`
	KcpNoCongestion int    `json:"kcp_nocongestion"`
	KcpSendWnd      int    `json:"kcp_sndwnd"`
	KcpRecvWnd      int    `json:"kcp_rcvwnd"`
	KcpMtu          int    `json:"kcp_mtu"`

	TuicUuid        string `json:"tuic_uuid"`
	TuicToken       string `json:"tuic_token"`
}

func (m *EvasionTunnelManager) SetCovertConfig(cfg CovertTransportConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.covertCfg = cfg
}

func (m *EvasionTunnelManager) GetCovertConfig() CovertTransportConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.covertCfg
}

func (m *EvasionTunnelManager) GetCovertGsaKey() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.covertGsaKey
}

func (m *EvasionTunnelManager) GetCovertGdocsAccessToken() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.covertGdocsAccessToken
}

func (m *EvasionTunnelManager) SetHostsOverride(val bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hostsOverride = val
}

func (m *EvasionTunnelManager) GetHostsOverride() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hostsOverride
}

func (m *EvasionTunnelManager) GetPrecisionSniSplits() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.precisionSniSplits
}

func (m *EvasionTunnelManager) SetPrecisionSniSplits(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.precisionSniSplits = v
}
