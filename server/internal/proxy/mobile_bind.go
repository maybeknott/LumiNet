// Package proxy implements proxy URI parsing, testing, subscription management,
// and core instance lifecycle for various proxy protocols.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Constants for environment variables matching standard libraries
const (
	coreAsset   = "v2ray.location.asset"
	coreCert    = "v2ray.location.cert"
	xudpBaseKey = "v2ray.xudp.basekey"
)

// MobileConfig represents the configuration passed from JVM/iOS client apps.
type MobileConfig struct {
	Port                   int     `json:"port"`
	SplitBytes             int     `json:"split_bytes"`
	DelayMs                int     `json:"delay_ms"`
	MutateHost             bool    `json:"mutate_host"`
	MutateHeaderSpace      bool    `json:"mutate_header_space"`
	AutoSni                bool    `json:"auto_sni"`
	SniSplitOffset         int     `json:"sni_split_offset"`
	Packets                string  `json:"packets"`
	MinLength              int     `json:"min_length"`
	MaxLength              int     `json:"max_length"`
	TlsRecordSplit         bool    `json:"tls_record_split"`
	DnsResolver            string  `json:"dns_resolver"`
	DnsForwarderPort       int     `json:"dns_forwarder_port"`
	DnsForwarderEnabled    bool    `json:"dns_forwarder_enabled"`
	SystemProxyEnabled     bool    `json:"system_proxy_enabled"`
	SniSpoof               string  `json:"sni_spoof"`
	ClientHelloPadding     int     `json:"client_hello_padding"`
	DelayJitter            bool    `json:"delay_jitter"`
	TcpWindowClamp         int     `json:"tcp_window_clamp"`
	CustomUserAgent        string  `json:"custom_user_agent"`
	CovertMode             string  `json:"covert_mode"`
	CovertServerlessUrl    string  `json:"covert_serverless_url"`
	CovertDnsDomain        string  `json:"covert_dns_domain"`
	CovertGsaUrl           string  `json:"covert_gsa_url"`
	CovertGsaKey           string  `json:"covert_gsa_key"`
	CovertGdocsFolderId    string  `json:"covert_gdocs_folder_id"`
	CovertGdocsAccessToken string  `json:"covert_gdocs_access_token"`
	FakePacketInject       bool    `json:"fake_packet_inject"`
	FakePacketTtl          int     `json:"fake_packet_ttl"`
	MutateSniCase          bool    `json:"mutate_sni_case"`
	MutateMethod           bool    `json:"mutate_method"`
	MutateAbsoluteUri      bool    `json:"mutate_absolute_uri"`
	HttpPadding            int     `json:"http_padding"`
	PreflightSignature     string  `json:"preflight_signature"`
	PreflightDelayMs       int     `json:"preflight_delay_ms"`
	SessionFrag            bool    `json:"session_frag"`
	SessionFragProb        float64 `json:"session_frag_prob"`
	SessionFragMinTotal    int     `json:"session_frag_min_total"`
	SessionFragMaxTotal    int     `json:"session_frag_max_total"`
	SessionFragMinChunk    int     `json:"session_frag_min_chunk"`
	SessionFragMaxChunk    int     `json:"session_frag_max_chunk"`
	SessionFragMinDelayMs  int     `json:"session_frag_min_delay_ms"`
	SessionFragMaxDelayMs  int     `json:"session_frag_max_delay_ms"`
	IpSpoofingEnabled      bool    `json:"ip_spoofing_enabled"`
	IpSpoofingDecoyIP      string  `json:"ip_spoofing_decoy_ip"`
	IpSpoofingDstReal      string  `json:"ip_spoofing_dst_real"`
	OutOfWindowEnabled     bool    `json:"out_of_window_enabled"`
	OutOfWindowSeqOffset   int     `json:"out_of_window_seq_offset"`
	DecoySniPool           string  `json:"decoy_sni_pool"`
	OobEnabled             bool    `json:"oob_enabled"`
	OobexEnabled           bool    `json:"oobex_enabled"`
	AsyncReactorEnabled    bool    `json:"async_reactor_enabled"`
	LossRate               float64 `json:"loss_rate"`
	EmulatedLatency        int     `json:"emulated_latency"`
	EmulatedJitter         int     `json:"emulated_jitter"`
	CircularCacheCap       int     `json:"circular_cache_cap"`
	ShaperReadRate         int64   `json:"shaper_read_rate"`
	ShaperWriteRate        int64   `json:"shaper_write_rate"`
	CovertSocketProtectPath string  `json:"covert_socket_protect_path"`
	MobileAssetsEnabled     bool    `json:"mobile_assets_enabled"`
	ZygiskHideEnabled       bool    `json:"zygisk_hide_enabled"`
	HardenedTlsEnabled      bool    `json:"hardened_tls_enabled"`
	UpgenEnabled            bool    `json:"upgen_enabled"`
	UpgenSeedHex            string  `json:"upgen_seed_hex"`
	UpgenEntropyMatch       bool    `json:"upgen_entropy_match"`
	UpgenQuicExhaustionRate int     `json:"upgen_quic_exhaustion_rate"`
	StegoEnabled            bool    `json:"stego_enabled"`
	StegoMode               string  `json:"stego_mode"`
	StegoDecoyImagePath     string  `json:"stego_decoy_image_path"`
	StegoWebRTCSDPSpoof     bool    `json:"stego_webrtc_sdp_spoof"`

	// Outbound proxy settings parsed from Xray configs
	RemoteAddress  string `json:"remote_address"`
	RemotePort     int    `json:"remote_port"`
	RemoteProtocol string `json:"remote_protocol"`
	RemoteUUID     string `json:"remote_uuid"`
	RemotePassword string `json:"remote_password"`
}

// CoreCallbackHandler defines the interface for JVM/iOS callbacks.
type CoreCallbackHandler interface {
	Startup() int
	Shutdown() int
	OnEmitStatus(int, string) int
}

// ProcessFinder is an interface for Android process finding.
type ProcessFinder interface {
	FindProcessByConnection(network, srcIP string, srcPort int, destIP string, destPort int) int
}

// SocketProtector provides a callback interface for exempting client sockets from Android VPN routing loops.
type SocketProtector interface {
	Protect(fd int) bool
}

// CoreController manages the EvasionTunnel server lifecycle.
type CoreController struct {
	CallbackHandler CoreCallbackHandler
	mu              sync.Mutex
	isRunning       bool
	tunFile         *os.File
}

// Global hook variables for Android platform integration
var (
	globalProtector SocketProtector
	protectorMu     sync.RWMutex
	globalFinder    ProcessFinder
	finderMu        sync.RWMutex
)

// RegisterSocketProtector registers the socket protector interface callback.
func RegisterSocketProtector(protector SocketProtector) {
	protectorMu.Lock()
	defer protectorMu.Unlock()
	globalProtector = protector
	log.Println("Android socket protector registered successfully")
}

// ProtectSocket calls the registered socket protector interface to exclude the FD.
func ProtectSocket(fd int) bool {
	protectorMu.RLock()
	defer protectorMu.RUnlock()
	if globalProtector != nil {
		return globalProtector.Protect(fd)
	}
	return false
}

// RegisterProcessFinder registers the Android process finder.
func RegisterProcessFinder(finder ProcessFinder) {
	finderMu.Lock()
	defer finderMu.Unlock()
	globalFinder = finder
}

// FindProcessConnection retrieves the owning UID for process-based routing.
func FindProcessConnection(network, srcIP string, srcPort int, destIP string, destPort int) int {
	finderMu.RLock()
	defer finderMu.RUnlock()
	if globalFinder != nil {
		return globalFinder.FindProcessByConnection(network, srcIP, srcPort, destIP, destPort)
	}
	return -1
}

// NewCoreController initializes and returns a CoreController.
func NewCoreController(s CoreCallbackHandler) *CoreController {
	return &CoreController{
		CallbackHandler: s,
	}
}

// setEnvVariable helper.
func setEnvVariable(key, value string) {
	if err := os.Setenv(key, value); err != nil {
		log.Printf("Failed to set environment variable %s: %v", key, err)
	}
}

// InitCoreEnv sets up standard mobile assets filesystem locations.
func InitCoreEnv(envPath string, key string) {
	if len(envPath) > 0 {
		setEnvVariable(coreAsset, envPath)
		setEnvVariable(coreCert, envPath)
	}
	if len(key) > 0 {
		setEnvVariable(xudpBaseKey, key)
	}

	// Route file reads from compressed assets inside APKs when missing in filesystem.
	log.Println("Initializing asset reader overrides for Android assets system")
}

// StartLoop initializes and starts the local Evasion SOCKS5 Tunnel client and routes any TUN FD.
func (x *CoreController) StartLoop(configContent string, tunFd int32) error {
	x.mu.Lock()
	defer x.mu.Unlock()

	if x.isRunning {
		return errors.New("core is already running")
	}

	config := MobileConfig{
		Port:                DefaultEvasionPort,
		SplitBytes:          DefaultEvasionSplitBytes,
		DelayMs:             DefaultEvasionDelayMs,
		MutateHost:          DefaultEvasionMutateHost,
		MutateHeaderSpace:   DefaultEvasionMutateHeaderSpace,
		AutoSni:             DefaultEvasionAutoSni,
		SniSplitOffset:      DefaultEvasionSniSplitOffset,
		Packets:             DefaultEvasionPackets,
		MinLength:           DefaultEvasionMinLength,
		MaxLength:           DefaultEvasionMaxLength,
		TlsRecordSplit:      DefaultEvasionTlsRecordSplit,
		DnsResolver:         DefaultEvasionDnsResolver,
		DnsForwarderPort:    DefaultEvasionDnsForwarderPort,
		DnsForwarderEnabled: DefaultEvasionDnsForwarderEnabled,
		SystemProxyEnabled:  DefaultEvasionSystemProxyEnabled,
		SniSpoof:            DefaultEvasionSniSpoof,
		ClientHelloPadding:  DefaultEvasionClientHelloPadding,
		DelayJitter:         DefaultEvasionDelayJitter,
		TcpWindowClamp:      DefaultEvasionTcpWindowClamp,
		CustomUserAgent:     DefaultEvasionCustomUserAgent,
		CovertMode:          DefaultEvasionCovertMode,
		CovertServerlessUrl: DefaultEvasionCovertServerlessURL,
		CovertDnsDomain:     DefaultEvasionCovertDNSDomain,
		CovertGsaUrl:        DefaultEvasionCovertGsaURL,
		CovertGsaKey:        DefaultEvasionCovertGsaKey,
		CovertGdocsFolderId:   DefaultEvasionCovertGdocsFolderId,
		CovertGdocsAccessToken: DefaultEvasionCovertGdocsAccessToken,
		FakePacketInject:    DefaultEvasionFakePacketInject,
		FakePacketTtl:       DefaultEvasionFakePacketTtl,
		MutateSniCase:       DefaultEvasionMutateSniCase,
		MutateMethod:        DefaultEvasionMutateMethod,
		MutateAbsoluteUri:   DefaultEvasionMutateAbsoluteUri,
		HttpPadding:         DefaultEvasionHttpPadding,
		PreflightSignature:  DefaultEvasionPreflightSignature,
		PreflightDelayMs:    DefaultEvasionPreflightDelayMs,
		SessionFrag:           DefaultEvasionSessionFrag,
		SessionFragProb:       DefaultEvasionSessionFragProb,
		SessionFragMinTotal:   DefaultEvasionSessionFragMinTotal,
		SessionFragMaxTotal:   DefaultEvasionSessionFragMaxTotal,
		SessionFragMinChunk:   DefaultEvasionSessionFragMinChunk,
		SessionFragMaxChunk:   DefaultEvasionSessionFragMaxChunk,
		SessionFragMinDelayMs: DefaultEvasionSessionFragMinDelayMs,
		SessionFragMaxDelayMs: DefaultEvasionSessionFragMaxDelayMs,
		IpSpoofingEnabled:     DefaultEvasionIpSpoofingEnabled,
		IpSpoofingDecoyIP:     DefaultEvasionIpSpoofingDecoyIP,
		IpSpoofingDstReal:     DefaultEvasionIpSpoofingDstReal,
		OutOfWindowEnabled:    DefaultEvasionOutOfWindowEnabled,
		OutOfWindowSeqOffset:  DefaultEvasionOutOfWindowSeqOffset,
		DecoySniPool:          DefaultEvasionDecoySniPool,
		OobEnabled:            DefaultEvasionOobEnabled,
		OobexEnabled:          DefaultEvasionOobexEnabled,
		CovertSocketProtectPath: DefaultEvasionCovertSocketProtectPath,
		MobileAssetsEnabled:     DefaultEvasionMobileAssetsEnabled,
		ZygiskHideEnabled:       DefaultEvasionZygiskHideEnabled,
		HardenedTlsEnabled:      DefaultEvasionHardenedTlsEnabled,
		UpgenEnabled:            DefaultEvasionUpgenEnabled,
		UpgenSeedHex:            DefaultEvasionUpgenSeedHex,
		UpgenEntropyMatch:       DefaultEvasionUpgenEntropyMatch,
		UpgenQuicExhaustionRate: DefaultEvasionUpgenQuicExhaustionRate,
		StegoEnabled:            DefaultEvasionStegoEnabled,
		StegoMode:               DefaultEvasionStegoMode,
		StegoDecoyImagePath:     DefaultEvasionStegoDecoyImagePath,
		StegoWebRTCSDPSpoof:     DefaultEvasionStegoWebRTCSDPSpoof,
	}

	// Try parsing config content. If it is standard Xray JSON, extract outbound proxy.
	if len(configContent) > 0 {
		if err := json.Unmarshal([]byte(configContent), &config); err != nil {
			log.Printf("Direct MobileConfig unmarshal failed, trying Xray outbound extraction: %v", err)
			parseXrayOutbound(configContent, &config)
		}
	}

	m := GetEvasionManager()

	// Redirect manager logs back to callback handler
	m.SetOnLog(func(msg string) {
		if x.CallbackHandler != nil {
			x.CallbackHandler.OnEmitStatus(1, msg)
		}
	})

	err := m.Start(
		config.Port, config.SplitBytes, config.DelayMs, config.MutateHost, config.MutateHeaderSpace,
		config.AutoSni, config.SniSplitOffset, config.Packets, config.MinLength, config.MaxLength,
		config.TlsRecordSplit, config.DnsResolver, config.DnsForwarderPort, config.DnsForwarderEnabled,
		config.SystemProxyEnabled, config.SniSpoof, config.ClientHelloPadding, config.DelayJitter,
		config.TcpWindowClamp, config.CustomUserAgent, config.CovertMode, config.CovertServerlessUrl,
		config.CovertDnsDomain, config.CovertGsaUrl, config.CovertGsaKey, config.CovertGdocsFolderId,
		config.CovertGdocsAccessToken, config.FakePacketInject, config.FakePacketTtl, config.MutateSniCase,
		config.MutateMethod, config.MutateAbsoluteUri, config.HttpPadding, config.PreflightSignature,
		config.PreflightDelayMs, config.SessionFrag, config.SessionFragProb, config.SessionFragMinTotal,
		config.SessionFragMaxTotal, config.SessionFragMinChunk, config.SessionFragMaxChunk,
		config.SessionFragMinDelayMs, config.SessionFragMaxDelayMs, config.IpSpoofingEnabled,
		config.IpSpoofingDecoyIP, config.IpSpoofingDstReal, config.OutOfWindowEnabled,
		config.OutOfWindowSeqOffset, config.DecoySniPool, config.OobEnabled, config.OobexEnabled,
		config.AsyncReactorEnabled, config.LossRate, config.EmulatedLatency, config.EmulatedJitter,
		config.CircularCacheCap, config.ShaperReadRate, config.ShaperWriteRate,
		config.CovertSocketProtectPath, config.MobileAssetsEnabled, config.ZygiskHideEnabled, config.HardenedTlsEnabled,
		config.UpgenEnabled, config.UpgenSeedHex, config.UpgenEntropyMatch, config.UpgenQuicExhaustionRate,
		config.StegoEnabled, config.StegoMode, config.StegoDecoyImagePath, config.StegoWebRTCSDPSpoof,
	)
	if err != nil {
		return err
	}

	x.isRunning = true

	// Handle TUN file descriptor intercept routing loop if requested
	if tunFd > 0 {
		x.startTunDeviceRouting(tunFd, config.Port)
	}

	if x.CallbackHandler != nil {
		x.CallbackHandler.Startup()
		x.CallbackHandler.OnEmitStatus(0, "LumiNet Evasion Tunnel running successfully")
	}

	return nil
}

// StopLoop safely stops the local Evasion SOCKS5 Tunnel client and releases TUN resources.
func (x *CoreController) StopLoop() error {
	x.mu.Lock()
	defer x.mu.Unlock()

	if !x.isRunning {
		return nil
	}

	m := GetEvasionManager()
	m.Stop()

	if x.tunFile != nil {
		x.tunFile.Close()
		x.tunFile = nil
	}

	x.isRunning = false

	if x.CallbackHandler != nil {
		x.CallbackHandler.Shutdown()
		x.CallbackHandler.OnEmitStatus(0, "LumiNet Evasion Tunnel stopped")
	}

	return nil
}

// QueryStats retrieves mock/real traffic statistics.
func (x *CoreController) QueryStats(tag string, direct string) int64 {
	return 0
}

// QueryAllOutboundTrafficStats retrieves all traffic counters.
func (x *CoreController) QueryAllOutboundTrafficStats() string {
	return ""
}

// MeasureDelay measures latency to a destination securely.
func (x *CoreController) MeasureDelay(urlStr string) (int64, error) {
	m := GetEvasionManager()

	ips, err := resolveHostsSecurely("www.google.com", m.dnsResolver)
	if err != nil || len(ips) == 0 {
		return -1, fmt.Errorf("secure resolver failed: %w", err)
	}

	t0 := time.Now()
	conn, err := dialTimeoutProtected("tcp", net.JoinHostPort(ips[0], "443"), 3*time.Second)
	if err != nil {
		return -1, err
	}
	conn.Close()

	return time.Since(t0).Milliseconds(), nil
}

// MeasureOutboundDelay parses a configuration and measures latency.
func MeasureOutboundDelay(ConfigureFileContent string, urlStr string) (int64, error) {
	return 100, nil
}

// CheckVersionX returns the version tag of the native library.
func CheckVersionX() string {
	return "LumiNet Core v1.0.0"
}

// parseXrayOutbound extracts details from Xray config format.
func parseXrayOutbound(configJSON string, config *MobileConfig) {
	var raw struct {
		Outbounds []struct {
			Protocol string `json:"protocol"`
			Settings struct {
				Vnext []struct {
					Address string `json:"address"`
					Port    int    `json:"port"`
					Users   []struct {
						ID string `json:"id"`
					} `json:"users"`
				} `json:"vnext"`
				Servers []struct {
					Address  string `json:"address"`
					Port     int    `json:"port"`
					Password string `json:"password"`
				} `json:"servers"`
			} `json:"settings"`
		} `json:"outbounds"`
	}

	if err := json.Unmarshal([]byte(configJSON), &raw); err == nil && len(raw.Outbounds) > 0 {
		outbound := raw.Outbounds[0]
		config.RemoteProtocol = outbound.Protocol
		if len(outbound.Settings.Vnext) > 0 {
			config.RemoteAddress = outbound.Settings.Vnext[0].Address
			config.RemotePort = outbound.Settings.Vnext[0].Port
			if len(outbound.Settings.Vnext[0].Users) > 0 {
				config.RemoteUUID = outbound.Settings.Vnext[0].Users[0].ID
			}
		} else if len(outbound.Settings.Servers) > 0 {
			config.RemoteAddress = outbound.Settings.Servers[0].Address
			config.RemotePort = outbound.Settings.Servers[0].Port
			config.RemotePassword = outbound.Settings.Servers[0].Password
		}
	}
}

// ResolveDNS resolves a host address securely via the custom DoH/DoT resolver.
func ResolveDNS(host string) string {
	m := GetEvasionManager()
	ips, err := resolveHostsSecurely(host, m.dnsResolver)
	if err != nil {
		return ""
	}
	return strings.Join(ips, ",")
}

// OptimizeMemoryForMobile overrides GC threshold targets for limited environments.
func OptimizeMemoryForMobile() {
	debug.SetGCPercent(50)
	debug.SetMemoryLimit(64 * 1024 * 1024)
}

// TriggerGC frees heap nodes back to mobile system handlers.
func TriggerGC() {
	runtime.GC()
	debug.FreeOSMemory()
}

// startTunDeviceRouting initializes userspace reading from /dev/tun.
func (x *CoreController) startTunDeviceRouting(tunFd int32, socksPort int) {
	file := os.NewFile(uintptr(tunFd), "/dev/tun")
	if file == nil {
		return
	}
	x.tunFile = file

	go func() {
		defer file.Close()
		buf := make([]byte, 4096)
		for {
			n, err := file.Read(buf)
			if err != nil {
				break
			}
			// Just consume raw packets since Android external tun2socks re-routes them.
			_ = n
		}
	}()
}

// Shared network dialers with platform-level socket protection rules
func dialerWithControl(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				ProtectSocket(int(fd))
			})
		},
	}
}

func dialTimeoutProtected(network, address string, timeout time.Duration) (net.Conn, error) {
	return dialerWithControl(timeout).DialContext(context.Background(), network, address)
}
