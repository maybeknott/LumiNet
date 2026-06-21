package api

import (
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/proxy"
	"github.com/maybeknott/luminet/internal/system"
)

type EvasionTunnelStatusResponse struct {
	Running             bool   `json:"running"`
	Port                int    `json:"port"`
	SplitBytes          int    `json:"split_bytes"`
	DelayMs             int    `json:"delay_ms"`
	MutateHost          bool   `json:"mutate_host"`
	MutateHeaderSpace   bool   `json:"mutate_header_space"`
	AutoSni             bool   `json:"auto_sni"`
	PrecisionSniSplits  bool   `json:"precision_sni_splits"`
	SniSplitOffset      int    `json:"sni_split_offset"`
	Packets             string `json:"packets"`
	MinLength           int    `json:"min_length"`
	MaxLength           int    `json:"max_length"`
	TlsRecordSplit      bool   `json:"tls_record_split"`
	DnsResolver         string `json:"dns_resolver"`
	DnsForwarderPort    int    `json:"dns_forwarder_port"`
	DnsForwarderEnabled bool   `json:"dns_forwarder_enabled"`
	SystemProxyEnabled  bool   `json:"system_proxy_enabled"`
	SniSpoof            string `json:"sni_spoof"`
	ClientHelloPadding  int    `json:"client_hello_padding"`
	DelayJitter         bool   `json:"delay_jitter"`
	TcpWindowClamp      int    `json:"tcp_window_clamp"`
	CustomUserAgent     string `json:"custom_user_agent"`
	CovertMode          string `json:"covert_mode"`
	CovertServerlessUrl string `json:"covert_serverless_url"`
	CovertDnsDomain     string `json:"covert_dns_domain"`
	CovertGsaUrl        string `json:"covert_gsa_url"`
	CovertGsaKey        string `json:"covert_gsa_key"`
	CovertGdocsFolderId   string `json:"covert_gdocs_folder_id"`
	CovertGdocsAccessToken string `json:"covert_gdocs_access_token"`
	FakePacketInject    bool   `json:"fake_packet_inject"`
	FakePacketTtl       int    `json:"fake_packet_ttl"`
	MutateSniCase       bool   `json:"mutate_sni_case"`
	MutateMethod        bool   `json:"mutate_method"`
	MutateAbsoluteUri   bool   `json:"mutate_absolute_uri"`
	HttpPadding         int    `json:"http_padding"`
	PreflightSignature  string `json:"preflight_signature"`
	PreflightDelayMs    int    `json:"preflight_delay_ms"`
	SessionFrag         bool   `json:"session_frag"`
	SessionFragProb     float64 `json:"session_frag_prob"`
	SessionFragMinTotal int    `json:"session_frag_min_total"`
	SessionFragMaxTotal int    `json:"session_frag_max_total"`
	SessionFragMinChunk int    `json:"session_frag_min_chunk"`
	SessionFragMaxChunk int    `json:"session_frag_max_chunk"`
	SessionFragMinDelayMs int  `json:"session_frag_min_delay_ms"`
	SessionFragMaxDelayMs int  `json:"session_frag_max_delay_ms"`
	IpSpoofingEnabled     bool `json:"ip_spoofing_enabled"`
	IpSpoofingDecoyIP     string `json:"ip_spoofing_decoy_ip"`
	IpSpoofingDstReal     string `json:"ip_spoofing_dst_real"`
	OutOfWindowEnabled   bool   `json:"out_of_window_enabled"`
	OutOfWindowSeqOffset int    `json:"out_of_window_seq_offset"`
	DecoySniPool         string `json:"decoy_sni_pool"`
	OobEnabled           bool   `json:"oob_enabled"`
	OobexEnabled         bool   `json:"oobex_enabled"`

	// Mobile shielding settings
	CovertSocketProtectPath string `json:"covert_socket_protect_path"`
	MobileAssetsEnabled     bool   `json:"mobile_assets_enabled"`
	ZygiskHideEnabled       bool   `json:"zygisk_hide_enabled"`
	HardenedTlsEnabled      bool   `json:"hardened_tls_enabled"`

	// Session 6 Covert Transport settings
	WsEndpoint      string `json:"ws_endpoint"`
	WsHeaders       string `json:"ws_headers"`
	WsUseUtls       bool   `json:"ws_use_utls"`
	WsFingerprint   string `json:"ws_fingerprint"`
	WsPadding       bool   `json:"ws_padding"`
	WsTunnelType    int    `json:"ws_tunnel_type"`
	SshHost         string `json:"ssh_host"`
	SshUser         string `json:"ssh_user"`
	SshPass         string `json:"ssh_pass"`
	SshKey          string `json:"ssh_key"`
	KCPNoDelay      int    `json:"kcp_nodelay"`
	KCPInterval     int    `json:"kcp_interval"`
	KCPResend       int    `json:"kcp_resend"`
	KCPNoCongestion int    `json:"kcp_nocongestion"`
	KCPSendWindow   int    `json:"kcp_sndwnd"`
	KCPReceiveWindow int    `json:"kcp_rcvwnd"`
	KCPMTU          int    `json:"kcp_mtu"`
	TuicUuid            string  `json:"tuic_uuid"`
	TuicToken           string  `json:"tuic_token"`
	AsyncReactorEnabled bool    `json:"async_reactor_enabled"`
	LossRate            float64 `json:"loss_rate"`
	EmulatedLatency     int     `json:"emulated_latency"`
	EmulatedJitter      int     `json:"emulated_jitter"`
	CircularCacheCap    int     `json:"circular_cache_cap"`
	ShaperReadRate      int64   `json:"shaper_read_rate"`
	ShaperWriteRate     int64   `json:"shaper_write_rate"`

	UpgenObfuscationEnabled bool   `json:"upgen_obfuscation_enabled"`
	UpgenSeedHex            string `json:"upgen_seed_hex"`
	UpgenEntropyMatch       bool   `json:"upgen_entropy_match"`
	UpgenQuicExhaustionRate int    `json:"upgen_quic_exhaustion_rate"`
	SteganographyEnabled    bool   `json:"steganography_enabled"`
	SteganographyMode       string `json:"steganography_mode"`
	SteganographyDecoyImagePath string `json:"steganography_decoy_image_path"`
	SteganographyWebRTCSDPSpoof bool   `json:"steganography_webrtc_sdp_spoof"`
}

type SetEvasionTunnelRequest struct {
	Enabled             bool   `json:"enabled"`
	Port                int    `json:"port"`
	SplitBytes          int    `json:"split_bytes"`
	DelayMs             int    `json:"delay_ms"`
	MutateHost          bool   `json:"mutate_host"`
	MutateHeaderSpace   bool   `json:"mutate_header_space"`
	AutoSni             bool   `json:"auto_sni"`
	PrecisionSniSplits  bool   `json:"precision_sni_splits"`
	SniSplitOffset      int    `json:"sni_split_offset"`
	Packets             string `json:"packets"`
	MinLength           int    `json:"min_length"`
	MaxLength           int    `json:"max_length"`
	TlsRecordSplit      bool   `json:"tls_record_split"`
	DnsResolver         string `json:"dns_resolver"`
	DnsForwarderPort    int    `json:"dns_forwarder_port"`
	DnsForwarderEnabled bool   `json:"dns_forwarder_enabled"`
	SystemProxyEnabled  bool   `json:"system_proxy_enabled"`
	SniSpoof            string `json:"sni_spoof"`
	ClientHelloPadding  int    `json:"client_hello_padding"`
	DelayJitter         bool   `json:"delay_jitter"`
	TcpWindowClamp      int    `json:"tcp_window_clamp"`
	CustomUserAgent     string `json:"custom_user_agent"`
	CovertMode          string `json:"covert_mode"`
	CovertServerlessUrl string `json:"covert_serverless_url"`
	CovertDnsDomain     string `json:"covert_dns_domain"`
	CovertGsaUrl        string `json:"covert_gsa_url"`
	CovertGsaKey        string `json:"covert_gsa_key"`
	CovertGdocsFolderId   string `json:"covert_gdocs_folder_id"`
	CovertGdocsAccessToken string `json:"covert_gdocs_access_token"`
	FakePacketInject    bool   `json:"fake_packet_inject"`
	FakePacketTtl       int     `json:"fake_packet_ttl"`
	MutateSniCase       bool   `json:"mutate_sni_case"`
	MutateMethod        bool   `json:"mutate_method"`
	MutateAbsoluteUri   bool   `json:"mutate_absolute_uri"`
	HttpPadding         int    `json:"http_padding"`
	PreflightSignature  string `json:"preflight_signature"`
	PreflightDelayMs    int    `json:"preflight_delay_ms"`
	SessionFrag         bool   `json:"session_frag"`
	SessionFragProb     float64 `json:"session_frag_prob"`
	SessionFragMinTotal int    `json:"session_frag_min_total"`
	SessionFragMaxTotal int    `json:"session_frag_max_total"`
	SessionFragMinChunk int    `json:"session_frag_min_chunk"`
	SessionFragMaxChunk int    `json:"session_frag_max_chunk"`
	SessionFragMinDelayMs int  `json:"session_frag_min_delay_ms"`
	SessionFragMaxDelayMs int  `json:"session_frag_max_delay_ms"`
	IpSpoofingEnabled     bool `json:"ip_spoofing_enabled"`
	IpSpoofingDecoyIP     string `json:"ip_spoofing_decoy_ip"`
	IpSpoofingDstReal     string `json:"ip_spoofing_dst_real"`
	OutOfWindowEnabled   bool   `json:"out_of_window_enabled"`
	OutOfWindowSeqOffset int    `json:"out_of_window_seq_offset"`
	DecoySniPool         string `json:"decoy_sni_pool"`
	OobEnabled           bool   `json:"oob_enabled"`
	OobexEnabled         bool   `json:"oobex_enabled"`

	// Mobile shielding settings
	CovertSocketProtectPath string `json:"covert_socket_protect_path"`
	MobileAssetsEnabled     bool   `json:"mobile_assets_enabled"`
	ZygiskHideEnabled       bool   `json:"zygisk_hide_enabled"`
	HardenedTlsEnabled      bool   `json:"hardened_tls_enabled"`

	// Session 6 Covert Transport settings
	WsEndpoint      string `json:"ws_endpoint"`
	WsHeaders       string `json:"ws_headers"`
	WsUseUtls       bool   `json:"ws_use_utls"`
	WsFingerprint   string `json:"ws_fingerprint"`
	WsPadding       bool   `json:"ws_padding"`
	WsTunnelType    int    `json:"ws_tunnel_type"`
	SshHost         string `json:"ssh_host"`
	SshUser         string `json:"ssh_user"`
	SshPass         string `json:"ssh_pass"`
	SshKey          string `json:"ssh_key"`
	KCPNoDelay      int    `json:"kcp_nodelay"`
	KCPInterval     int    `json:"kcp_interval"`
	KCPResend       int    `json:"kcp_resend"`
	KCPNoCongestion int    `json:"kcp_nocongestion"`
	KCPSendWindow   int    `json:"kcp_sndwnd"`
	KCPReceiveWindow int    `json:"kcp_rcvwnd"`
	KCPMTU          int    `json:"kcp_mtu"`
	TuicUuid            string  `json:"tuic_uuid"`
	TuicToken           string  `json:"tuic_token"`
	AsyncReactorEnabled bool    `json:"async_reactor_enabled"`
	LossRate            float64 `json:"loss_rate"`
	EmulatedLatency     int     `json:"emulated_latency"`
	EmulatedJitter      int     `json:"emulated_jitter"`
	CircularCacheCap    int     `json:"circular_cache_cap"`
	ShaperReadRate      int64   `json:"shaper_read_rate"`
	ShaperWriteRate     int64   `json:"shaper_write_rate"`

	UpgenObfuscationEnabled bool   `json:"upgen_obfuscation_enabled"`
	UpgenSeedHex            string `json:"upgen_seed_hex"`
	UpgenEntropyMatch       bool   `json:"upgen_entropy_match"`
	UpgenQuicExhaustionRate int    `json:"upgen_quic_exhaustion_rate"`
	SteganographyEnabled    bool   `json:"steganography_enabled"`
	SteganographyMode       string `json:"steganography_mode"`
	SteganographyDecoyImagePath string `json:"steganography_decoy_image_path"`
	SteganographyWebRTCSDPSpoof bool   `json:"steganography_webrtc_sdp_spoof"`
}

// GetEvasionTunnelStatus handles GET /api/system/evasion-tunnel
func (s *Server) GetEvasionTunnelStatus(c *gin.Context) {
	mgr := proxy.GetEvasionManager()
	running, port, splitBytes, delayMs, mutateHost, mutateHeaderSpace, autoSni, sniSplitOffset, packets, minLen, maxLen, tlsRecSplit, dnsResolver, dnsFwdPort, dnsFwdEnabled, systemProxyEnabled, sniSpoof, clientHelloPadding, delayJitter, tcpWindowClamp, customUserAgent, covertMode, covertServerlessUrl, covertDnsDomain, covertGsaUrl, covertGsaKey, covertGdocsFolderId, covertGdocsAccessToken, fakePacketInject, fakePacketTtl, mutateSniCase, mutateMethod, mutateAbsoluteUri, httpPadding, preflightSignature, preflightDelayMs, sessionFrag, sessionFragProb, sessionFragMinTotal, sessionFragMaxTotal, sessionFragMinChunk, sessionFragMaxChunk, sessionFragMinDelayMs, sessionFragMaxDelayMs, ipSpoofingEnabled, ipSpoofingDecoyIP, ipSpoofingDstReal, outOfWindowEnabled, outOfWindowSeqOffset, decoySniPool, oobEnabled, oobexEnabled, asyncReactorEnabled, lossRate, emulatedLatency, emulatedJitter, circularCacheCap, shaperReadRate, shaperWriteRate, covertSocketProtectPath, mobileAssetsEnabled, zygiskHideEnabled, hardenedTlsEnabled, upgenEnabled, upgenSeedHex, upgenEntropyMatch, upgenQuicExhaustionRate, stegoEnabled, stegoMode, stegoDecoyImagePath, stegoWebRTCSDPSpoof := mgr.Status()

	covertCfg := mgr.GetCovertConfig()

	displayGsaKey := covertGsaKey
	if displayGsaKey != "" {
		displayGsaKey = "[REDACTED]"
	}
	displayGdocsToken := covertGdocsAccessToken
	if displayGdocsToken != "" {
		displayGdocsToken = "[REDACTED]"
	}
	displaySshPass := covertCfg.SshPass
	if displaySshPass != "" {
		displaySshPass = "[REDACTED]"
	}
	displaySshKey := covertCfg.SshKey
	if displaySshKey != "" {
		displaySshKey = "[REDACTED]"
	}
	displayTuicToken := covertCfg.TuicToken
	if displayTuicToken != "" {
		displayTuicToken = "[REDACTED]"
	}

	c.JSON(http.StatusOK, EvasionTunnelStatusResponse{
		Running:             running,
		Port:                port,
		SplitBytes:          splitBytes,
		DelayMs:             delayMs,
		MutateHost:          mutateHost,
		MutateHeaderSpace:   mutateHeaderSpace,
		AutoSni:             autoSni,
		PrecisionSniSplits:  mgr.GetPrecisionSniSplits(),
		SniSplitOffset:      sniSplitOffset,
		Packets:             packets,
		MinLength:           minLen,
		MaxLength:           maxLen,
		TlsRecordSplit:      tlsRecSplit,
		DnsResolver:         dnsResolver,
		DnsForwarderPort:    dnsFwdPort,
		DnsForwarderEnabled: dnsFwdEnabled,
		SystemProxyEnabled:  systemProxyEnabled,
		SniSpoof:            sniSpoof,
		ClientHelloPadding:  clientHelloPadding,
		DelayJitter:         delayJitter,
		TcpWindowClamp:      tcpWindowClamp,
		CustomUserAgent:     customUserAgent,
		CovertMode:          covertMode,
		CovertServerlessUrl: covertServerlessUrl,
		CovertDnsDomain:     covertDnsDomain,
		CovertGsaUrl:        covertGsaUrl,
		CovertGsaKey:        displayGsaKey,
		CovertGdocsFolderId:   covertGdocsFolderId,
		CovertGdocsAccessToken: displayGdocsToken,
		FakePacketInject:    fakePacketInject,
		FakePacketTtl:       fakePacketTtl,
		MutateSniCase:       mutateSniCase,
		MutateMethod:        mutateMethod,
		MutateAbsoluteUri:   mutateAbsoluteUri,
		HttpPadding:         httpPadding,
		PreflightSignature:  preflightSignature,
		PreflightDelayMs:    preflightDelayMs,
		SessionFrag:         sessionFrag,
		SessionFragProb:     sessionFragProb,
		SessionFragMinTotal: sessionFragMinTotal,
		SessionFragMaxTotal: sessionFragMaxTotal,
		SessionFragMinChunk: sessionFragMinChunk,
		SessionFragMaxChunk: sessionFragMaxChunk,
		SessionFragMinDelayMs: sessionFragMinDelayMs,
		SessionFragMaxDelayMs: sessionFragMaxDelayMs,
		IpSpoofingEnabled:     ipSpoofingEnabled,
		IpSpoofingDecoyIP:     ipSpoofingDecoyIP,
		IpSpoofingDstReal:     ipSpoofingDstReal,
		OutOfWindowEnabled:   outOfWindowEnabled,
		OutOfWindowSeqOffset: outOfWindowSeqOffset,
		DecoySniPool:         decoySniPool,
		OobEnabled:           oobEnabled,
		OobexEnabled:         oobexEnabled,
		CovertSocketProtectPath: covertSocketProtectPath,
		MobileAssetsEnabled:     mobileAssetsEnabled,
		ZygiskHideEnabled:       zygiskHideEnabled,
		HardenedTlsEnabled:      hardenedTlsEnabled,
		WsEndpoint:           covertCfg.WsEndpoint,
		WsHeaders:            covertCfg.WsHeaders,
		WsUseUtls:            covertCfg.WsUseUtls,
		WsFingerprint:        covertCfg.WsFingerprint,
		WsPadding:            covertCfg.WsPadding,
		WsTunnelType:         covertCfg.WsTunnelType,
		SshHost:              covertCfg.SshHost,
		SshUser:              covertCfg.SshUser,
		SshPass:              displaySshPass,
		SshKey:               displaySshKey,
		KCPNoDelay:           covertCfg.KcpNoDelay,
		KCPInterval:          covertCfg.KcpInterval,
		KCPResend:            covertCfg.KcpResend,
		KCPNoCongestion:      covertCfg.KcpNoCongestion,
		KCPSendWindow:        covertCfg.KcpSendWnd,
		KCPReceiveWindow:     covertCfg.KcpRecvWnd,
		KCPMTU:               covertCfg.KcpMtu,
		TuicUuid:             covertCfg.TuicUuid,
		TuicToken:            displayTuicToken,
		AsyncReactorEnabled:  asyncReactorEnabled,
		LossRate:            lossRate,
		EmulatedLatency:     emulatedLatency,
		EmulatedJitter:      emulatedJitter,
		CircularCacheCap:    circularCacheCap,
		ShaperReadRate:      shaperReadRate,
		ShaperWriteRate:     shaperWriteRate,
		UpgenObfuscationEnabled: upgenEnabled,
		UpgenSeedHex:            upgenSeedHex,
		UpgenEntropyMatch:       upgenEntropyMatch,
		UpgenQuicExhaustionRate: upgenQuicExhaustionRate,
		SteganographyEnabled:    stegoEnabled,
		SteganographyMode:       stegoMode,
		SteganographyDecoyImagePath: stegoDecoyImagePath,
		SteganographyWebRTCSDPSpoof: stegoWebRTCSDPSpoof,
	})
}

// SetEvasionTunnel handles POST /api/system/evasion-tunnel
func (s *Server) SetEvasionTunnel(c *gin.Context) {
	var req SetEvasionTunnelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	mgr := proxy.GetEvasionManager()

	mgr.SetPrecisionSniSplits(req.PrecisionSniSplits)
	
	// Setup WebSocket log forwarder on demand
	mgr.SetOnLog(func(msg string) {
		s.hub.BroadcastSystemEvent("evasion_log", msg)
	})

	if req.Enabled {
		if req.Port <= 0 || req.Port > 65535 {
			req.Port = proxy.DefaultEvasionPort
		}
		if req.SplitBytes < 0 {
			req.SplitBytes = proxy.DefaultEvasionSplitBytes
		}
		if req.DelayMs < 0 {
			req.DelayMs = proxy.DefaultEvasionDelayMs
		}
		if req.Packets == "" {
			req.Packets = proxy.DefaultEvasionPackets
		}
		if req.DnsForwarderPort <= 0 || req.DnsForwarderPort > 65535 {
			req.DnsForwarderPort = proxy.DefaultEvasionDnsForwarderPort
		}
		if req.CovertMode == "" {
			req.CovertMode = proxy.DefaultEvasionCovertMode
		}
		if req.FakePacketTtl <= 0 {
			req.FakePacketTtl = 4
		}
		if req.SessionFragProb <= 0 {
			req.SessionFragProb = proxy.DefaultEvasionSessionFragProb
		}
		if req.SessionFragMinTotal <= 0 {
			req.SessionFragMinTotal = proxy.DefaultEvasionSessionFragMinTotal
		}
		if req.SessionFragMaxTotal <= 0 {
			req.SessionFragMaxTotal = proxy.DefaultEvasionSessionFragMaxTotal
		}
		if req.SessionFragMinChunk <= 0 {
			req.SessionFragMinChunk = proxy.DefaultEvasionSessionFragMinChunk
		}
		if req.SessionFragMaxChunk <= 0 {
			req.SessionFragMaxChunk = proxy.DefaultEvasionSessionFragMaxChunk
		}
		if req.SessionFragMinDelayMs < 0 {
			req.SessionFragMinDelayMs = proxy.DefaultEvasionSessionFragMinDelayMs
		}
		if req.SessionFragMaxDelayMs < 0 {
			req.SessionFragMaxDelayMs = proxy.DefaultEvasionSessionFragMaxDelayMs
		}
		if (req.CircularCacheCap <= 0) {
			req.CircularCacheCap = 500
		}

		// Restore redacted keys/secrets
		currentCfg := mgr.GetCovertConfig()
		if req.SshPass == "[REDACTED]" {
			req.SshPass = currentCfg.SshPass
		}
		if req.SshKey == "[REDACTED]" {
			req.SshKey = currentCfg.SshKey
		}
		if req.TuicToken == "[REDACTED]" {
			req.TuicToken = currentCfg.TuicToken
		}
		if req.CovertGsaKey == "[REDACTED]" {
			req.CovertGsaKey = mgr.GetCovertGsaKey()
		}
		if req.CovertGdocsAccessToken == "[REDACTED]" {
			req.CovertGdocsAccessToken = mgr.GetCovertGdocsAccessToken()
		}

		mgr.SetCovertConfig(proxy.CovertTransportConfig{
			WsEndpoint:      req.WsEndpoint,
			WsHeaders:       req.WsHeaders,
			WsUseUtls:       req.WsUseUtls,
			WsFingerprint:   req.WsFingerprint,
			WsPadding:       req.WsPadding,
			WsTunnelType:    req.WsTunnelType,
			SshHost:         req.SshHost,
			SshUser:         req.SshUser,
			SshPass:         req.SshPass,
			SshKey:          req.SshKey,
			KcpNoDelay:      req.KCPNoDelay,
			KcpInterval:     req.KCPInterval,
			KcpResend:       req.KCPResend,
			KcpNoCongestion: req.KCPNoCongestion,
			KcpSendWnd:      req.KCPSendWindow,
			KcpRecvWnd:      req.KCPReceiveWindow,
			KcpMtu:          req.KCPMTU,
			TuicUuid:        req.TuicUuid,
			TuicToken:       req.TuicToken,
		})

		err := mgr.Start(req.Port, req.SplitBytes, req.DelayMs, req.MutateHost, req.MutateHeaderSpace, req.AutoSni, req.SniSplitOffset, req.Packets, req.MinLength, req.MaxLength, req.TlsRecordSplit, req.DnsResolver, req.DnsForwarderPort, req.DnsForwarderEnabled, req.SystemProxyEnabled, req.SniSpoof, req.ClientHelloPadding, req.DelayJitter, req.TcpWindowClamp, req.CustomUserAgent, req.CovertMode, req.CovertServerlessUrl, req.CovertDnsDomain, req.CovertGsaUrl, req.CovertGsaKey, req.CovertGdocsFolderId, req.CovertGdocsAccessToken, req.FakePacketInject, req.FakePacketTtl, req.MutateSniCase, req.MutateMethod, req.MutateAbsoluteUri, req.HttpPadding, req.PreflightSignature, req.PreflightDelayMs, req.SessionFrag, req.SessionFragProb, req.SessionFragMinTotal, req.SessionFragMaxTotal, req.SessionFragMinChunk, req.SessionFragMaxChunk, req.SessionFragMinDelayMs, req.SessionFragMaxDelayMs, req.IpSpoofingEnabled, req.IpSpoofingDecoyIP, req.IpSpoofingDstReal, req.OutOfWindowEnabled, req.OutOfWindowSeqOffset, req.DecoySniPool, req.OobEnabled, req.OobexEnabled, req.AsyncReactorEnabled, req.LossRate, req.EmulatedLatency, req.EmulatedJitter, req.CircularCacheCap, req.ShaperReadRate, req.ShaperWriteRate, req.CovertSocketProtectPath, req.MobileAssetsEnabled, req.ZygiskHideEnabled, req.HardenedTlsEnabled, req.UpgenObfuscationEnabled, req.UpgenSeedHex, req.UpgenEntropyMatch, req.UpgenQuicExhaustionRate, req.SteganographyEnabled, req.SteganographyMode, req.SteganographyDecoyImagePath, req.SteganographyWebRTCSDPSpoof)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	} else {
		mgr.Stop()
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "applied",
		"enabled": req.Enabled,
	})
}

// GetEvasionTunnelLogs handles GET /api/system/evasion-tunnel/logs
func (s *Server) GetEvasionTunnelLogs(c *gin.Context) {
	evasionMgr := proxy.GetEvasionManager()
	evasionLogs := evasionMgr.GetLogs()

	tunMgr := system.GetTunRouterManager()
	tunLogs := tunMgr.GetLogs()

	totalLen := len(evasionLogs) + len(tunLogs)
	mergedLogs := make([]string, 0, totalLen)
	mergedLogs = append(mergedLogs, evasionLogs...)
	mergedLogs = append(mergedLogs, tunLogs...)

	sort.SliceStable(mergedLogs, func(i, j int) bool {
		return mergedLogs[i] < mergedLogs[j]
	})

	if len(mergedLogs) > 200 {
		mergedLogs = mergedLogs[len(mergedLogs)-200:]
	}

	c.JSON(http.StatusOK, gin.H{
		"logs": mergedLogs,
	})
}
