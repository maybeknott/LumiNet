//go:build windows && cgo

package cmd

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	. "github.com/lxn/walk/declarative"
)
func (s *nativeShell) bypassTunnelPage() TabPage {
	return TabPage{
		Title:  "Bypass Tunnel",
		Layout: VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			GroupBox{
				Title:  "Local Evasion SOCKS5 Proxy Client Settings",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Strategy Preset Profile:"},
					ComboBox{
						AssignTo: &s.tunnelPresetCombo,
						Model: []string{
							"Custom (Manual Config)",
							"Default Bypass Preset",
							"Hardened Firewall Preset",
							"Minimal Latency Preset",
							"Strict SNI Obfuscation Preset",
						},
						OnCurrentIndexChanged: s.onTunnelPresetChanged,
					},
					Label{Text: ""},
					Label{Text: ""},

					Label{Text: "SOCKS5 Local Port:"},
					LineEdit{AssignTo: &s.tunnelPortEdit},
					Label{Text: "TCP Split Offset (Bytes):"},
					LineEdit{AssignTo: &s.tunnelSplitBytesEdit},

					Label{Text: "TCP Split Delay (ms):"},
					LineEdit{AssignTo: &s.tunnelDelayEdit},
					Label{Text: "Mutate HTTP Host Header:"},
					CheckBox{AssignTo: &s.tunnelHostCheck, Text: "Enable (Host: -> hOsT:)"},

					Label{Text: "Auto-Split TLS SNI:"},
					CheckBox{AssignTo: &s.tunnelAutoSniCheck, Text: "Enable (Split at TLS SNI boundaries)"},
					Label{Text: "Target Packets Mode:"},
					ComboBox{AssignTo: &s.tunnelPacketsCombo, Model: []string{"TLS ClientHello only", "All traffic"}},

					Label{Text: "Min Fragment Size (Bytes):"},
					LineEdit{AssignTo: &s.tunnelMinLenEdit},
					Label{Text: "Max Fragment Size (Bytes):"},
					LineEdit{AssignTo: &s.tunnelMaxLenEdit},

					Label{Text: "Secure DNS Resolver:"},
					LineEdit{AssignTo: &s.tunnelDnsResolverEdit},
					Label{Text: "Enable DNS Forwarder:"},
					CheckBox{AssignTo: &s.tunnelDnsForwarderCheck, Text: "Plain UDP to Secure DNS"},

					Label{Text: "DNS Forwarder Port:"},
					LineEdit{AssignTo: &s.tunnelDnsForwarderPortEdit},
					Label{Text: "Split TLS Records:"},
					CheckBox{AssignTo: &s.tunnelTlsRecordSplitCheck, Text: "Enable (Fragment ClientHello TLS records)"},

					Label{Text: "Randomize Delay (Jitter):"},
					CheckBox{AssignTo: &s.tunnelDelayJitterCheck, Text: "Enable timing jitter"},
					Label{Text: "TCP Window Clamp (Bytes):"},
					LineEdit{AssignTo: &s.tunnelTcpWindowClampEdit},

					Label{Text: "Custom User-Agent:"},
					LineEdit{AssignTo: &s.tunnelCustomUserAgentEdit},
					Label{Text: "Fake Packet Injection:"},
					CheckBox{AssignTo: &s.tunnelFakePacketInjectCheck, Text: "Enable fake packet injection"},

					Label{Text: "Fake Packet TTL:"},
					LineEdit{AssignTo: &s.tunnelFakePacketTtlEdit},
					Label{Text: "Out-of-Window Evasion:"},
					CheckBox{AssignTo: &s.tunnelOutOfWindowCheck, Text: "Enable wrong-seq"},

					Label{Text: "Wrong-Seq Offset (Bytes):"},
					LineEdit{AssignTo: &s.tunnelOutOfWindowSeqOffsetEdit},
					Label{Text: "Decoy SNI Pool:"},
					LineEdit{AssignTo: &s.tunnelDecoySniPoolEdit},

					Label{Text: "Out-of-band (OOB) Evasion:"},
					CheckBox{AssignTo: &s.tunnelOobCheck, Text: "Enable MSG_OOB"},
					Label{Text: "OOB ClientHello Split (OOBEx):"},
					CheckBox{AssignTo: &s.tunnelOobexCheck, Text: "Enable OOBEx"},

					Label{Text: "Covert Tunnel Mode:"},
					ComboBox{
						AssignTo: &s.tunnelCovertModeCombo,
						Model: []string{
							"Direct",
							"Serverless Relay",
							"DNS Tunnel",
							"GSA Relay",
							"Raw Handshake Bypass (paqet)",
							"Edge Worker Relay",
							"Google Docs Tunnel",
						},
					},
					Label{Text: ""},
					Label{Text: ""},

					Label{Text: "GSA Web App URL:"},
					LineEdit{AssignTo: &s.tunnelCovertGsaUrlEdit},
					Label{Text: "GSA Auth Key:"},
					LineEdit{AssignTo: &s.tunnelCovertGsaKeyEdit},

					Label{Text: "Serverless Worker URL:"},
					LineEdit{AssignTo: &s.tunnelCovertServerlessUrlEdit},
					Label{Text: "DNS Tunnel Domain:"},
					LineEdit{AssignTo: &s.tunnelCovertDnsDomainEdit},
				},
			},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					CheckBox{AssignTo: &s.tunnelActiveCheck, Text: "Activate Local Evasion Tunnel", OnClicked: s.toggleEvasionTunnel},
					HSpacer{},
					Label{AssignTo: &s.tunnelStatusLabel, Text: "Status: Stopped (Inactive)"},
				},
			},
			GroupBox{
				Title:  "UPGen CFG Obfuscation & Steganographic Camouflage Settings",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "UPGen Protocol Obfuscation:"},
					CheckBox{AssignTo: &s.tunnelUpgenCheck, Text: "Enable CFG Obfuscation"},
					Label{Text: "UPGen Shared Seed Hex:"},
					LineEdit{AssignTo: &s.tunnelUpgenSeedEdit},

					Label{Text: "Entropy Matching:"},
					CheckBox{AssignTo: &s.tunnelUpgenEntropyCheck, Text: "Shape packet entropy"},
					Label{Text: "QUIC Exhaustion Rate (pps):"},
					LineEdit{AssignTo: &s.tunnelUpgenQuicRateEdit},

					Label{Text: "Steganographic Camouflage:"},
					CheckBox{AssignTo: &s.tunnelStegoCheck, Text: "Enable VoIP/WebRTC Stego"},
					Label{Text: "Stego Mode:"},
					ComboBox{
						AssignTo: &s.tunnelStegoModeCombo,
						Model: []string{
							"webrtc_voip",
							"pixel_stego",
						},
					},

					Label{Text: "Pixel Decoy Image Path:"},
					LineEdit{AssignTo: &s.tunnelStegoDecoyImageEdit},
					Label{Text: "WebRTC SDP Spoofing:"},
					CheckBox{AssignTo: &s.tunnelStegoWebRTCSDPCheck, Text: "Spoof signals"},
				},
			},
			GroupBox{
				Title:  "Android Mobile VPN Integration & Shielding",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Socket Protect Unix Path:"},
					LineEdit{AssignTo: &s.tunnelCovertSocketProtectPathEdit},
					Label{Text: "APK Assets FileReader:"},
					CheckBox{AssignTo: &s.tunnelMobileAssetsCheck, Text: "Enable asset reader override"},

					Label{Text: "Zygisk VPN-Interface Hider:"},
					CheckBox{AssignTo: &s.tunnelZygiskHideCheck, Text: "Hide tun*/wg* interfaces"},
					Label{Text: "Hardened TLS Ciphers:"},
					CheckBox{AssignTo: &s.tunnelHardenedTlsCheck, Text: "Enforce cipher suite hardening"},
				},
			},
			GroupBox{
				Title:  "Virtual TUN Router (Bypass all system traffic)",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "TUN Device Name:"},
					LineEdit{AssignTo: &s.tunDeviceNameEdit},
					Label{Text: "SOCKS5 Proxy Address:"},
					LineEdit{AssignTo: &s.tunProxyAddrEdit},

					Label{Text: "Split Tunneling App IDs (comma sep):"},
					LineEdit{AssignTo: &s.tunSplitTunnelEdit, MinSize: Size{Width: 200}},
					Label{Text: "(e.g., com.whatsapp, org.telegram.messenger)"},
					Label{Text: ""},
				},
			},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					CheckBox{AssignTo: &s.tunActiveCheck, Text: "Activate Virtual TUN Router", OnClicked: s.toggleTunRouter},
					HSpacer{},
					Label{AssignTo: &s.tunStatusLabel, Text: "Status: Stopped (Inactive)"},
				},
			},
			GroupBox{
				Title:  "Statically Bundled Evasion Core Wrappers (Tor / Psiphon)",
				Layout: Grid{Columns: 4, Spacing: 10},
				Children: []Widget{
					Label{Text: "Tor Network (Onion Client):"},
					Label{AssignTo: &s.torStatusLabel, Text: "Status: STANDBY (Offline)"},
					PushButton{AssignTo: &s.torStartBtn, Text: "Start Tor", OnClicked: s.startTor},
					PushButton{AssignTo: &s.torStopBtn, Text: "Stop Tor", OnClicked: s.stopTor},

					Label{Text: "Psiphon Client Core:"},
					Label{AssignTo: &s.psiphonStatusLabel, Text: "Status: STANDBY (Offline)"},
					PushButton{AssignTo: &s.psiphonStartBtn, Text: "Start Psiphon", OnClicked: s.startPsiphon},
					PushButton{AssignTo: &s.psiphonStopBtn, Text: "Stop Psiphon", OnClicked: s.stopPsiphon},

					CheckBox{AssignTo: &s.psiphonChainCheck, Text: "Chain Psiphon through Evasion Tunnel", ColumnSpan: 4},
				},
			},
			GroupBox{
				Title:  "Bypass Tunnel Connection & Traffic Logs",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &s.tunnelLogText, ReadOnly: true, VScroll: true, MinSize: Size{Height: 320}},
				},
			},
			VSpacer{},
		},
	}
}

func (s *nativeShell) toggleEvasionTunnel() {
	if s.tunnelActiveCheck == nil || s.tunnelStatusLabel == nil {
		return
	}

	active := s.tunnelActiveCheck.Checked()
	portVal := 10888
	if s.tunnelPortEdit != nil {
		if val, err := strconv.Atoi(strings.TrimSpace(s.tunnelPortEdit.Text())); err == nil && val > 0 {
			portVal = val
		}
	}

	splitOffset := 2
	if s.tunnelSplitBytesEdit != nil {
		if val, err := strconv.Atoi(strings.TrimSpace(s.tunnelSplitBytesEdit.Text())); err == nil && val >= 0 {
			splitOffset = val
		}
	}

	delayMs := 20
	if s.tunnelDelayEdit != nil {
		if val, err := strconv.Atoi(strings.TrimSpace(s.tunnelDelayEdit.Text())); err == nil && val >= 0 {
			delayMs = val
		}
	}

	mutateHost := false
	if s.tunnelHostCheck != nil {
		mutateHost = s.tunnelHostCheck.Checked()
	}

	autoSni := false
	if s.tunnelAutoSniCheck != nil {
		autoSni = s.tunnelAutoSniCheck.Checked()
	}

	tlsRecordSplit := false
	if s.tunnelTlsRecordSplitCheck != nil {
		tlsRecordSplit = s.tunnelTlsRecordSplitCheck.Checked()
	}

	packets := "tlshello"
	if s.tunnelPacketsCombo != nil && s.tunnelPacketsCombo.CurrentIndex() == 1 {
		packets = "all"
	}

	minLen := 0
	if s.tunnelMinLenEdit != nil {
		if val, err := strconv.Atoi(strings.TrimSpace(s.tunnelMinLenEdit.Text())); err == nil && val >= 0 {
			minLen = val
		}
	}

	maxLen := 0
	if s.tunnelMaxLenEdit != nil {
		if val, err := strconv.Atoi(strings.TrimSpace(s.tunnelMaxLenEdit.Text())); err == nil && val >= 0 {
			maxLen = val
		}
	}

	dnsResolver := ""
	if s.tunnelDnsResolverEdit != nil {
		dnsResolver = strings.TrimSpace(s.tunnelDnsResolverEdit.Text())
	}

	dnsFwdEnabled := false
	if s.tunnelDnsForwarderCheck != nil {
		dnsFwdEnabled = s.tunnelDnsForwarderCheck.Checked()
	}

	dnsFwdPort := 10053
	if s.tunnelDnsForwarderPortEdit != nil {
		if val, err := strconv.Atoi(strings.TrimSpace(s.tunnelDnsForwarderPortEdit.Text())); err == nil && val > 0 {
			dnsFwdPort = val
		}
	}

	delayJitter := false
	if s.tunnelDelayJitterCheck != nil {
		delayJitter = s.tunnelDelayJitterCheck.Checked()
	}

	windowClamp := 0
	if s.tunnelTcpWindowClampEdit != nil {
		if val, err := strconv.Atoi(strings.TrimSpace(s.tunnelTcpWindowClampEdit.Text())); err == nil && val >= 0 {
			windowClamp = val
		}
	}

	customUA := ""
	if s.tunnelCustomUserAgentEdit != nil {
		customUA = strings.TrimSpace(s.tunnelCustomUserAgentEdit.Text())
	}

	fakePacketInject := false
	if s.tunnelFakePacketInjectCheck != nil {
		fakePacketInject = s.tunnelFakePacketInjectCheck.Checked()
	}

	fakePacketTtl := 4
	if s.tunnelFakePacketTtlEdit != nil {
		if val, err := strconv.Atoi(strings.TrimSpace(s.tunnelFakePacketTtlEdit.Text())); err == nil && val > 0 {
			fakePacketTtl = val
		}
	}

	outOfWindow := false
	if s.tunnelOutOfWindowCheck != nil {
		outOfWindow = s.tunnelOutOfWindowCheck.Checked()
	}

	outOfWindowSeqOffset := 0
	if s.tunnelOutOfWindowSeqOffsetEdit != nil {
		if val, err := strconv.Atoi(strings.TrimSpace(s.tunnelOutOfWindowSeqOffsetEdit.Text())); err == nil {
			outOfWindowSeqOffset = val
		}
	}

	decoySniPool := ""
	if s.tunnelDecoySniPoolEdit != nil {
		decoySniPool = strings.TrimSpace(s.tunnelDecoySniPoolEdit.Text())
	}

	oob := false
	if s.tunnelOobCheck != nil {
		oob = s.tunnelOobCheck.Checked()
	}

	oobex := false
	if s.tunnelOobexCheck != nil {
		oobex = s.tunnelOobexCheck.Checked()
	}

	covertSocketProtectPath := ""
	if s.tunnelCovertSocketProtectPathEdit != nil {
		covertSocketProtectPath = strings.TrimSpace(s.tunnelCovertSocketProtectPathEdit.Text())
	}

	mobileAssetsEnabled := true
	if s.tunnelMobileAssetsCheck != nil {
		mobileAssetsEnabled = s.tunnelMobileAssetsCheck.Checked()
	}

	zygiskHideEnabled := false
	if s.tunnelZygiskHideCheck != nil {
		zygiskHideEnabled = s.tunnelZygiskHideCheck.Checked()
	}

	hardenedTlsEnabled := true
	if s.tunnelHardenedTlsCheck != nil {
		hardenedTlsEnabled = s.tunnelHardenedTlsCheck.Checked()
	}

	type evasionRequest struct {
		Enabled              bool    `json:"enabled"`
		Port                 int     `json:"port"`
		SplitBytes           int     `json:"split_bytes"`
		DelayMs              int     `json:"delay_ms"`
		MutateHost           bool    `json:"mutate_host"`
		MutateHeaderSpace    bool    `json:"mutate_header_space"`
		AutoSni              bool    `json:"auto_sni"`
		SniSplitOffset       int     `json:"sni_split_offset"`
		Packets              string  `json:"packets"`
		MinLength            int     `json:"min_length"`
		MaxLength            int     `json:"max_length"`
		TlsRecordSplit       bool    `json:"tls_record_split"`
		DnsResolver          string  `json:"dns_resolver"`
		DnsForwarderPort     int     `json:"dns_forwarder_port"`
		DnsForwarderEnabled  bool    `json:"dns_forwarder_enabled"`
		SystemProxyEnabled   bool    `json:"system_proxy_enabled"`
		SniSpoof             string  `json:"sni_spoof"`
		ClientHelloPadding   int     `json:"client_hello_padding"`
		DelayJitter          bool    `json:"delay_jitter"`
		TcpWindowClamp       int     `json:"tcp_window_clamp"`
		CustomUserAgent      string  `json:"custom_user_agent"`
		CovertMode           string  `json:"covert_mode"`
		CovertServerlessUrl  string  `json:"covert_serverless_url"`
		CovertDnsDomain      string  `json:"covert_dns_domain"`
		CovertGsaUrl         string  `json:"covert_gsa_url"`
		CovertGsaKey         string  `json:"covert_gsa_key"`
		FakePacketInject     bool    `json:"fake_packet_inject"`
		FakePacketTtl        int     `json:"fake_packet_ttl"`
		OutOfWindowEnabled   bool    `json:"out_of_window_enabled"`
		OutOfWindowSeqOffset int     `json:"out_of_window_seq_offset"`
		DecoySniPool         string  `json:"decoy_sni_pool"`
		MutateSniCase        bool    `json:"mutate_sni_case"`
		MutateMethod         bool    `json:"mutate_method"`
		MutateAbsoluteUri    bool    `json:"mutate_absolute_uri"`
		HttpPadding          int     `json:"http_padding"`
		PreflightSignature   string  `json:"preflight_signature"`
		PreflightDelayMs     int     `json:"preflight_delay_ms"`
		SessionFrag          bool    `json:"session_frag"`
		SessionFragProb      float64 `json:"session_frag_prob"`
		SessionFragMinTotal  int     `json:"session_frag_min_total"`
		SessionFragMaxTotal  int     `json:"session_frag_max_total"`
		SessionFragMinChunk  int     `json:"session_frag_min_chunk"`
		SessionFragMaxChunk  int     `json:"session_frag_max_chunk"`
		SessionFragMinDelayMs int   `json:"session_frag_min_delay_ms"`
		SessionFragMaxDelayMs int   `json:"session_frag_max_delay_ms"`
		OobEnabled           bool    `json:"oob_enabled"`
		OobexEnabled         bool    `json:"oobex_enabled"`
		CovertSocketProtectPath string  `json:"covert_socket_protect_path"`
		MobileAssetsEnabled     bool    `json:"mobile_assets_enabled"`
		ZygiskHideEnabled       bool    `json:"zygisk_hide_enabled"`
		HardenedTlsEnabled      bool    `json:"hardened_tls_enabled"`
		UpgenObfuscationEnabled bool    `json:"upgen_obfuscation_enabled"`
		UpgenSeedHex            string  `json:"upgen_seed_hex"`
		UpgenEntropyMatch       bool    `json:"upgen_entropy_match"`
		UpgenQuicExhaustionRate int     `json:"upgen_quic_exhaustion_rate"`
		SteganographyEnabled    bool    `json:"steganography_enabled"`
		SteganographyMode       string  `json:"steganography_mode"`
		SteganographyDecoyImagePath string `json:"steganography_decoy_image_path"`
		SteganographyWebRTCSDPSpoof bool   `json:"steganography_webrtc_sdp_spoof"`
	}

	go func() {
		var req evasionRequest
		// Fetch current full status to preserve any advanced/covert tunnel settings
		_ = s.getJSON("/api/system/evasion-tunnel", &req)

		// Overwrite with GUI controls
		req.Enabled = active
		req.Port = portVal
		req.SplitBytes = splitOffset
		req.DelayMs = delayMs
		req.MutateHost = mutateHost
		req.AutoSni = autoSni
		req.TlsRecordSplit = tlsRecordSplit
		req.Packets = packets
		req.MinLength = minLen
		req.MaxLength = maxLen
		req.DnsResolver = dnsResolver
		req.DnsForwarderEnabled = dnsFwdEnabled
		req.DnsForwarderPort = dnsFwdPort
		req.DelayJitter = delayJitter
		req.TcpWindowClamp = windowClamp
		req.CustomUserAgent = customUA
		req.FakePacketInject = fakePacketInject
		req.FakePacketTtl = fakePacketTtl
		req.OutOfWindowEnabled = outOfWindow
		req.OutOfWindowSeqOffset = outOfWindowSeqOffset
		req.DecoySniPool = decoySniPool
		req.OobEnabled = oob
		req.OobexEnabled = oobex
		req.CovertSocketProtectPath = covertSocketProtectPath
		req.MobileAssetsEnabled = mobileAssetsEnabled
		req.ZygiskHideEnabled = zygiskHideEnabled
		req.HardenedTlsEnabled = hardenedTlsEnabled

		if s.tunnelUpgenCheck != nil {
			req.UpgenObfuscationEnabled = s.tunnelUpgenCheck.Checked()
		}
		if s.tunnelUpgenSeedEdit != nil {
			req.UpgenSeedHex = strings.TrimSpace(s.tunnelUpgenSeedEdit.Text())
		}
		if s.tunnelUpgenEntropyCheck != nil {
			req.UpgenEntropyMatch = s.tunnelUpgenEntropyCheck.Checked()
		}
		if s.tunnelUpgenQuicRateEdit != nil {
			if val, err := strconv.Atoi(strings.TrimSpace(s.tunnelUpgenQuicRateEdit.Text())); err == nil && val >= 0 {
				req.UpgenQuicExhaustionRate = val
			}
		}
		if s.tunnelStegoCheck != nil {
			req.SteganographyEnabled = s.tunnelStegoCheck.Checked()
		}
		if s.tunnelStegoModeCombo != nil {
			if s.tunnelStegoModeCombo.CurrentIndex() == 1 {
				req.SteganographyMode = "pixel_stego"
			} else {
				req.SteganographyMode = "webrtc_voip"
			}
		}
		if s.tunnelStegoDecoyImageEdit != nil {
			req.SteganographyDecoyImagePath = strings.TrimSpace(s.tunnelStegoDecoyImageEdit.Text())
		}
		if s.tunnelStegoWebRTCSDPCheck != nil {
			req.SteganographyWebRTCSDPSpoof = s.tunnelStegoWebRTCSDPCheck.Checked()
		}

		if s.tunnelCovertModeCombo != nil {
			switch s.tunnelCovertModeCombo.CurrentIndex() {
			case 1:
				req.CovertMode = "serverless"
			case 2:
				req.CovertMode = "dnstunnel"
			case 3:
				req.CovertMode = "gsa"
			case 4:
				req.CovertMode = "paqet"
			case 5:
				req.CovertMode = "edge"
			case 6:
				req.CovertMode = "gdocs"
			default:
				req.CovertMode = "direct"
			}
		}
		if s.tunnelCovertGsaUrlEdit != nil {
			req.CovertGsaUrl = strings.TrimSpace(s.tunnelCovertGsaUrlEdit.Text())
		}
		if s.tunnelCovertGsaKeyEdit != nil {
			req.CovertGsaKey = strings.TrimSpace(s.tunnelCovertGsaKeyEdit.Text())
		}
		if s.tunnelCovertServerlessUrlEdit != nil {
			req.CovertServerlessUrl = strings.TrimSpace(s.tunnelCovertServerlessUrlEdit.Text())
		}
		if s.tunnelCovertDnsDomainEdit != nil {
			req.CovertDnsDomain = strings.TrimSpace(s.tunnelCovertDnsDomainEdit.Text())
		}

		payload, err := json.Marshal(req)
		if err != nil {
			s.sync(func() {
				s.tunnelActiveCheck.SetChecked(false)
				s.tunnelStatusLabel.SetText("Error: JSON marshal failed")
			})
			return
		}

		var resp struct {
			Status  string `json:"status"`
			Enabled bool   `json:"enabled"`
		}
		err = s.postJSON("/api/system/evasion-tunnel", payload, &resp)
		s.sync(func() {
			if err != nil {
				s.tunnelActiveCheck.SetChecked(false)
				s.tunnelStatusLabel.SetText("Error: " + err.Error())
				return
			}

			if active {
				s.tunnelStatusLabel.SetText(fmt.Sprintf("Status: Running SOCKS5 on 127.0.0.1:%d", portVal))
				if s.tunnelLogText != nil {
					s.tunnelLogText.SetText("")
				}
			} else {
				s.tunnelStatusLabel.SetText("Status: Stopped (Inactive)")
			}
		})
	}()
}

func (s *nativeShell) startEvasionLogLoop() {
	go func() {
		ticker := time.NewTicker(1000 * time.Millisecond)
		defer ticker.Stop()
		lastIdx := 0
		for range ticker.C {
			if s.mw == nil || s.mw.Handle() == 0 {
				return
			}
			if s.tunnelActiveCheck == nil || !s.tunnelActiveCheck.Checked() {
				lastIdx = 0
				continue
			}

			var resp struct {
				Logs []string `json:"logs"`
			}
			err := s.getJSON("/api/system/evasion-tunnel/logs", &resp)
			if err != nil {
				continue
			}

			s.sync(func() {
				if s.tunnelLogText == nil {
					return
				}
				if len(resp.Logs) < lastIdx {
					lastIdx = 0
					s.tunnelLogText.SetText("")
				}
				for i := lastIdx; i < len(resp.Logs); i++ {
					s.tunnelLogText.AppendText(resp.Logs[i] + "\r\n")
				}
				lastIdx = len(resp.Logs)
			})
		}
	}()
}

func (s *nativeShell) refreshEvasionStatus() {
	go func() {
		type response struct {
			Running              bool   `json:"running"`
			Port                 int    `json:"port"`
			SplitBytes           int    `json:"split_bytes"`
			DelayMs              int    `json:"delay_ms"`
			MutateHost           bool   `json:"mutate_host"`
			AutoSni              bool   `json:"auto_sni"`
			Packets              string `json:"packets"`
			MinLength            int    `json:"min_length"`
			MaxLength            int    `json:"max_length"`
			TlsRecordSplit       bool   `json:"tls_record_split"`
			DnsResolver          string `json:"dns_resolver"`
			DnsForwarderPort     int    `json:"dns_forwarder_port"`
			DnsForwarderEnabled  bool   `json:"dns_forwarder_enabled"`
			DelayJitter          bool   `json:"delay_jitter"`
			TcpWindowClamp       int    `json:"tcp_window_clamp"`
			CustomUserAgent      string `json:"custom_user_agent"`
			CovertMode           string `json:"covert_mode"`
			CovertServerlessUrl  string `json:"covert_serverless_url"`
			CovertDnsDomain      string `json:"covert_dns_domain"`
			CovertGsaUrl         string `json:"covert_gsa_url"`
			CovertGsaKey         string `json:"covert_gsa_key"`
			FakePacketInject     bool   `json:"fake_packet_inject"`
			FakePacketTtl        int    `json:"fake_packet_ttl"`
			OutOfWindowEnabled   bool   `json:"out_of_window_enabled"`
			OutOfWindowSeqOffset int    `json:"out_of_window_seq_offset"`
			DecoySniPool         string `json:"decoy_sni_pool"`
			OobEnabled           bool   `json:"oob_enabled"`
			OobexEnabled         bool   `json:"oobex_enabled"`
			CovertSocketProtectPath string `json:"covert_socket_protect_path"`
			MobileAssetsEnabled     bool   `json:"mobile_assets_enabled"`
			ZygiskHideEnabled       bool   `json:"zygisk_hide_enabled"`
			HardenedTlsEnabled      bool   `json:"hardened_tls_enabled"`
			UpgenObfuscationEnabled bool   `json:"upgen_obfuscation_enabled"`
			UpgenSeedHex            string `json:"upgen_seed_hex"`
			UpgenEntropyMatch       bool   `json:"upgen_entropy_match"`
			UpgenQuicExhaustionRate int    `json:"upgen_quic_exhaustion_rate"`
			SteganographyEnabled    bool   `json:"steganography_enabled"`
			SteganographyMode       string `json:"steganography_mode"`
			SteganographyDecoyImagePath string `json:"steganography_decoy_image_path"`
			SteganographyWebRTCSDPSpoof bool   `json:"steganography_webrtc_sdp_spoof"`
		}
		var resp response
		err := s.getJSON("/api/system/evasion-tunnel", &resp)
		s.sync(func() {
			if err != nil {
				return
			}
			if s.tunnelActiveCheck != nil {
				s.tunnelActiveCheck.SetChecked(resp.Running)
			}
			if s.tunnelPortEdit != nil {
				s.tunnelPortEdit.SetText(strconv.Itoa(resp.Port))
			}
			if s.tunnelSplitBytesEdit != nil {
				s.tunnelSplitBytesEdit.SetText(strconv.Itoa(resp.SplitBytes))
			}
			if s.tunnelDelayEdit != nil {
				s.tunnelDelayEdit.SetText(strconv.Itoa(resp.DelayMs))
			}
			if s.tunnelHostCheck != nil {
				s.tunnelHostCheck.SetChecked(resp.MutateHost)
			}
			if s.tunnelAutoSniCheck != nil {
				s.tunnelAutoSniCheck.SetChecked(resp.AutoSni)
			}
			if s.tunnelTlsRecordSplitCheck != nil {
				s.tunnelTlsRecordSplitCheck.SetChecked(resp.TlsRecordSplit)
			}
			if s.tunnelPacketsCombo != nil {
				if resp.Packets == "all" {
					_ = s.tunnelPacketsCombo.SetCurrentIndex(1)
				} else {
					_ = s.tunnelPacketsCombo.SetCurrentIndex(0)
				}
			}
			if s.tunnelMinLenEdit != nil {
				s.tunnelMinLenEdit.SetText(strconv.Itoa(resp.MinLength))
			}
			if s.tunnelMaxLenEdit != nil {
				s.tunnelMaxLenEdit.SetText(strconv.Itoa(resp.MaxLength))
			}
			if s.tunnelDnsResolverEdit != nil {
				s.tunnelDnsResolverEdit.SetText(resp.DnsResolver)
			}
			if s.tunnelDnsForwarderCheck != nil {
				s.tunnelDnsForwarderCheck.SetChecked(resp.DnsForwarderEnabled)
			}
			if s.tunnelDnsForwarderPortEdit != nil {
				s.tunnelDnsForwarderPortEdit.SetText(strconv.Itoa(resp.DnsForwarderPort))
			}
			if s.tunnelDelayJitterCheck != nil {
				s.tunnelDelayJitterCheck.SetChecked(resp.DelayJitter)
			}
			if s.tunnelTcpWindowClampEdit != nil {
				s.tunnelTcpWindowClampEdit.SetText(strconv.Itoa(resp.TcpWindowClamp))
			}
			if s.tunnelCustomUserAgentEdit != nil {
				s.tunnelCustomUserAgentEdit.SetText(resp.CustomUserAgent)
			}
			if s.tunnelFakePacketInjectCheck != nil {
				s.tunnelFakePacketInjectCheck.SetChecked(resp.FakePacketInject)
			}
			if s.tunnelFakePacketTtlEdit != nil {
				s.tunnelFakePacketTtlEdit.SetText(strconv.Itoa(resp.FakePacketTtl))
			}
			if s.tunnelOutOfWindowCheck != nil {
				s.tunnelOutOfWindowCheck.SetChecked(resp.OutOfWindowEnabled)
			}
			if s.tunnelOutOfWindowSeqOffsetEdit != nil {
				s.tunnelOutOfWindowSeqOffsetEdit.SetText(strconv.Itoa(resp.OutOfWindowSeqOffset))
			}
			if s.tunnelDecoySniPoolEdit != nil {
				s.tunnelDecoySniPoolEdit.SetText(resp.DecoySniPool)
			}
			if s.tunnelOobCheck != nil {
				s.tunnelOobCheck.SetChecked(resp.OobEnabled)
			}
			if s.tunnelOobexCheck != nil {
				s.tunnelOobexCheck.SetChecked(resp.OobexEnabled)
			}
			if s.tunnelCovertModeCombo != nil {
				idx := 0
				switch resp.CovertMode {
				case "serverless":
					idx = 1
				case "dnstunnel":
					idx = 2
				case "gsa":
					idx = 3
				case "paqet":
					idx = 4
				case "edge":
					idx = 5
				case "gdocs":
					idx = 6
				default:
					idx = 0
				}
				_ = s.tunnelCovertModeCombo.SetCurrentIndex(idx)
			}
			if s.tunnelCovertGsaUrlEdit != nil {
				s.tunnelCovertGsaUrlEdit.SetText(resp.CovertGsaUrl)
			}
			if s.tunnelCovertGsaKeyEdit != nil {
				s.tunnelCovertGsaKeyEdit.SetText(resp.CovertGsaKey)
			}
			if s.tunnelCovertServerlessUrlEdit != nil {
				s.tunnelCovertServerlessUrlEdit.SetText(resp.CovertServerlessUrl)
			}
			if s.tunnelCovertDnsDomainEdit != nil {
				s.tunnelCovertDnsDomainEdit.SetText(resp.CovertDnsDomain)
			}
			if s.tunnelCovertSocketProtectPathEdit != nil {
				s.tunnelCovertSocketProtectPathEdit.SetText(resp.CovertSocketProtectPath)
			}
			if s.tunnelMobileAssetsCheck != nil {
				s.tunnelMobileAssetsCheck.SetChecked(resp.MobileAssetsEnabled)
			}
			if s.tunnelZygiskHideCheck != nil {
				s.tunnelZygiskHideCheck.SetChecked(resp.ZygiskHideEnabled)
			}
			if s.tunnelHardenedTlsCheck != nil {
				s.tunnelHardenedTlsCheck.SetChecked(resp.HardenedTlsEnabled)
			}
			if s.tunnelUpgenCheck != nil {
				s.tunnelUpgenCheck.SetChecked(resp.UpgenObfuscationEnabled)
			}
			if s.tunnelUpgenSeedEdit != nil {
				s.tunnelUpgenSeedEdit.SetText(resp.UpgenSeedHex)
			}
			if s.tunnelUpgenEntropyCheck != nil {
				s.tunnelUpgenEntropyCheck.SetChecked(resp.UpgenEntropyMatch)
			}
			if s.tunnelUpgenQuicRateEdit != nil {
				s.tunnelUpgenQuicRateEdit.SetText(strconv.Itoa(resp.UpgenQuicExhaustionRate))
			}
			if s.tunnelStegoCheck != nil {
				s.tunnelStegoCheck.SetChecked(resp.SteganographyEnabled)
			}
			if s.tunnelStegoModeCombo != nil {
				if resp.SteganographyMode == "pixel_stego" {
					_ = s.tunnelStegoModeCombo.SetCurrentIndex(1)
				} else {
					_ = s.tunnelStegoModeCombo.SetCurrentIndex(0)
				}
			}
			if s.tunnelStegoDecoyImageEdit != nil {
				s.tunnelStegoDecoyImageEdit.SetText(resp.SteganographyDecoyImagePath)
			}
			if s.tunnelStegoWebRTCSDPCheck != nil {
				s.tunnelStegoWebRTCSDPCheck.SetChecked(resp.SteganographyWebRTCSDPSpoof)
			}

			if s.tunnelStatusLabel != nil {
				if resp.Running {
					s.tunnelStatusLabel.SetText(fmt.Sprintf("Status: Running SOCKS5 on 127.0.0.1:%d", resp.Port))
				} else {
					s.tunnelStatusLabel.SetText("Status: Stopped (Inactive)")
				}
			}
		})

		// Also fetch and refresh Virtual TUN Router status
		var tunStatus struct {
			Running    bool   `json:"running"`
			DeviceName string `json:"device_name"`
			ProxyAddr  string `json:"proxy_addr"`
			MTU        int    `json:"mtu"`
		}
		errTun := s.getJSON("/api/system/tun-router", &tunStatus)
		s.sync(func() {
			if errTun != nil {
				return
			}
			if s.tunActiveCheck != nil {
				s.tunActiveCheck.SetChecked(tunStatus.Running)
			}
			if s.tunDeviceNameEdit != nil && tunStatus.DeviceName != "" {
				s.tunDeviceNameEdit.SetText(tunStatus.DeviceName)
			}
			if s.tunProxyAddrEdit != nil && tunStatus.ProxyAddr != "" {
				s.tunProxyAddrEdit.SetText(tunStatus.ProxyAddr)
			}
			if s.tunStatusLabel != nil {
				if tunStatus.Running {
					s.tunStatusLabel.SetText(fmt.Sprintf("Status: Running on %s -> %s (MTU: %d)", tunStatus.DeviceName, tunStatus.ProxyAddr, tunStatus.MTU))
				} else {
					s.tunStatusLabel.SetText("Status: Stopped (Inactive)")
				}
			}
		})

		// Also fetch and refresh Advanced Bypass Engines status
		type engineStatus struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Running   bool   `json:"running"`
			SocksPort int    `json:"socks_port"`
		}
		var enginesResp struct {
			Engines []engineStatus `json:"engines"`
		}
		errEngines := s.getJSON("/api/system/engines", &enginesResp)
		s.sync(func() {
			if errEngines != nil {
				return
			}
			for _, eng := range enginesResp.Engines {
				if eng.ID == "tor" {
					if s.torStatusLabel != nil {
						if eng.Running {
							s.torStatusLabel.SetText(fmt.Sprintf("Status: ONLINE (SOCKS5 127.0.0.1:%d)", eng.SocksPort))
						} else {
							s.torStatusLabel.SetText("Status: STANDBY (Offline)")
						}
					}
				} else if eng.ID == "psiphon" {
					if s.psiphonStatusLabel != nil {
						if eng.Running {
							s.psiphonStatusLabel.SetText(fmt.Sprintf("Status: ONLINE (SOCKS5 127.0.0.1:%d)", eng.SocksPort))
						} else {
							s.psiphonStatusLabel.SetText("Status: STANDBY (Offline)")
						}
					}
				}
			}
		})
	}()
}

func (s *nativeShell) toggleTunRouter() {
	if s.tunActiveCheck == nil || s.tunStatusLabel == nil {
		return
	}

	active := s.tunActiveCheck.Checked()
	deviceName := "wintun0"
	if s.tunDeviceNameEdit != nil {
		deviceName = strings.TrimSpace(s.tunDeviceNameEdit.Text())
	}
	proxyAddr := "127.0.0.1:10888"
	if s.tunProxyAddrEdit != nil {
		proxyAddr = strings.TrimSpace(s.tunProxyAddrEdit.Text())
	}
	splitApps := ""
	if s.tunSplitTunnelEdit != nil {
		splitApps = strings.TrimSpace(s.tunSplitTunnelEdit.Text())
	}

	payload, err := json.Marshal(map[string]interface{}{
		"enabled":     active,
		"device_name": deviceName,
		"proxy_addr":  proxyAddr,
		"split_apps":  splitApps,
	})
	if err != nil {
		s.tunActiveCheck.SetChecked(false)
		s.tunStatusLabel.SetText("Error: JSON marshal failed")
		return
	}

	go func() {
		var resp struct {
			Status     string `json:"status"`
			Enabled    bool   `json:"enabled"`
			DeviceName string `json:"device_name"`
			ProxyAddr  string `json:"proxy_addr"`
			MTU        int    `json:"mtu"`
		}
		err := s.postJSON("/api/system/tun-router", payload, &resp)
		s.sync(func() {
			if err != nil {
				s.tunActiveCheck.SetChecked(false)
				s.tunStatusLabel.SetText("Error: " + err.Error())
				return
			}

			if resp.Enabled {
				s.tunStatusLabel.SetText(fmt.Sprintf("Status: Running on %s -> %s (MTU: %d)", resp.DeviceName, resp.ProxyAddr, resp.MTU))
			} else {
				s.tunStatusLabel.SetText("Status: Stopped (Inactive)")
			}
		})
	}()
}

func (s *nativeShell) onTunnelPresetChanged() {
	if s.tunnelPresetCombo == nil {
		return
	}
	idx := s.tunnelPresetCombo.CurrentIndex()
	if idx <= 0 { // Custom (Manual Config)
		return
	}

	var (
		splitBytes      string
		delayMs         string
		autoSni         bool
		packetsIdx      int
		minLen          string
		maxLen          string
		tlsRecordSplit  bool
		delayJitter     bool
		tcpWindowClamp  string
		customUserAgent string
		mutateHost      bool
	)

	switch idx {
	case 1: // Fast
		splitBytes = "2"
		delayMs = "10"
		autoSni = true
		packetsIdx = 0 // TLS ClientHello only
		minLen = "0"
		maxLen = "0"
		tlsRecordSplit = false
		delayJitter = false
		tcpWindowClamp = "0"
		customUserAgent = ""
		mutateHost = true
	case 2: // Balanced
		splitBytes = "5"
		delayMs = "25"
		autoSni = true
		packetsIdx = 0 // TLS ClientHello only
		minLen = "0"
		maxLen = "0"
		tlsRecordSplit = true
		delayJitter = true
		tcpWindowClamp = "0"
		customUserAgent = ""
		mutateHost = true
	case 3: // Stealth
		splitBytes = "1"
		delayMs = "40"
		autoSni = true
		packetsIdx = 1 // All traffic
		minLen = "5"
		maxLen = "25"
		tlsRecordSplit = true
		delayJitter = true
		tcpWindowClamp = "1024"
		customUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
		mutateHost = true
	}

	if s.tunnelSplitBytesEdit != nil {
		s.tunnelSplitBytesEdit.SetText(splitBytes)
	}
	if s.tunnelDelayEdit != nil {
		s.tunnelDelayEdit.SetText(delayMs)
	}
	if s.tunnelAutoSniCheck != nil {
		s.tunnelAutoSniCheck.SetChecked(autoSni)
	}
	if s.tunnelPacketsCombo != nil {
		_ = s.tunnelPacketsCombo.SetCurrentIndex(packetsIdx)
	}
	if s.tunnelMinLenEdit != nil {
		s.tunnelMinLenEdit.SetText(minLen)
	}
	if s.tunnelMaxLenEdit != nil {
		s.tunnelMaxLenEdit.SetText(maxLen)
	}
	if s.tunnelTlsRecordSplitCheck != nil {
		s.tunnelTlsRecordSplitCheck.SetChecked(tlsRecordSplit)
	}
	if s.tunnelDelayJitterCheck != nil {
		s.tunnelDelayJitterCheck.SetChecked(delayJitter)
	}
	if s.tunnelTcpWindowClampEdit != nil {
		s.tunnelTcpWindowClampEdit.SetText(tcpWindowClamp)
	}
	if s.tunnelCustomUserAgentEdit != nil {
		s.tunnelCustomUserAgentEdit.SetText(customUserAgent)
	}
	if s.tunnelHostCheck != nil {
		s.tunnelHostCheck.SetChecked(mutateHost)
	}

	oob := false
	oobex := false
	if idx == 3 {
		oob = true
	}
	if s.tunnelOobCheck != nil {
		s.tunnelOobCheck.SetChecked(oob)
	}
	if s.tunnelOobexCheck != nil {
		s.tunnelOobexCheck.SetChecked(oobex)
	}

	s.setStatus("Evasion tunnel preset strategy applied to fields.")
}

func (s *nativeShell) startTor() {
	s.controlBypassEngine("tor", "start")
}

func (s *nativeShell) stopTor() {
	s.controlBypassEngine("tor", "stop")
}

func (s *nativeShell) startPsiphon() {
	s.controlBypassEngine("psiphon", "start")
}

func (s *nativeShell) stopPsiphon() {
	s.controlBypassEngine("psiphon", "stop")
}

func (s *nativeShell) controlBypassEngine(engine, action string) {
	s.setStatus(fmt.Sprintf("Sending %s command to %s engine...", action, engine))

	reqMap := map[string]interface{}{
		"engine": engine,
		"action": action,
	}

	if engine == "psiphon" && action == "start" && s.psiphonChainCheck != nil && s.psiphonChainCheck.Checked() {
		portVal := 10888
		if s.tunnelPortEdit != nil {
			if val, err := strconv.Atoi(strings.TrimSpace(s.tunnelPortEdit.Text())); err == nil && val > 0 {
				portVal = val
			}
		}
		reqMap["upstream_proxy"] = fmt.Sprintf("127.0.0.1:%d", portVal)
	}

	payload, err := json.Marshal(reqMap)
	if err != nil {
		s.setStatus("Failed to marshal engine command.")
		return
	}

	go func() {
		var resp map[string]interface{}
		err := s.postJSON("/api/system/engines", payload, &resp)
		s.sync(func() {
			if err != nil {
				s.setStatus(fmt.Sprintf("Failed to %s %s: %s", action, engine, err))
				return
			}
			s.setStatus(fmt.Sprintf("Engine %s %s command succeeded.", engine, action))
			s.refreshEvasionStatus()
		})
	}()
}
