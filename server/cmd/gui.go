//go:build windows && cgo

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

type nativeSystemStatus struct {
	APIConnected  bool                     `json:"api_connected"`
	PublicIPv4    string                   `json:"public_ipv4"`
	PublicIPv6    string                   `json:"public_ipv6"`
	DNSServers    []string                 `json:"dns_servers"`
	ProxyActive   bool                     `json:"proxy_active"`
	EvasionActive bool                     `json:"evasion_active"`
	Interfaces    []nativeNetworkInterface `json:"interfaces"`
	UptimeSeconds int64                    `json:"uptime_seconds"`
	ActiveJobs    int                      `json:"active_jobs"`
	CPUUsage      int                      `json:"cpu_usage"`
	RAMUsage      int                      `json:"ram_usage"`
	TotalRAMGb    float64                  `json:"total_ram_gb"`
	UsedRAMGb     float64                  `json:"used_ram_gb"`
	DiskUsage     int                      `json:"disk_usage"`
	DiskFreeGb    int                      `json:"disk_free_gb"`
}

type nativeNetworkInterface struct {
	Name       string   `json:"name"`
	MAC        string   `json:"mac"`
	IPs        []string `json:"ips"`
	Gateway    string   `json:"gateway"`
	IsWireless bool     `json:"is_wireless"`
	SSID       string   `json:"ssid"`
}

type nativeCapabilityResponse struct {
	Runtime struct {
		OS       string            `json:"os"`
		Arch     string            `json:"arch"`
		MockCore bool              `json:"mock_core"`
		Ports    map[string]string `json:"ports"`
	} `json:"runtime"`
	SafetyBoundary struct {
		Mode              string   `json:"mode"`
		BlockedOperations []string `json:"blocked_operations"`
	} `json:"safety_boundary"`
	Catalog []struct {
		ID                string   `json:"id"`
		Name              string   `json:"name"`
		Domain            string   `json:"domain"`
		Priority          string   `json:"priority"`
		Maturity          string   `json:"maturity"`
		NativeRuntime     string   `json:"native_runtime"`
		SafeState         string   `json:"safe_state"`
		AllowedOperations []string `json:"allowed_operations"`
		Warning           string   `json:"warning"`
	} `json:"catalog"`
	NetworkToolTemplates []struct {
		ID             string   `json:"id"`
		Name           string   `json:"name"`
		Source         string   `json:"source"`
		Status         string   `json:"status"`
		NativeTarget   string   `json:"native_target"`
		UsefulFor      []string `json:"useful_for"`
		SafetyBoundary string   `json:"safety_boundary"`
	} `json:"network_tool_templates"`
}

type nativeHistoryResponse struct {
	Jobs  []nativeHistoryJob `json:"jobs"`
	Total int                `json:"total"`
}

type nativeHistoryJob struct {
	ID          string
	Type        string
	Status      string
	Progress    int
	CreatedAt   time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
	Config      string
	Results     string
	Error       string
}

type nativeDNSStatus struct {
	Interface string   `json:"interface"`
	Servers   []string `json:"servers"`
	Source    string   `json:"source"`
}

type nativeProxyStatus struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server"`
	Bypass  string `json:"bypass"`
	PacURL  string `json:"pac_url"`
}

type nativeStartupStatus struct {
	Enabled bool `json:"enabled"`
}

type nativeNCSIStatus struct {
	ActiveWebProbeHost     string `json:"active_web_probe_host"`
	ActiveWebProbePath     string `json:"active_web_probe_path"`
	ActiveWebProbeContents string `json:"active_web_probe_contents"`
	ActiveDnsProbeHost     string `json:"active_dns_probe_host"`
	ActiveDnsProbeContent  string `json:"active_dns_probe_content"`
	EnableActiveProbing    uint32 `json:"enable_active_probing"`
}

type nativeMihomoRulesOptions struct {
	BypassChina       bool `json:"bypass_china"`
	BypassIran        bool `json:"bypass_iran"`
	BypassRussia      bool `json:"bypass_russia"`
	BypassOpenAI      bool `json:"bypass_openai"`
	BypassGoogleAI    bool `json:"bypass_google_ai"`
	BypassMicrosoft   bool `json:"bypass_microsoft"`
	BypassOracle      bool `json:"bypass_oracle"`
	BypassDocker      bool `json:"bypass_docker"`
	BypassAdobe       bool `json:"bypass_adobe"`
	BypassEpicGames   bool `json:"bypass_epic_games"`
	BypassIntel       bool `json:"bypass_intel"`
	BypassAMD         bool `json:"bypass_amd"`
	BypassNvidia      bool `json:"bypass_nvidia"`
	BypassAsus        bool `json:"bypass_asus"`
	BypassHP          bool `json:"bypass_hp"`
	BypassLenovo      bool `json:"bypass_lenovo"`
	BlockMalware      bool `json:"block_malware"`
	BlockPhishing     bool `json:"block_phishing"`
	BlockCryptominers bool `json:"block_cryptominers"`
	BlockAds          bool `json:"block_ads"`
	BlockPorn         bool `json:"block_porn"`
}

type nativeScannerSettings struct {
	DefaultTimeoutMs int                      `json:"default_timeout_ms"`
	MaxConcurrency   int                      `json:"max_concurrency"`
	DebugLogs        bool                     `json:"debug_logs"`
	DnsResolution    bool                     `json:"dns_resolution"`
	MihomoRules      nativeMihomoRulesOptions `json:"mihomo_rules"`
	HostsOverride    bool                     `json:"hosts_override"`
}

type nativeDDNSStatus struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`
	Domain   string `json:"domain"`
	Interval int    `json:"interval"`
}

type nativeProfilesStatus struct {
	Profiles   []nativeProfile `json:"profiles"`
	ActiveSSID string          `json:"active_ssid"`
	Message    string          `json:"message"`
}

type nativeProfile struct {
	Name   string `json:"name"`
	SSID   string `json:"ssid"`
	BSSID  string `json:"bssid"`
	Active bool   `json:"active"`
}

// runGUI launches the Windows-native LumiNet shell. It uses Win32 controls via
// walk and talks to the local Go daemon API.
func runGUI(url, apiKey string, cancel context.CancelFunc) {
	app := &nativeShell{baseURL: strings.TrimRight(url, "/"), apiKey: apiKey, client: &http.Client{Timeout: 8 * time.Second}}
	app.run(cancel)
}

func nativeGUIAvailable() bool {
	return true
}

type nativeShell struct {
	baseURL string
	apiKey  string
	client  *http.Client

	mw              *walk.MainWindow
	workbench       *walk.MainWindow
	cockpitWidget   *walk.CustomWidget
	statusLine      *walk.Label
	cpuLabel        *walk.Label
	ramLabel        *walk.Label
	diskLabel       *walk.Label
	jobsLabel       *walk.Label
	publicIPLabel   *walk.Label
	publicIPv6Label *walk.Label
	dnsLabel        *walk.Label
	proxyLabel      *walk.Label
	runtimeLabel    *walk.Label
	overviewEdit    *walk.TextEdit
	interfacesEdit  *walk.TextEdit
	capabilityEdit  *walk.TextEdit
	toolLedgerEdit  *walk.TextEdit
	boundaryEdit    *walk.TextEdit
	activityLog     *walk.TextEdit
	targetEdit      *walk.LineEdit
	autoRefresh     *walk.CheckBox
	compactMode     *walk.CheckBox
	diagnosticsMode *walk.ComboBox
	parserInput          *walk.TextEdit
	parserOutput         *walk.TextEdit
	rewriteInput         *walk.TextEdit
	rewriteCleanIPs      *walk.TextEdit
	rewritePortOverride  *walk.LineEdit
	rewriteNameTemplate  *walk.LineEdit
	rewriteOutput        *walk.TextEdit
	rewritePreviewOutput *walk.TextEdit
	historyEdit          *walk.TextEdit
	historyTotal    *walk.Label
	scanMode        *walk.ComboBox
	scanTarget      *walk.TextEdit
	scanPorts       *walk.LineEdit
	scanDNSServer   *walk.LineEdit
	scanRecordType  *walk.ComboBox
	scanTimeout     *walk.LineEdit
	scanConcurrency *walk.LineEdit
	scanIPv6        *walk.CheckBox
	scanSni         *walk.LineEdit
	dnsInterface    *walk.Label
	dnsServersEdit  *walk.LineEdit
	dnsSourceLabel  *walk.Label
	sysProxyEnabled *walk.CheckBox
	sysProxyServer  *walk.LineEdit
	sysProxyBypass  *walk.LineEdit
	sysProxyPACEnabled *walk.CheckBox
	sysProxyPACURL     *walk.LineEdit

	ncsiWebHost     *walk.LineEdit
	ncsiWebPath     *walk.LineEdit
	ncsiWebContent  *walk.LineEdit
	ncsiDnsHost     *walk.LineEdit
	ncsiDnsContent  *walk.LineEdit
	ncsiActiveProbe     *walk.CheckBox
	defaultTimeoutEdit  *walk.LineEdit
	maxConcurrencyEdit  *walk.LineEdit
	debugLogsCheck      *walk.CheckBox
	dnsResolutionCheck  *walk.CheckBox
	hostsOverrideCheck  *walk.CheckBox
	bypassChinaCheck        *walk.CheckBox
	bypassIranCheck         *walk.CheckBox
	bypassRussiaCheck       *walk.CheckBox
	bypassOpenAICheck       *walk.CheckBox
	bypassGoogleAICheck     *walk.CheckBox
	bypassMicrosoftCheck    *walk.CheckBox
	bypassOracleCheck       *walk.CheckBox
	bypassDockerCheck       *walk.CheckBox
	bypassAdobeCheck        *walk.CheckBox
	bypassEpicGamesCheck    *walk.CheckBox
	bypassIntelCheck        *walk.CheckBox
	bypassAMDCheck          *walk.CheckBox
	bypassNvidiaCheck       *walk.CheckBox
	bypassAsusCheck         *walk.CheckBox
	bypassHPCheck           *walk.CheckBox
	bypassLenovoCheck       *walk.CheckBox
	blockMalwareCheck       *walk.CheckBox
	blockPhishingCheck      *walk.CheckBox
	blockCryptominersCheck  *walk.CheckBox
	blockAdsCheck           *walk.CheckBox
	blockPornCheck          *walk.CheckBox
	proxyTestInput  *walk.TextEdit
	proxyTestURL    *walk.LineEdit
	proxyTimeout    *walk.LineEdit
	proxySpeedTest  *walk.CheckBox
	proxyTestOutput *walk.TextEdit
	startupEnabled  *walk.CheckBox
	ddnsEnabled     *walk.CheckBox
	ddnsProvider    *walk.LineEdit
	ddnsDomain      *walk.LineEdit
	ddnsToken       *walk.LineEdit
	ddnsInterval    *walk.LineEdit
	profilesEdit    *walk.TextEdit
	jobIDEdit       *walk.LineEdit
	jobInspector    *walk.TextEdit
	runbookEdit     *walk.TextEdit
	cockpitScenario *walk.ComboBox
	cockpitTarget   *walk.LineEdit
	cockpitPorts    *walk.LineEdit

	// Subscription Center variables
	subAggInputs         *walk.TextEdit
	subAggVMess          *walk.CheckBox
	subAggVLESS          *walk.CheckBox
	subAggTrojan         *walk.CheckBox
	subAggSS             *walk.CheckBox
	subAggSearch         *walk.LineEdit
	subAggMinPort        *walk.LineEdit
	subAggMaxPort        *walk.LineEdit
	subAggOutput         *walk.TextEdit
	subShapeTemplate     *walk.TextEdit
	subShapeCleanIPs     *walk.TextEdit
	subShapeNameTemplate *walk.LineEdit
	subShapeOutput       *walk.TextEdit

	dnsSecDomain         *walk.LineEdit
	dnsSecUdpServer      *walk.LineEdit
	dnsSecDohServer      *walk.LineEdit
	dnsSecDohPresetCombo *walk.ComboBox
	dnsSecDotServer      *walk.LineEdit
	dnsSecOutput         *walk.TextEdit

	speedServerEdit    *walk.LineEdit
	speedTimeoutEdit   *walk.LineEdit
	speedPresetCombo   *walk.ComboBox
	speedResultEdit    *walk.TextEdit
	speedDownloadLabel *walk.Label
	speedUploadLabel   *walk.Label
	speedLatencyLabel  *walk.Label
	speedJitterLabel   *walk.Label
	speedGradeLabel    *walk.Label

	dnsBenchDomain     *walk.LineEdit
	dnsBenchOutput     *walk.TextEdit
	dnsBenchGoogle     *walk.Label
	dnsBenchCloudflare *walk.Label
	dnsBenchQuad9      *walk.Label
	dnsBenchOpenDns    *walk.Label
	dnsBenchAdGuard    *walk.Label
	dnsBenchLocal      *walk.Label
	dnsBenchShecan     *walk.Label
	dnsBench403        *walk.Label
	dnsBenchMullvad    *walk.Label
	dnsBenchElectro    *walk.Label
	dnsBenchRadar      *walk.Label
	dnsBenchLevel3     *walk.Label

	subnetCidrEdit    *walk.LineEdit
	subnetResultEdit  *walk.TextEdit
	subnetHostsLabel  *walk.Label
	subnetPortsEdit   *walk.LineEdit
	subnetConcurrency *walk.LineEdit
	subnetTimeoutEdit *walk.LineEdit
	subnetScanMode    *walk.ComboBox

	wgTargetEdit   *walk.LineEdit
	wgPortEdit     *walk.LineEdit
	wgTimeoutEdit  *walk.LineEdit
	wgPaddingEdit  *walk.LineEdit
	wgPresetCombo  *walk.ComboBox
	wgResultEdit   *walk.TextEdit
	wgStatusLabel  *walk.Label
	wgLatencyLabel *walk.Label

	censorshipTargetEdit  *walk.LineEdit
	censorshipPortEdit    *walk.LineEdit
	censorshipProxyEdit   *walk.LineEdit
	censorshipResultEdit  *walk.TextEdit
	censorshipDirectLabel *walk.Label
	censorshipProxyLabel  *walk.Label
	censorshipRiskLabel   *walk.Label

	captiveTimeoutEdit   *walk.LineEdit
	captiveResultEdit    *walk.TextEdit
	captiveStatusLabel   *walk.Label
	captiveRedirectLabel *walk.Label

	evasionHostEdit        *walk.LineEdit
	evasionPortEdit        *walk.LineEdit
	evasionDelayEdit       *walk.LineEdit
	evasionResultEdit      *walk.TextEdit
	evasionStatusLabel     *walk.Label
	evasionFingerprintEdit *walk.TextEdit

	frontingTargetEdit  *walk.LineEdit
	frontingSniEdit     *walk.LineEdit
	frontingPaddingEdit *walk.LineEdit
	frontingResultEdit  *walk.TextEdit
	frontingStatusLabel *walk.Label

	echTargetEdit  *walk.LineEdit
	echPortEdit    *walk.LineEdit
	echDnsEdit     *walk.LineEdit
	echDohEdit     *walk.LineEdit
	echSniEdit     *walk.LineEdit
	echConfigEdit  *walk.LineEdit
	echResultEdit  *walk.TextEdit
	echStatusLabel *walk.Label

	geoIPTargetEdit *walk.LineEdit
	geoIPOutput     *walk.TextEdit

	wizardTargetEdit  *walk.LineEdit
	wizardStatusLabel *walk.Label
	wizardOutput      *walk.TextEdit

	cpuHistory []int
	ramHistory []int

	tunnelPresetCombo          *walk.ComboBox
	tunnelPortEdit             *walk.LineEdit
	tunnelSplitBytesEdit       *walk.LineEdit
	tunnelDelayEdit            *walk.LineEdit
	tunnelHostCheck            *walk.CheckBox
	tunnelAutoSniCheck         *walk.CheckBox
	tunnelTlsRecordSplitCheck  *walk.CheckBox
	tunnelOobCheck             *walk.CheckBox
	tunnelOobexCheck           *walk.CheckBox
	tunnelPacketsCombo         *walk.ComboBox
	tunnelMinLenEdit           *walk.LineEdit
	tunnelMaxLenEdit           *walk.LineEdit
	tunnelDnsResolverEdit      *walk.LineEdit
	tunnelDnsForwarderCheck    *walk.CheckBox
	tunnelDnsForwarderPortEdit *walk.LineEdit
	tunnelDelayJitterCheck      *walk.CheckBox
	tunnelTcpWindowClampEdit    *walk.LineEdit
	tunnelCustomUserAgentEdit   *walk.LineEdit
	tunnelFakePacketInjectCheck *walk.CheckBox
	tunnelFakePacketTtlEdit     *walk.LineEdit
	tunnelOutOfWindowCheck      *walk.CheckBox
	tunnelOutOfWindowSeqOffsetEdit *walk.LineEdit
	tunnelDecoySniPoolEdit      *walk.LineEdit
	tunnelCovertModeCombo       *walk.ComboBox
	tunnelCovertGsaUrlEdit      *walk.LineEdit
	tunnelCovertGsaKeyEdit      *walk.LineEdit
	tunnelCovertServerlessUrlEdit *walk.LineEdit
	tunnelCovertDnsDomainEdit     *walk.LineEdit
	tunnelCovertSocketProtectPathEdit *walk.LineEdit
	tunnelMobileAssetsCheck          *walk.CheckBox
	tunnelZygiskHideCheck            *walk.CheckBox
	tunnelHardenedTlsCheck           *walk.CheckBox
	tunnelUpgenCheck                 *walk.CheckBox
	tunnelUpgenSeedEdit              *walk.LineEdit
	tunnelUpgenEntropyCheck          *walk.CheckBox
	tunnelUpgenQuicRateEdit          *walk.LineEdit
	tunnelStegoCheck                 *walk.CheckBox
	tunnelStegoModeCombo             *walk.ComboBox
	tunnelStegoDecoyImageEdit        *walk.LineEdit
	tunnelStegoWebRTCSDPCheck        *walk.CheckBox
	tunnelStatusLabel          *walk.Label
	tunnelActiveCheck          *walk.CheckBox
	tunnelLogText              *walk.TextEdit

	socksListener net.Listener
	socksRunning  bool
	socksCancel   context.CancelFunc

	tunActiveCheck     *walk.CheckBox
	tunDeviceNameEdit  *walk.LineEdit
	tunProxyAddrEdit   *walk.LineEdit
	tunSplitTunnelEdit *walk.LineEdit
	tunStatusLabel     *walk.Label

	torStartBtn        *walk.PushButton
	torStopBtn         *walk.PushButton
	torStatusLabel     *walk.Label
	psiphonStartBtn    *walk.PushButton
	psiphonStopBtn     *walk.PushButton
	psiphonStatusLabel *walk.Label
	psiphonChainCheck  *walk.CheckBox

	proxyRegHost    *walk.LineEdit
	proxyRegPort    *walk.LineEdit
	proxyRegNotes   *walk.LineEdit
	proxyRegType    *walk.ComboBox
	proxyRegAuth    *walk.CheckBox
	proxyRegUser    *walk.LineEdit
	proxyRegPass    *walk.LineEdit
	proxyDirOutput  *walk.TextEdit
	proxySelectedId *walk.LineEdit

	tgChannelEdit        *walk.LineEdit
	tgStatusLabel        *walk.Label
	tgResultEdit         *walk.TextEdit
	tgChannelPresetCombo *walk.ComboBox
	lastTgProxies        []struct {
		Host   string `json:"host"`
		Port   int    `json:"port"`
		Secret string `json:"secret"`
		PingMs int    `json:"ping_ms"`
	}

	lastStatus  nativeSystemStatus
	lastCaps    nativeCapabilityResponse
	lastHistory nativeHistoryResponse
	lastRefresh time.Time
}

func (s *nativeShell) run(cancel context.CancelFunc) {
	defer cancel()

	err := MainWindow{
		AssignTo: &s.mw,
		Title:    "LumiNet Native Operations Console",
		MinSize:  Size{Width: 1220, Height: 800},
		Size:     Size{Width: 1440, Height: 920},
		Layout:   VBox{MarginsZero: true, SpacingZero: true},
		Children: []Widget{
			s.commandCenter(),
			Composite{
				Layout:  HBox{Margins: Margins{Left: 10, Top: 6, Right: 10, Bottom: 6}},
				MaxSize: Size{Height: 42},
				Children: []Widget{
					Label{AssignTo: &s.statusLine, Text: "Starting native shell..."},
				},
			},
		},
	}.Create()
	if err != nil {
		fmt.Printf("Native GUI failed: %v\n", err)
		return
	}

	if s.autoRefresh != nil {
		s.autoRefresh.SetChecked(true)
	}
	if s.targetEdit != nil {
		s.targetEdit.SetText("cloudflare.com")
	}
	if s.diagnosticsMode != nil {
		s.diagnosticsMode.SetCurrentIndex(0)
	}
	if s.cockpitScenario != nil {
		s.cockpitScenario.SetCurrentIndex(0)
	}
	s.applyWorkbenchDefaults()
	time.AfterFunc(350*time.Millisecond, s.refreshAll)
	time.AfterFunc(2*time.Second, s.refreshAll)
	go s.refreshLoop()
	s.refreshEvasionStatus()
	s.startEvasionLogLoop()

	// Initialize global hotkey listener to start/stop the local proxy layer via Ctrl+Alt+P
	hotkeyCtx, hotkeyCancel := context.WithCancel(context.Background())
	defer hotkeyCancel()
	startGlobalHotkeyListener(hotkeyCtx, func() {
		if s.mw != nil {
			s.mw.Synchronize(func() {
				if s.tunnelActiveCheck != nil {
					newChecked := !s.tunnelActiveCheck.Checked()
					s.tunnelActiveCheck.SetChecked(newChecked)
					s.toggleEvasionTunnel()
				} else {
					// Fallback direct API toggling if GUI checkbox is not initialized
					go func() {
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
						}
						var req evasionRequest
						if err := s.getJSON("/api/system/evasion-tunnel", &req); err == nil {
							req.Enabled = !req.Enabled
							if payload, err := json.Marshal(req); err == nil {
								var resp struct {
									Status  string `json:"status"`
									Enabled bool   `json:"enabled"`
								}
								_ = s.postJSON("/api/system/evasion-tunnel", payload, &resp)
							}
						}
					}()
				}
			})
		}
	})

	s.mw.Run()
}

func (s *nativeShell) header() Widget {
	return Composite{
		Layout:  HBox{Margins: Margins{Left: 14, Top: 12, Right: 14, Bottom: 12}},
		MaxSize: Size{Height: 76},
		Children: []Widget{
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					Label{Text: "LumiNet", Font: Font{PointSize: 18, Bold: true}},
					Label{Text: "Desktop control plane for scans, proxy ops, diagnostics, and ported capability ledgers"},
				},
			},
			HSpacer{},
			PushButton{Text: "Refresh", MaxSize: Size{Width: 110}, OnClicked: s.refreshAll},
			PushButton{Text: "API Health", MaxSize: Size{Width: 110}, OnClicked: s.healthCheck},
			PushButton{Text: "Support", MaxSize: Size{Width: 110}, OnClicked: s.showDonationDialog},
		},
	}
}

func (s *nativeShell) commandCenter() Widget {
	return Composite{
		Layout: VBox{MarginsZero: true, SpacingZero: true},
		Children: []Widget{
			CustomWidget{
				AssignTo:            &s.cockpitWidget,
				MinSize:             Size{Width: 1180, Height: 680},
				StretchFactor:       1,
				InvalidatesOnResize: true,
				PaintMode:           PaintBuffered,
				PaintPixels:         s.paintCockpit,
			},
			Composite{
				Layout:  HBox{Margins: Margins{Left: 18, Top: 8, Right: 18, Bottom: 10}, Spacing: 10},
				MaxSize: Size{Height: 56},
				Children: []Widget{
					ComboBox{
						AssignTo: &s.cockpitScenario,
						Model: []string{
							"Diagnostic: HTTP/TLS",
							"Scan: ICMP sweep",
							"Scan: TCP ports",
							"Scan: DNS records",
							"Scan: SNI reachability",
						},
						MaxSize: Size{Width: 180},
					},
					LineEdit{AssignTo: &s.cockpitTarget, Text: "cloudflare.com", MaxSize: Size{Width: 210}},
					LineEdit{AssignTo: &s.cockpitPorts, Text: "80,443,8443", MaxSize: Size{Width: 118}},
					PushButton{Text: "Run workflow", OnClicked: s.runCockpitWorkflow},
					PushButton{Text: "Runbook", OnClicked: s.generateRunbook},
					PushButton{Text: "Workbench", OnClicked: s.openWorkbench},
					HSpacer{},
					PushButton{Text: "Refresh", OnClicked: s.refreshAll},
					PushButton{Text: "Export history", OnClicked: func() { s.openPath("/api/export") }},
					PushButton{Text: "API health", OnClicked: s.healthCheck},
				},
			},
		},
	}
}

func (s *nativeShell) openWorkbench() {
	if s.workbench != nil && s.workbench.Handle() != 0 {
		s.workbench.Show()
		_ = s.workbench.SetFocus()
		return
	}
	err := MainWindow{
		AssignTo: &s.workbench,
		Title:    "LumiNet Native Workbench",
		MinSize:  Size{Width: 1180, Height: 760},
		Size:     Size{Width: 1320, Height: 860},
		Layout:   VBox{MarginsZero: true, SpacingZero: true},
		Children: []Widget{
			TabWidget{
				Pages: []TabPage{
					s.dashboardPage(),
					s.runbookPage(),
					s.interfacesPage(),
					s.operationsPage(),
					s.scansPage(),
					s.parserPage(),
					s.proxyPage(),
					s.systemPage(),
					s.maintenancePage(),
					s.jobsPage(),
					s.historyPage(),
					s.actionsPage(),
					s.dnsSecurityPage(),
					s.speedBenchmarkPage(),
					s.dnsBenchmarkPage(),
					s.subnetScannerPage(),
					s.wgAuditorPage(),
					s.censorshipAuditorPage(),
					s.captivePortalPage(),
					s.evasionAuditorPage(),
					s.domainFrontingPage(),
					s.echAuditorPage(),
					s.geoIPPage(),
					s.bypassWizardPage(),
					s.bypassTunnelPage(),
					s.telegramPage(),
					s.provisionPage(),
					s.subscriptionPage(),
					s.optionsPage(),
				},
			},
		},
	}.Create()
	if err != nil {
		s.setStatus("Workbench failed: " + err.Error())
		return
	}
	s.applyWorkbenchDefaults()
	s.refreshAll()
	s.workbench.Show()
}

func (s *nativeShell) applyWorkbenchDefaults() {
	if s.autoRefresh != nil {
		s.autoRefresh.SetChecked(true)
	}
	if s.targetEdit != nil {
		s.targetEdit.SetText("cloudflare.com")
	}
	if s.dnsSecDomain != nil && s.dnsSecDomain.Text() == "" {
		s.dnsSecDomain.SetText("google.com")
	}
	if s.dnsSecUdpServer != nil && s.dnsSecUdpServer.Text() == "" {
		s.dnsSecUdpServer.SetText("8.8.8.8")
	}
	if s.dnsSecDohServer != nil && s.dnsSecDohServer.Text() == "" {
		s.dnsSecDohServer.SetText("https://cloudflare-dns.com/dns-query")
	}
	if s.dnsSecDotServer != nil && s.dnsSecDotServer.Text() == "" {
		s.dnsSecDotServer.SetText("one.one.one.one:853")
	}
	if s.speedServerEdit != nil && s.speedServerEdit.Text() == "" {
		s.speedServerEdit.SetText("speedtest.tele2.net:80")
	}
	if s.speedTimeoutEdit != nil && s.speedTimeoutEdit.Text() == "" {
		s.speedTimeoutEdit.SetText("5")
	}
	if s.dnsBenchDomain != nil && s.dnsBenchDomain.Text() == "" {
		s.dnsBenchDomain.SetText("google.com")
	}
	// Auto-detect system active interface IP and default to its /24 CIDR
	cidr := "192.168.1.0/24"
	if len(s.lastStatus.Interfaces) > 0 {
		for _, iface := range s.lastStatus.Interfaces {
			for _, ip := range iface.IPs {
				if strings.Contains(ip, ".") && !strings.HasPrefix(ip, "127.") {
					parts := strings.Split(ip, ".")
					if len(parts) == 4 {
						cidr = fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
						break
					}
				}
			}
		}
	}
	if s.subnetCidrEdit != nil && s.subnetCidrEdit.Text() == "" {
		s.subnetCidrEdit.SetText(cidr)
	}
	if s.subnetPortsEdit != nil && s.subnetPortsEdit.Text() == "" {
		s.subnetPortsEdit.SetText("21,22,23,53,80,443,445,3389,8080")
	}
	if s.subnetConcurrency != nil && s.subnetConcurrency.Text() == "" {
		s.subnetConcurrency.SetText("100")
	}
	if s.subnetTimeoutEdit != nil && s.subnetTimeoutEdit.Text() == "" {
		s.subnetTimeoutEdit.SetText("1000")
	}
	if s.subnetScanMode != nil && s.subnetScanMode.CurrentIndex() < 0 {
		s.subnetScanMode.SetCurrentIndex(0)
	}
	if s.wgTargetEdit != nil && s.wgTargetEdit.Text() == "" {
		s.wgTargetEdit.SetText("162.159.192.1")
	}
	if s.wgPortEdit != nil && s.wgPortEdit.Text() == "" {
		s.wgPortEdit.SetText("2408")
	}
	if s.wgTimeoutEdit != nil && s.wgTimeoutEdit.Text() == "" {
		s.wgTimeoutEdit.SetText("2000")
	}
	if s.wgPaddingEdit != nil && s.wgPaddingEdit.Text() == "" {
		s.wgPaddingEdit.SetText("0")
	}
	if s.censorshipTargetEdit != nil && s.censorshipTargetEdit.Text() == "" {
		s.censorshipTargetEdit.SetText("google.com")
	}
	if s.censorshipPortEdit != nil && s.censorshipPortEdit.Text() == "" {
		s.censorshipPortEdit.SetText("443")
	}
	socksPort := "10888"
	if s.tunnelPortEdit != nil && s.tunnelPortEdit.Text() != "" {
		socksPort = strings.TrimSpace(s.tunnelPortEdit.Text())
	}
	if s.censorshipProxyEdit != nil && s.censorshipProxyEdit.Text() == "" {
		s.censorshipProxyEdit.SetText("127.0.0.1:" + socksPort)
	}
	if s.captiveTimeoutEdit != nil && s.captiveTimeoutEdit.Text() == "" {
		s.captiveTimeoutEdit.SetText("3000")
	}
	if s.evasionHostEdit != nil && s.evasionHostEdit.Text() == "" {
		s.evasionHostEdit.SetText("google.com")
	}
	if s.evasionPortEdit != nil && s.evasionPortEdit.Text() == "" {
		s.evasionPortEdit.SetText("80")
	}
	if s.evasionDelayEdit != nil && s.evasionDelayEdit.Text() == "" {
		s.evasionDelayEdit.SetText("20")
	}
	if s.frontingTargetEdit != nil && s.frontingTargetEdit.Text() == "" {
		s.frontingTargetEdit.SetText("https://ajax.aspnetcdn.com/")
	}
	if s.frontingSniEdit != nil && s.frontingSniEdit.Text() == "" {
		s.frontingSniEdit.SetText("microsoft.com")
	}
	if s.frontingPaddingEdit != nil && s.frontingPaddingEdit.Text() == "" {
		s.frontingPaddingEdit.SetText("0")
	}
	if s.echTargetEdit != nil && s.echTargetEdit.Text() == "" {
		s.echTargetEdit.SetText("cloudflare.com")
	}
	if s.echPortEdit != nil && s.echPortEdit.Text() == "" {
		s.echPortEdit.SetText("443")
	}
	if s.echDnsEdit != nil && s.echDnsEdit.Text() == "" {
		s.echDnsEdit.SetText("1.1.1.1")
	}
	if s.echSniEdit != nil && s.echSniEdit.Text() == "" {
		s.echSniEdit.SetText("cloudflare.com")
	}
	if s.echDohEdit != nil && s.echDohEdit.Text() == "" {
		s.echDohEdit.SetText("https://cloudflare-dns.com/dns-query")
	}
	if s.diagnosticsMode != nil && s.diagnosticsMode.CurrentIndex() < 0 {
		s.diagnosticsMode.SetCurrentIndex(0)
	}
	if s.scanMode != nil && s.scanMode.CurrentIndex() < 0 {
		s.scanMode.SetCurrentIndex(0)
	}
	if s.scanTarget != nil && strings.TrimSpace(s.scanTarget.Text()) == "" {
		s.scanTarget.SetText("cloudflare.com")
	}
	if s.scanPorts != nil && strings.TrimSpace(s.scanPorts.Text()) == "" {
		s.scanPorts.SetText("80,443,8443")
	}
	if s.scanDNSServer != nil && strings.TrimSpace(s.scanDNSServer.Text()) == "" {
		s.scanDNSServer.SetText("1.1.1.1")
	}
	if s.scanRecordType != nil && s.scanRecordType.CurrentIndex() < 0 {
		s.scanRecordType.SetCurrentIndex(0)
	}
	if s.scanTimeout != nil && strings.TrimSpace(s.scanTimeout.Text()) == "" {
		s.scanTimeout.SetText("3000")
	}
	if s.scanConcurrency != nil && strings.TrimSpace(s.scanConcurrency.Text()) == "" {
		s.scanConcurrency.SetText("100")
	}
	if s.proxyTestURL != nil && strings.TrimSpace(s.proxyTestURL.Text()) == "" {
		s.proxyTestURL.SetText("http://cp.cloudflare.com/")
	}
	if s.proxyTimeout != nil && strings.TrimSpace(s.proxyTimeout.Text()) == "" {
		s.proxyTimeout.SetText("10")
	}
	if s.ddnsInterval != nil && strings.TrimSpace(s.ddnsInterval.Text()) == "" {
		s.ddnsInterval.SetText("30")
	}
	if s.geoIPTargetEdit != nil && s.geoIPTargetEdit.Text() == "" {
		s.geoIPTargetEdit.SetText("8.8.8.8")
	}
	if s.wizardTargetEdit != nil && s.wizardTargetEdit.Text() == "" {
		s.wizardTargetEdit.SetText("google.com")
	}
	if s.tunnelPortEdit != nil && s.tunnelPortEdit.Text() == "" {
		s.tunnelPortEdit.SetText("10888")
	}
	if s.tunnelSplitBytesEdit != nil && s.tunnelSplitBytesEdit.Text() == "" {
		s.tunnelSplitBytesEdit.SetText("2")
	}
	if s.tunnelDelayEdit != nil && s.tunnelDelayEdit.Text() == "" {
		s.tunnelDelayEdit.SetText("20")
	}
	if s.tunnelCovertServerlessUrlEdit != nil && s.tunnelCovertServerlessUrlEdit.Text() == "" {
		s.tunnelCovertServerlessUrlEdit.SetText("https://example.workers.dev")
	}
	if s.tunnelCovertDnsDomainEdit != nil && s.tunnelCovertDnsDomainEdit.Text() == "" {
		s.tunnelCovertDnsDomainEdit.SetText("tunnel.example.com")
	}
	if s.tunnelHostCheck != nil {
		s.tunnelHostCheck.SetChecked(true)
	}
	if s.tunnelAutoSniCheck != nil {
		s.tunnelAutoSniCheck.SetChecked(true)
	}
	if s.tunnelTlsRecordSplitCheck != nil {
		s.tunnelTlsRecordSplitCheck.SetChecked(true)
	}
	if s.tunnelPacketsCombo != nil {
		_ = s.tunnelPacketsCombo.SetCurrentIndex(0)
	}
	if s.tunnelMinLenEdit != nil && s.tunnelMinLenEdit.Text() == "" {
		s.tunnelMinLenEdit.SetText("0")
	}
	if s.tunnelMaxLenEdit != nil && s.tunnelMaxLenEdit.Text() == "" {
		s.tunnelMaxLenEdit.SetText("0")
	}
	if s.tgChannelEdit != nil && s.tgChannelEdit.Text() == "" {
		s.tgChannelEdit.SetText("ProxyMTProto")
	}
	if s.dnsSecDohPresetCombo != nil && s.dnsSecDohPresetCombo.CurrentIndex() < 0 {
		_ = s.dnsSecDohPresetCombo.SetCurrentIndex(0)
	}
	if s.tunnelDnsResolverEdit != nil && s.tunnelDnsResolverEdit.Text() == "" {
		s.tunnelDnsResolverEdit.SetText("https://dns.quad9.net/dns-query")
	}
	if s.tunnelDnsForwarderCheck != nil {
		s.tunnelDnsForwarderCheck.SetChecked(true)
	}
	if s.tunnelDnsForwarderPortEdit != nil && s.tunnelDnsForwarderPortEdit.Text() == "" {
		s.tunnelDnsForwarderPortEdit.SetText("10053")
	}
	if s.tunnelUpgenCheck != nil {
		s.tunnelUpgenCheck.SetChecked(false)
	}
	if s.tunnelUpgenSeedEdit != nil && s.tunnelUpgenSeedEdit.Text() == "" {
		s.tunnelUpgenSeedEdit.SetText("4a7b9e02c1f8d4")
	}
	if s.tunnelUpgenEntropyCheck != nil {
		s.tunnelUpgenEntropyCheck.SetChecked(true)
	}
	if s.tunnelUpgenQuicRateEdit != nil && s.tunnelUpgenQuicRateEdit.Text() == "" {
		s.tunnelUpgenQuicRateEdit.SetText("50")
	}
	if s.tunnelStegoCheck != nil {
		s.tunnelStegoCheck.SetChecked(false)
	}
	if s.tunnelStegoModeCombo != nil {
		_ = s.tunnelStegoModeCombo.SetCurrentIndex(0)
	}
	if s.tunnelStegoDecoyImageEdit != nil && s.tunnelStegoDecoyImageEdit.Text() == "" {
		s.tunnelStegoDecoyImageEdit.SetText("/var/lib/luminet/decoy.png")
	}
	if s.tunnelStegoWebRTCSDPCheck != nil {
		s.tunnelStegoWebRTCSDPCheck.SetChecked(true)
	}
	if s.speedPresetCombo != nil && s.speedPresetCombo.CurrentIndex() < 0 {
		_ = s.speedPresetCombo.SetCurrentIndex(0)
	}
	if s.wgPresetCombo != nil && s.wgPresetCombo.CurrentIndex() < 0 {
		_ = s.wgPresetCombo.SetCurrentIndex(0)
	}
	if s.tgChannelPresetCombo != nil && s.tgChannelPresetCombo.CurrentIndex() < 0 {
		_ = s.tgChannelPresetCombo.SetCurrentIndex(0)
	}
	if s.rewriteNameTemplate != nil && s.rewriteNameTemplate.Text() == "" {
		s.rewriteNameTemplate.SetText("{name} | {ip}")
	}
	if s.defaultTimeoutEdit != nil && s.defaultTimeoutEdit.Text() == "" {
		s.defaultTimeoutEdit.SetText("4000")
	}
	if s.maxConcurrencyEdit != nil && s.maxConcurrencyEdit.Text() == "" {
		s.maxConcurrencyEdit.SetText("50")
	}
	if s.debugLogsCheck != nil {
		s.debugLogsCheck.SetChecked(true)
	}
	if s.dnsResolutionCheck != nil {
		s.dnsResolutionCheck.SetChecked(true)
	}
	if s.tunDeviceNameEdit != nil && s.tunDeviceNameEdit.Text() == "" {
		s.tunDeviceNameEdit.SetText("luminet-tun0")
	}
	if s.tunProxyAddrEdit != nil && s.tunProxyAddrEdit.Text() == "" {
		s.tunProxyAddrEdit.SetText("127.0.0.1:10888")
	}
	if s.tunnelPresetCombo != nil && s.tunnelPresetCombo.CurrentIndex() < 0 {
		_ = s.tunnelPresetCombo.SetCurrentIndex(0)
	}
	if s.proxyRegType != nil && s.proxyRegType.CurrentIndex() < 0 {
		_ = s.proxyRegType.SetCurrentIndex(1) // SOCKS5 default
	}
}

// Tab Pages and Custom Panel components have been refactored and moved to gui_pages.go

func (s *nativeShell) showDonationDialog() {
	var dlg *walk.Dialog
	var acceptPB *walk.PushButton

	err := Dialog{
		AssignTo:      &dlg,
		Title:         "Support & Donation Wallets",
		MinSize:       Size{Width: 540, Height: 260},
		Layout:        VBox{Margins: Margins{Left: 16, Top: 16, Right: 16, Bottom: 16}},
		DefaultButton: &acceptPB,
		Children: []Widget{
			Label{
				Text: "If you find LumiNet and the integrated scanning/evasion tools useful, please consider supporting the project and its upstream contributors (patterniha, Musixal, and others).",
				Font: Font{PointSize: 10},
			},
			VSpacer{Size: 10},
			GroupBox{
				Title:  "Donation Wallets",
				Layout: Grid{Columns: 2, Spacing: 10},
				Children: []Widget{
					Label{Text: "USDT (BEP20):", Font: Font{Bold: true}},
					Composite{
						Layout: HBox{MarginsZero: true, Spacing: 6},
						Children: []Widget{
							LineEdit{Text: "0x76a768B53Ca77B43086946315f0BDF21156bF424", ReadOnly: true},
							PushButton{Text: "Copy", MaxSize: Size{Width: 60}, OnClicked: func() {
								_ = walk.Clipboard().SetText("0x76a768B53Ca77B43086946315f0BDF21156bF424")
								s.setStatus("USDT (BEP20) address copied to clipboard!")
							}},
						},
					},

					Label{Text: "USDT (TRC20):", Font: Font{Bold: true}},
					Composite{
						Layout: HBox{MarginsZero: true, Spacing: 6},
						Children: []Widget{
							LineEdit{Text: "TU5gKvKqcXPn8itp1DouBCwcqGHMemBm8o", ReadOnly: true},
							PushButton{Text: "Copy", MaxSize: Size{Width: 60}, OnClicked: func() {
								_ = walk.Clipboard().SetText("TU5gKvKqcXPn8itp1DouBCwcqGHMemBm8o")
								s.setStatus("USDT (TRC20) address copied to clipboard!")
							}},
						},
					},

					Label{Text: "TON:", Font: Font{Bold: true}},
					Composite{
						Layout: HBox{MarginsZero: true, Spacing: 6},
						Children: []Widget{
							LineEdit{Text: "UQAc-mZB3y7uxWHKiMmq0ORZEYgycWDWZ4V1k73HsXvTJx-i", ReadOnly: true},
							PushButton{Text: "Copy", MaxSize: Size{Width: 60}, OnClicked: func() {
								_ = walk.Clipboard().SetText("UQAc-mZB3y7uxWHKiMmq0ORZEYgycWDWZ4V1k73HsXvTJx-i")
								s.setStatus("TON address copied to clipboard!")
							}},
						},
					},
				},
			},
			VSpacer{Size: 10},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					HSpacer{},
					PushButton{
						AssignTo:  &acceptPB,
						Text:      "Close",
						OnClicked: func() { dlg.Accept() },
					},
				},
			},
		},
	}.Create(s.mw)
	if err != nil {
		s.setStatus(fmt.Sprintf("Failed to show support dialog: %v", err))
		return
	}
	dlg.Run()
}
