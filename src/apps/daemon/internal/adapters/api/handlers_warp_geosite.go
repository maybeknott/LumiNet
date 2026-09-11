package api

import (
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/analysis/diagnostics"
	scanner_pkg "github.com/maybeknott/luminet/internal/analysis/scanner"
	"github.com/maybeknott/luminet/internal/integrations/sub"
	"github.com/maybeknott/luminet/internal/networking/dns"
	"github.com/maybeknott/luminet/internal/networking/routing"
	proxyconfig "github.com/maybeknott/luminet/internal/networking/proxyconfig"
	"github.com/maybeknott/luminet/internal/runtime/warp"
)

type WarpNoiseRequest struct {
	TargetAddr string `json:"target_addr"`
	NoiseCount int    `json:"noise_count"`
}

type GeoSiteMatchRequest struct {
	Domain string `json:"domain"`
}

type SmartDNSRequest struct {
	Domain string `json:"domain"`
}

type CDNFrontingRequest struct {
	CustomIPList string `json:"custom_ip_list"`
	CustomSNI    string `json:"custom_sni"`
}

type CleanIPProbeRequest struct {
	SampleCount int `json:"sample_count"`
}

type IPSecurityRequest struct {
	IP      string `json:"ip"`
	ASN     int    `json:"asn"`
	OrgName string `json:"org_name"`
}

type SNISpoofingRequest struct {
	Enabled           bool   `json:"enabled"`
	TargetSNI         string `json:"target_sni"`
	FakeSNI           string `json:"fake_sni"`
	InjectWrongSeq    bool   `json:"inject_wrong_seq"`
	FragmentationSize int    `json:"fragmentation_size"`
}

type DPIDesyncRequest struct {
	Enabled        bool   `json:"enabled"`
	Mode           string `json:"mode"`
	SplitPosition  int    `json:"split_position"`
	HTTPCaseRandom bool   `json:"http_case_random"`
}

type DoHBlocklistRequest struct {
	Domain string `json:"domain"`
}

type CDNDiscoverRequest struct {
	Hostname string `json:"hostname"`
}

type AntiBotInspectRequest struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	Body       string              `json:"body"`
}

type GDriveTunnelRequest struct {
	Enabled      bool   `json:"enabled"`
	FolderID     string `json:"folder_id"`
	AccessToken  string `json:"access_token"`
	PayloadChunk string `json:"payload_chunk"`
}

// HandleWarpNoise handles POST /api/system/warp-noise
func (s *Server) HandleWarpNoise(c *gin.Context) {
	var req WarpNoiseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := warp.ValidateNoiseCount(req.NoiseCount); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := warp.InjectNoise(c.Request.Context(), req.TargetAddr, req.NoiseCount)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":      "success",
		"target_addr": req.TargetAddr,
		"noise_sent":  req.NoiseCount,
	})
}

// HandleGeoSiteMatch handles POST /api/system/geosite-match
func (s *Server) HandleGeoSiteMatch(c *gin.Context) {
	var req GeoSiteMatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	router, err := routing.NewRouter()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	action, category := router.Lookup(req.Domain)
	actionStr := "proxy"
	switch action {
	case routing.RouteDirect:
		actionStr = "direct"
	case routing.RouteProxy:
		actionStr = "proxy"
	case routing.RouteBlock:
		actionStr = "block"
	case routing.RouteDNS:
		actionStr = "dns"
	}

	c.JSON(http.StatusOK, gin.H{
		"domain":      req.Domain,
		"disposition": actionStr,
		"category":    category,
	})
}

// HandleSmartDNS handles POST /api/system/smart-dns
func (s *Server) HandleSmartDNS(c *gin.Context) {
	var req SmartDNSRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	addrs, err := dns.ResolveDomain(c.Request.Context(), req.Domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"domain":    req.Domain,
		"addresses": addrs,
	})
}

// HandleCDNFronting handles POST /api/system/cdn-fronting
func (s *Server) HandleCDNFronting(c *gin.Context) {
	var req CDNFrontingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	overrides := proxyconfig.BuildCDNDialOverrides(req.CustomIPList, req.CustomSNI)
	c.JSON(http.StatusOK, gin.H{
		"status":    "success",
		"overrides": overrides,
	})
}

// HandleCleanIPProbe handles POST /api/system/clean-ip-probe
func (s *Server) HandleCleanIPProbe(c *gin.Context) {
	var req CleanIPProbeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		req.SampleCount = 10
	}
	if req.SampleCount <= 0 {
		req.SampleCount = 10
	}

	found, pool := diagnostics.ProbeCleanCloudflareIPs(c.Request.Context(), req.SampleCount, 2*time.Second)

	c.JSON(http.StatusOK, gin.H{
		"status":     "success",
		"clean_ips":  found,
		"total_pool": pool,
	})
}

// HandleIPSecurity handles POST /api/system/ip-security
func (s *Server) HandleIPSecurity(c *gin.Context) {
	var req IPSecurityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	report := diagnostics.AnalyzeIPSecurity(c.Request.Context(), req.IP, req.ASN, req.OrgName)
	c.JSON(http.StatusOK, report)
}

// HandleSNISpoofing handles POST /api/system/sni-spoofing
func (s *Server) HandleSNISpoofing(c *gin.Context) {
	var req SNISpoofingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	unavailableAdvancedCapability(c, "POST /sni-spoofing")
}

// HandleDPIDesync handles POST /api/system/dpi-desync
func (s *Server) HandleDPIDesync(c *gin.Context) {
	var req DPIDesyncRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	unavailableAdvancedCapability(c, "POST /dpi-desync")
}

// HandleDoHBlocklist handles POST /api/system/doh-blocklist
func (s *Server) HandleDoHBlocklist(c *gin.Context) {
	var req DoHBlocklistRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	blocked := dns.IsDoHBlockedDomain(req.Domain)
	c.JSON(http.StatusOK, gin.H{
		"domain":        req.Domain,
		"blocked":       blocked,
		"blocked_count": map[bool]int{false: 0, true: 1}[blocked],
		"scope":         "request",
	})
}

// HandleCDNDiscover handles POST /api/system/cdn-discover
func (s *Server) HandleCDNDiscover(c *gin.Context) {
	var req CDNDiscoverRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cleanIPs, err := diagnostics.NewCDNDiscoveryEngine().DiscoverCleanIPs(c.Request.Context(), req.Hostname, nil, "")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":    "success",
		"hostname":  req.Hostname,
		"clean_ips": cleanIPs,
	})
}

// HandleAntiBotInspect handles POST /api/system/antibot-inspect
func (s *Server) HandleAntiBotInspect(c *gin.Context) {
	var req AntiBotInspectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	res := diagnostics.NewAntiBotDetector().InspectResponse(req.StatusCode, req.Headers, []byte(req.Body))
	c.JSON(http.StatusOK, res)
}

// HandleGDriveTunnel handles POST /api/system/gdrive-tunnel
func (s *Server) HandleGDriveTunnel(c *gin.Context) {
	var req GDriveTunnelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	unavailableAdvancedCapability(c, "POST /gdrive-tunnel")
}

// HandleMasterTelemetry handles GET /api/system/master-telemetry
func (s *Server) HandleMasterTelemetry(c *gin.Context) {
	unavailableAdvancedCapability(c, "GET /master-telemetry")
}

type SubParseRequest struct {
	RawContent string `json:"raw_content"`
}

// HandleSubscriptionParse handles POST /api/system/subscription-parse
func (s *Server) HandleSubscriptionParse(c *gin.Context) {
	var req SubParseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	configs, err := sub.ParseContent(req.RawContent)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	nodes := make([]gin.H, 0, len(configs))
	for _, cfg := range configs {
		nodes = append(nodes, gin.H{
			"protocol": string(cfg.Protocol),
			"address":  cfg.Address,
			"port":     strconv.Itoa(cfg.Port),
			"remarks":  cfg.Name,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"nodes":  nodes,
	})
}

// HandleVPNState handles GET /api/system/vpn-state
func (s *Server) HandleVPNState(c *gin.Context) {
	unavailableAdvancedCapability(c, "GET /vpn-state")
}

// HandleGetDeviceProfile handles GET /api/system/device-profile
func (s *Server) HandleGetDeviceProfile(c *gin.Context) {
	unavailableAdvancedCapability(c, "GET /device-profile")
}

// HandleSetDeviceProfile handles POST /api/system/device-profile
func (s *Server) HandleSetDeviceProfile(c *gin.Context) {
	var req struct {
		DeviceModel string `json:"device_model"`
		OSVersion   string `json:"os_version"`
		HardwareID  string `json:"hardware_id"`
		AndroidID   string `json:"android_id"`
		CpuInfo     string `json:"cpu_info"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	unavailableAdvancedCapability(c, "POST /device-profile")
}

// HandleWarpRegister handles POST /api/system/warp-register
func (s *Server) HandleWarpRegister(c *gin.Context) {
	key, err := warp.RegisterWarpAccountWithClient(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, struct {
		IPv4       string `json:"ipv4"`
		IPv6       string `json:"ipv6"`
		Reserved   []int  `json:"reserved"`
		PublicKey  string `json:"public_key"`
		PrivateKey string `json:"private_key"`
		ClientID   string `json:"client_id"`
	}{
		IPv4:       key.Address,
		IPv6:       key.IPv6Address,
		Reserved:   append([]int(nil), key.Reserved...),
		PublicKey:  key.PeerPublicKey,
		PrivateKey: key.PrivateKey,
		ClientID:   key.ClientID,
	})
}

type WarpScanRequest struct {
	Endpoints   []string `json:"endpoints"`
	Count       int      `json:"count"`
	Concurrency int      `json:"concurrency"`
	TimeoutMs   int      `json:"timeout_ms"`
	Attempts    int      `json:"attempts"`
	Ifpm        string   `json:"ifpm"`
	NoiseType   string   `json:"noise_type"`
	NoiseVal    string   `json:"noise_val"`
	NoiseCount  int      `json:"noise_count"`
}

// HandleWarpScan handles POST /api/system/warp-scan
func (s *Server) HandleWarpScan(c *gin.Context) {
	var req WarpScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	requestedCandidates := req.Count
	if len(req.Endpoints) > 0 {
		requestedCandidates = len(req.Endpoints)
	}
	if err := warp.ValidateScanLimits(requestedCandidates, req.Concurrency, time.Duration(req.TimeoutMs)*time.Millisecond, req.Attempts, req.NoiseCount); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	timeoutMs := req.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = 1500
	}
	scanner := warp.NewWarpScanner(warp.WarpScannerOptions{
		ConcurrentScanners:  req.Concurrency,
		ConnectionTimeout:   time.Duration(timeoutMs) * time.Millisecond,
		HandshakeTimeout:    time.Duration(timeoutMs) * time.Millisecond,
		AttemptsPerEndpoint: req.Attempts,
		Ipv4Mode:            true,
		UseNoise:            req.NoiseCount > 0,
		NoiseCount:          req.NoiseCount,
	})

	var candidateEndpoints []string
	if len(req.Endpoints) > 0 {
		candidateEndpoints = req.Endpoints
	} else {
		count := req.Count
		if count <= 0 {
			count = 60
		}
		for _, candidate := range scanner.GenerateCandidates(count) {
			candidateEndpoints = append(candidateEndpoints, candidate.String())
		}
	}

	validCandidates := make([]netip.AddrPort, 0, len(candidateEndpoints))
	results := make([]struct {
		Endpoint           string
		RTT                time.Duration
		Loss               float64
		Attempts           int
		SuccessfulAttempts int
		Error              error
	}, 0, len(candidateEndpoints))
	for _, endpoint := range candidateEndpoints {
		candidate, parseErr := netip.ParseAddrPort(endpoint)
		if parseErr != nil {
			results = append(results, struct {
				Endpoint           string
				RTT                time.Duration
				Loss               float64
				Attempts           int
				SuccessfulAttempts int
				Error              error
			}{Endpoint: endpoint, Loss: 100, Error: fmt.Errorf("invalid WARP endpoint: %w", parseErr)})
			continue
		}
		validCandidates = append(validCandidates, candidate)
	}

	if len(validCandidates) > 0 {
		for _, result := range scanner.Scan(c.Request.Context(), validCandidates) {
			var scanErr error
			if result.Error != "" {
				scanErr = fmt.Errorf("%s", result.Error)
			}
			results = append(results, struct {
				Endpoint           string
				RTT                time.Duration
				Loss               float64
				Attempts           int
				SuccessfulAttempts int
				Error              error
			}{
				Endpoint:           result.AddrPort.String(),
				RTT:                result.RTT,
				Loss:               result.Loss,
				Attempts:           result.Attempts,
				SuccessfulAttempts: result.SuccessfulAttempts,
				Error:              scanErr,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"results": results,
	})
}

type CloudflareDeployRequest struct {
	Email     string `json:"email"`
	Token     string `json:"token"`
	AccountID string `json:"account_id"`
	Name      string `json:"name"`
	Script    string `json:"script"`
}

// HandleCloudflareDeploy handles POST /api/system/cloudflare-deploy
func (s *Server) HandleCloudflareDeploy(c *gin.Context) {
	var req CloudflareDeployRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	deployer := scanner_pkg.NewCloudflareDeployer()
	err := deployer.DeployWorkerScript(
		c.Request.Context(),
		req.Email,
		req.Token,
		req.AccountID,
		req.Name,
		req.Script,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "success",
		"verified": false,
		"message":  "Cloudflare accepted the Worker script upload; runtime protocol behavior was not verified",
	})
}
