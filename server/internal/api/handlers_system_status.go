package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/ddns"
	"github.com/maybeknott/luminet/internal/proxy"
	"github.com/maybeknott/luminet/internal/system"
	"github.com/maybeknott/luminet/internal/utils"
)

// GetSystemStatus handles GET /api/system/status — returns real-time system metrics.
func (s *Server) GetSystemStatus(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	// Get memory stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Uptime
	uptime := int64(time.Since(s.startTime).Seconds())

	// Public IP (best effort)
	updater := ddns.NewUpdater("cloudflare", "", "") // provider doesn't matter for GetPublicIP
	publicIP, _ := updater.GetPublicIP(ctx)

	// Active jobs
	activeJobs := len(s.jobManager.GetActiveJobs())

	resourceStats := collectSystemResourceStats(ctx)
	usedRam := float64(m.Alloc) / 1024 / 1024 / 1024
	totalRam := 16.0
	ramUsage := int((usedRam / totalRam) * 100)
	if resourceStats.TotalRamGb > 0 {
		usedRam = resourceStats.UsedRamGb
		totalRam = resourceStats.TotalRamGb
		ramUsage = resourceStats.RamUsage
	}

	interfaces := make([]NetworkInterfaceResponse, 0)
	if active, err := system.GetActiveInterfaces(ctx); err == nil {
		for _, iface := range active {
			interfaces = append(interfaces, NetworkInterfaceResponse{
				Name:       iface.Name,
				MAC:        iface.MAC,
				IPs:        iface.IPs,
				Gateway:    iface.Gateway,
				IsWireless: iface.IsWireless,
				SSID:       iface.SSID,
			})
		}
	}

	dnsServers, _ := system.GetDNS(ctx, "")
	proxyStatus, _ := system.GetProxySettings(ctx)
	proxyActive := false
	if proxyStatus != nil {
		proxyActive = proxyStatus.Enabled
	}

	evasionActive, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _ := proxy.GetEvasionManager().Status()
	tunActive := system.GetTunRouterManager().IsRunning()

	upBytes, downBytes := proxy.GetEvasionTrafficStats()

	c.JSON(http.StatusOK, SystemStatusResponse{
		ApiConnected:  true,
		PublicIPv4:    publicIP,
		DNSServers:    dnsServers,
		ProxyActive:   proxyActive,
		EvasionActive: evasionActive,
		TunActive:     tunActive,
		Interfaces:    interfaces,
		UptimeSeconds: uptime,
		ActiveJobs:    activeJobs,
		CpuUsage:      resourceStats.CPUUsage,
		RamUsage:      ramUsage,
		UsedRamGb:     usedRam,
		TotalRamGb:    totalRam,
		DiskUsage:     resourceStats.DiskUsage,
		DiskFreeGb:    resourceStats.DiskFreeGb,
		UploadBytes:   upBytes,
		DownloadBytes: downBytes,
	})
}

type nativeResourceStats struct {
	CPUUsage   int
	RamUsage   int
	TotalRamGb float64
	UsedRamGb  float64
	DiskUsage  int
	DiskFreeGb int
}

func collectSystemResourceStats(ctx context.Context) nativeResourceStats {
	stats := nativeResourceStats{
		CPUUsage:   0,
		RamUsage:   0,
		TotalRamGb: 0,
		UsedRamGb:  0,
		DiskUsage:  0,
		DiskFreeGb: 0,
	}
	if runtime.GOOS != "windows" {
		return stats
	}

	const script = `
$cpu = [math]::Round((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average)
$os = Get-CimInstance Win32_OperatingSystem
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
[pscustomobject]@{
  cpu_usage = [int]$cpu
  total_ram_gb = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
  used_ram_gb = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1MB, 2)
  ram_usage = [int][math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100)
  disk_usage = [int][math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100)
  disk_free_gb = [int][math]::Round($disk.FreeSpace / 1GB)
} | ConvertTo-Json -Compress
`
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = utils.GetHideWindowSysProcAttr()
	out, err := cmd.Output()
	if err != nil {
		return stats
	}

	var payload struct {
		CPUUsage   int     `json:"cpu_usage"`
		TotalRamGb float64 `json:"total_ram_gb"`
		UsedRamGb  float64 `json:"used_ram_gb"`
		RamUsage   int     `json:"ram_usage"`
		DiskUsage  int     `json:"disk_usage"`
		DiskFreeGb int     `json:"disk_free_gb"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &payload); err != nil {
		return stats
	}

	stats.CPUUsage = clampPercent(payload.CPUUsage)
	stats.RamUsage = clampPercent(payload.RamUsage)
	stats.TotalRamGb = payload.TotalRamGb
	stats.UsedRamGb = payload.UsedRamGb
	stats.DiskUsage = clampPercent(payload.DiskUsage)
	stats.DiskFreeGb = payload.DiskFreeGb
	return stats
}

func clampPercent(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}
