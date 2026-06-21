package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/config"
	"github.com/maybeknott/luminet/internal/proxy"
	"github.com/maybeknott/luminet/internal/system"
)

// GetStartupStatus handles GET /api/system/startup — returns startup status.
func (s *Server) GetStartupStatus(c *gin.Context) {
	enabled := system.IsStartupEnabled()
	c.JSON(http.StatusOK, StartupStatusResponse{Enabled: enabled})
}

// SetStartup handles POST /api/system/startup — enables or disables auto-start.
func (s *Server) SetStartup(c *gin.Context) {
	var req SetStartupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var err error
	if req.Enabled {
		err = system.EnableStartup()
	} else {
		err = system.DisableStartup()
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"enabled": req.Enabled,
	})
}

// SystemSettings represents the settings payload for the frontend configuration.
type SystemSettings struct {
	DefaultTimeoutMs int                       `json:"default_timeout_ms"`
	MaxConcurrency   int                       `json:"max_concurrency"`
	DebugLogs        bool                      `json:"debug_logs"`
	DNSResolution    bool                      `json:"dns_resolution"`
	MihomoRules      config.MihomoRulesOptions `json:"mihomo_rules"`
	HostsOverride    bool                      `json:"hosts_override"`
}

// GetSystemSettings handles GET /api/system/settings — returns scanner & UI config values.
func (s *Server) GetSystemSettings(c *gin.Context) {
	cfg := s.configManager.Get()
	c.JSON(http.StatusOK, SystemSettings{
		DefaultTimeoutMs: cfg.DefaultTimeoutMs,
		MaxConcurrency:   cfg.MaxConcurrency,
		DebugLogs:        cfg.DebugLogs,
		DNSResolution:    cfg.DNSResolution,
		MihomoRules:      cfg.MihomoRules,
		HostsOverride:    cfg.HostsOverride,
	})
}

// SetSystemSettings handles POST /api/system/settings — saves scanner & UI config values.
func (s *Server) SetSystemSettings(c *gin.Context) {
	var req SystemSettings
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cfg := s.configManager.Get()
	cfg.DefaultTimeoutMs = req.DefaultTimeoutMs
	cfg.MaxConcurrency = req.MaxConcurrency
	cfg.DebugLogs = req.DebugLogs
	cfg.DNSResolution = req.DNSResolution
	cfg.MihomoRules = req.MihomoRules
	cfg.HostsOverride = req.HostsOverride

	proxy.GetEvasionManager().SetHostsOverride(req.HostsOverride)

	if err := s.configManager.Save(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
