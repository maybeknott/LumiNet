package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/geoip"
	"github.com/maybeknott/luminet/internal/jobs"
)

// RunDiagnostic handles POST /api/diagnostics — starts the diagnostic pipeline.
func (s *Server) RunDiagnostic(c *gin.Context) {
	var req struct {
		Target string `json:"target,omitempty"`
		Type   string `json:"type,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Target == "" {
		req.Target = "8.8.8.8:53"
	}
	if req.Type == "" {
		req.Type = "ping"
	}

	config, _ := json.Marshal(map[string]interface{}{
		"type":    req.Type,
		"target":  req.Target,
		"timeout": 10,
	})

	jobID := s.jobManager.CreateJob(jobs.JobTypeDiagnostic, string(config))
	if err := s.jobManager.StartJob(jobID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"id":         jobID,
		"status":     string(jobs.JobStatusRunning),
		"progress":   0,
		"created_at": time.Now(),
	})
}

// GetDiagnosticPhases handles GET /api/diagnostics/phases — lists available phases.
func (s *Server) GetDiagnosticPhases(c *gin.Context) {
	phases := []map[string]interface{}{
		{"number": 1, "name": "Connectivity", "description": "Basic TCP/ICMP connectivity check"},
		{"number": 2, "name": "DNS", "description": "DNS resolution latency audit"},
		{"number": 3, "name": "TLS", "description": "TLS handshake inspection"},
		{"number": 4, "name": "HTTP", "description": "HTTP response time audit"},
		{"number": 5, "name": "SNI", "description": "SNI blocking detection"},
		{"number": 6, "name": "Speed", "description": "Throughput measurement"},
		{"number": 7, "name": "Reliability (ARQ)", "description": "Sliding-window reliable UDP diagnostic benchmark"},
		{"number": 8, "name": "Browser Stealth", "description": "Browser fingerprinting & anti-fingerprint audit"},
		{"number": 9, "name": "ISP Spoofing & ASN Check", "description": "CAIDA API database query for IP spoofing capability"},
	}
	c.JSON(http.StatusOK, gin.H{"phases": phases})
}

// GetDiagnostic handles GET /api/diagnostics/:id — returns diagnostic status.
func (s *Server) GetDiagnostic(c *gin.Context) {
	id := c.Param("id")
	job, err := s.jobManager.GetJob(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":           job.ID,
		"status":       string(job.Status),
		"progress":     job.Progress,
		"created_at":   job.CreatedAt,
		"started_at":   job.StartedAt,
		"completed_at": job.CompletedAt,
		"results":      job.Results,
		"error":        job.Error,
	})
}

// ExportDiagnostic handles GET /api/diagnostics/:id/export — exports diagnostic report.
func (s *Server) ExportDiagnostic(c *gin.Context) {
	id := c.Param("id")
	job, err := s.jobManager.GetJob(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.Header("Content-Disposition", "attachment; filename=diagnostic-"+id+".json")
	c.JSON(http.StatusOK, gin.H{
		"id":           job.ID,
		"status":       string(job.Status),
		"created_at":   job.CreatedAt,
		"completed_at": job.CompletedAt,
		"results":      job.Results,
		"error":        job.Error,
		"exported_at":  time.Now(),
	})
}

// HandleGeoIPLookup handles GET /api/diagnostics/geoip — resolves and geolocates target host/IP.
func (s *Server) HandleGeoIPLookup(c *gin.Context) {
	target := c.Query("target")
	if target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing target query parameter"})
		return
	}

	// Resolve domain to IP first if it's not a direct IP address
	ipAddr := target
	if ips, err := net.LookupIP(target); err == nil && len(ips) > 0 {
		ipAddr = ips[0].String()
	}

	service, err := geoip.NewService("")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("GeoIP service creation failed: %v", err)})
		return
	}
	defer service.Close()

	country, code, region, city, lat, lon, err := service.Lookup(c.Request.Context(), ipAddr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("GeoIP lookup failed: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"target":       target,
		"ip":           ipAddr,
		"country":      country,
		"country_code": code,
		"region":       region,
		"city":         city,
		"latitude":     lat,
		"longitude":    lon,
	})
}
