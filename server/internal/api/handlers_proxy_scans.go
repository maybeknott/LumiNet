package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/jobs"
)

// CreateProxyScan handles POST /api/proxy-scans — creates a batch proxy scan.
func (s *Server) CreateProxyScan(c *gin.Context) {
	var req CreateProxyScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Timeout <= 0 {
		req.Timeout = 10
	}
	if req.Concurrency <= 0 {
		req.Concurrency = 8
	}
	if len(req.URLs) == 0 {
		req.URLs = []string{"http://cp.cloudflare.com/"}
	}

	config, _ := json.Marshal(map[string]interface{}{
		"proxies":      req.Proxies,
		"urls":         req.URLs,
		"timeout":      req.Timeout,
		"concurrency":  req.Concurrency,
		"speed_test":   req.SpeedTest,
		"geoip":        req.GeoIP,
		"core_type":    req.CoreType,
		"dns_resolver": req.DnsResolver,
	})

	jobID := s.jobManager.CreateJob(jobs.JobTypeProxyTest, string(config))
	if err := s.jobManager.StartJob(jobID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusAccepted, ProxyScanResponse{
		ID:           jobID,
		Status:       string(jobs.JobStatusRunning),
		Progress:     0,
		CreatedAt:    time.Now(),
		TotalProxies: len(req.Proxies),
	})
}

// GetProxyScan handles GET /api/proxy-scans/:id — returns proxy scan status.
func (s *Server) GetProxyScan(c *gin.Context) {
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
		"error":        job.Error,
	})
}

// GetProxyScanRows handles GET /api/proxy-scans/:id/rows — returns proxy result rows.
func (s *Server) GetProxyScanRows(c *gin.Context) {
	id := c.Param("id")
	job, err := s.jobManager.GetJob(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	if job.Status != jobs.JobStatusCompleted || job.Results == "" {
		c.JSON(http.StatusOK, gin.H{
			"id":   job.ID,
			"rows": []interface{}{},
		})
		return
	}

	var rows []ProxyScanRowResponse
	if err := json.Unmarshal([]byte(job.Results), &rows); err != nil {
		rows = []ProxyScanRowResponse{}
	}

	c.JSON(http.StatusOK, gin.H{
		"id":   job.ID,
		"rows": rows,
	})
}

// CancelProxyScan handles POST /api/proxy-scans/:id/cancel — cancels a running proxy scan.
func (s *Server) CancelProxyScan(c *gin.Context) {
	id := c.Param("id")
	if err := s.jobManager.CancelJob(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "cancelled"})
}
