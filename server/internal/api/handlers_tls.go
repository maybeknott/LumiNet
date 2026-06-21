package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/jobs"
)

// CreateTlsScan handles POST /api/tls-scans.
func (s *Server) CreateTlsScan(c *gin.Context) {
	var req CreateTlsScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Mode == "cdn_sweep" {
		if len(req.Targets) == 0 && req.Target != "" {
			req.Targets = []string{req.Target}
		}
		if len(req.Targets) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "targets are required for cdn_sweep"})
			return
		}
		if req.TimeoutMs == 0 {
			req.TimeoutMs = 2000
		}
		if req.Concurrency == 0 {
			req.Concurrency = 50
		}
		if req.Sni == "" {
			req.Sni = "speed.cloudflare.com"
		}

		config, _ := json.Marshal(map[string]interface{}{
			"targets":     req.Targets,
			"cdn_host":    req.Sni,
			"sample_rate": req.SampleRate,
			"timeout_ms":  req.TimeoutMs,
			"concurrency": req.Concurrency,
		})

		jobID := s.jobManager.CreateJob(jobs.JobTypeCdnScan, string(config))
		if err := s.jobManager.StartJob(jobID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusAccepted, gin.H{"id": jobID, "status": "running"})
		return
	}

	if req.Target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target is required"})
		return
	}
	if req.Port == 0 {
		req.Port = 443
	}
	if req.TimeoutMs == 0 {
		req.TimeoutMs = 5000
	}

	config, _ := json.Marshal(map[string]interface{}{
		"target":     req.Target,
		"port":       req.Port,
		"timeout_ms": req.TimeoutMs,
		"sni":        req.Sni,
	})

	jobID := s.jobManager.CreateJob(jobs.JobTypeTlsScan, string(config))
	if err := s.jobManager.StartJob(jobID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"id": jobID, "status": "running"})
}

// GetTlsScan handles GET /api/tls-scans/:id.
func (s *Server) GetTlsScan(c *gin.Context) {
	id := c.Param("id")
	job, err := s.jobManager.GetJob(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id": job.ID, "status": string(job.Status),
		"progress": job.Progress, "results": job.Results, "error": job.Error,
	})
}
