package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/jobs"
)

// CreatePortScan handles POST /api/port-scans — creates and starts a new TCP port scan.
func (s *Server) CreatePortScan(c *gin.Context) {
	var req CreatePortScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Timeout <= 0 {
		req.Timeout = 1000
	}
	if req.Concurrency <= 0 {
		req.Concurrency = 100
	}

	configPayload := map[string]interface{}{
		"target": req.Target,
		"ports":  req.Ports,
		"config": map[string]interface{}{
			"timeout_ms":     req.Timeout,
			"max_concurrent": req.Concurrency,
			"rate_limit_pps": 1000,
			"retry_count":    1,
			"adaptive_rate":  false,
			"ipv6":           false,
		},
	}

	configJSON, err := json.Marshal(configPayload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to marshal scan config"})
		return
	}

	jobID := s.jobManager.CreateJob(jobs.JobTypePortScan, string(configJSON))
	if err := s.jobManager.StartJob(jobID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{"id": jobID, "status": "running"})
}

// GetPortScan handles GET /api/port-scans/:id — returns current port scan status.
func (s *Server) GetPortScan(c *gin.Context) {
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
		"results":      job.Results,
		"error":        job.Error,
		"created_at":   job.CreatedAt,
		"started_at":   job.StartedAt,
		"completed_at": job.CompletedAt,
	})
}
