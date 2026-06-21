package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/jobs"
)

// CreateSniScan handles POST /api/sni-scans.
func (s *Server) CreateSniScan(c *gin.Context) {
	var req CreateSniScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.TimeoutMs == 0 {
		req.TimeoutMs = 5000
	}

	config, _ := json.Marshal(map[string]interface{}{
		"domain":     req.Domain,
		"timeout_ms": req.TimeoutMs,
	})

	jobID := s.jobManager.CreateJob(jobs.JobTypeSniScan, string(config))
	if err := s.jobManager.StartJob(jobID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"id": jobID, "status": "running"})
}

// GetSniScan handles GET /api/sni-scans/:id.
func (s *Server) GetSniScan(c *gin.Context) {
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
