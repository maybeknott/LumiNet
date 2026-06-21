package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/jobs"
)

// CreateDnsScan handles POST /api/dns-scans.
func (s *Server) CreateDnsScan(c *gin.Context) {
	var req CreateDnsScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Server == "" {
		req.Server = "8.8.8.8"
	}
	if req.RecordType == "" {
		req.RecordType = "A"
	}
	if req.TimeoutMs == 0 {
		req.TimeoutMs = 3000
	}

	config, _ := json.Marshal(map[string]interface{}{
		"server":      req.Server,
		"domain":      req.Domain,
		"record_type": req.RecordType,
		"timeout_ms":  req.TimeoutMs,
	})

	jobID := s.jobManager.CreateJob(jobs.JobTypeDnsScan, string(config))
	if err := s.jobManager.StartJob(jobID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"id": jobID, "status": "running"})
}

// GetDnsScan handles GET /api/dns-scans/:id.
func (s *Server) GetDnsScan(c *gin.Context) {
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
