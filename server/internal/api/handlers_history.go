package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/jobs"
)

// GetHistory handles GET /api/history — returns the job history.
func (s *Server) GetHistory(c *gin.Context) {
	allJobs := s.jobManager.ListJobs(jobs.JobFilter{Limit: 100})
	c.JSON(http.StatusOK, gin.H{
		"jobs":  allJobs,
		"total": len(allJobs),
	})
}

// GetJob handles GET /api/jobs/:id — returns one job with config/results.
func (s *Server) GetJob(c *gin.Context) {
	job, err := s.jobManager.GetJob(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, job)
}

// CancelJob handles POST /api/jobs/:id/cancel — cancels a queued/running job.
func (s *Server) CancelJob(c *gin.Context) {
	if err := s.jobManager.CancelJob(c.Param("id")); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "cancelled"})
}

// ClearHistory handles DELETE /api/history — clears the job history.
func (s *Server) ClearHistory(c *gin.Context) {
	if err := s.jobManager.ClearHistory(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "cleared"})
}

// ExportHistory handles GET /api/export — exports all jobs to JSON.
func (s *Server) ExportHistory(c *gin.Context) {
	allJobs := s.jobManager.ListJobs(jobs.JobFilter{Limit: 1000})
	c.Header("Content-Disposition", "attachment; filename=luminet-history.json")
	c.JSON(http.StatusOK, gin.H{
		"exported_at": time.Now(),
		"jobs":        allJobs,
	})
}
