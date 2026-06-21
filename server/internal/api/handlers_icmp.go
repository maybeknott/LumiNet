package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/jobs"
)

// CreateScan handles POST /api/scans — creates and starts a new ICMP scan job.
func (s *Server) CreateScan(c *gin.Context) {
	var req CreateScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set defaults
	if req.Timeout <= 0 {
		req.Timeout = 1000
	}
	if req.Concurrency <= 0 {
		req.Concurrency = 100
	}

	configPayload := map[string]interface{}{
		"targets": req.Targets,
		"config": map[string]interface{}{
			"timeout_ms":     req.Timeout,
			"max_concurrent": req.Concurrency,
			"rate_limit_pps": 1000,
			"retry_count":    1,
			"adaptive_rate":  true,
			"ipv6":           req.IPv6,
		},
	}

	configJSON, err := json.Marshal(configPayload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to marshal scan config"})
		return
	}

	jobID := s.jobManager.CreateJob(jobs.JobTypeIcmpScan, string(configJSON))
	if err := s.jobManager.StartJob(jobID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{"id": jobID, "status": "running"})
}

// GetScan handles GET /api/scans/:id — returns current scan status.
func (s *Server) GetScan(c *gin.Context) {
	id := c.Param("id")
	job, err := s.jobManager.GetJob(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, ScanResponse{
		ID:          job.ID,
		Status:      string(job.Status),
		Progress:    job.Progress,
		CreatedAt:   job.CreatedAt,
		StartedAt:   job.StartedAt,
		CompletedAt: job.CompletedAt,
		Error:       job.Error,
	})
}

// GetScanAlive handles GET /api/scans/:id/alive — returns only alive hosts found.
func (s *Server) GetScanAlive(c *gin.Context) {
	id := c.Param("id")
	job, err := s.jobManager.GetJob(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	var results []ProbeResultResponse
	if job.Results != "" {
		_ = json.Unmarshal([]byte(job.Results), &results)
	}

	var alive []AliveHost
	for _, r := range results {
		if r.Alive {
			alive = append(alive, AliveHost{
				IP:        r.IP,
				Hostname:  r.Vendor, // Using vendor as fallback for now
				LatencyMs: r.LatencyMs,
				TTL:       r.TTL,
			})
		}
	}

	c.JSON(http.StatusOK, ScanAliveResponse{
		ID:    job.ID,
		Alive: alive,
	})
}

// GetScanResults handles GET /api/scans/:id/results — returns full scan results.
func (s *Server) GetScanResults(c *gin.Context) {
	id := c.Param("id")
	job, err := s.jobManager.GetJob(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	var results []ProbeResultResponse
	if job.Results != "" {
		_ = json.Unmarshal([]byte(job.Results), &results)
	}

	format := c.Query("format")
	if format == "jsonl" {
		c.Header("Content-Disposition", "attachment; filename=scan-"+id+".jsonl")
		c.Header("Content-Type", "application/x-jsonlines")
		for _, r := range results {
			line, err := json.Marshal(r)
			if err != nil {
				continue
			}
			c.Writer.Write(line)
			c.Writer.Write([]byte("\n"))
		}
		return
	}
	if format == "xml" {
		c.Header("Content-Disposition", "attachment; filename=scan-"+id+".xml")
		c.Header("Content-Type", "application/xml")
		c.String(http.StatusOK, s.renderNmapXML(id, results))
		return
	}
	if format == "grepable" {
		c.Header("Content-Disposition", "attachment; filename=scan-"+id+".gnmap")
		c.Header("Content-Type", "text/plain")
		c.String(http.StatusOK, s.renderGrepable(id, results))
		return
	}

	aliveCount := 0
	var sumLat float64
	for _, r := range results {
		if r.Alive {
			aliveCount++
			sumLat += r.LatencyMs
		}
	}

	avgLat := 0.0
	if aliveCount > 0 {
		avgLat = sumLat / float64(aliveCount)
	}

	c.JSON(http.StatusOK, ScanResultsResponse{
		ID:      job.ID,
		Results: results,
		Summary: ScanSummary{
			TotalTargets: len(results),
			AliveCount:   aliveCount,
			DeadCount:    len(results) - aliveCount,
			AvgLatencyMs: avgLat,
		},
	})
}

func (s *Server) renderNmapXML(id string, results []ProbeResultResponse) string {
	var sb strings.Builder
	sb.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	sb.WriteString("<!DOCTYPE nmaprun>\n")
	sb.WriteString("<nmaprun scanner=\"luminet\" args=\"luminet icmp-scan\" start=\"0\" startstr=\"\" version=\"1.0\">\n")
	for _, r := range results {
		status := "down"
		if r.Alive {
			status = "up"
		}
		addr := r.IP
		if addr == "" {
			addr = r.Target
		}
		sb.WriteString(fmt.Sprintf("  <host><address addr=\"%s\" addrtype=\"ipv4\"/>\n", addr))
		sb.WriteString(fmt.Sprintf("    <status state=\"%s\" reason=\"\" reason_ttl=\"%d\"/>\n", status, r.TTL))
		if r.LatencyMs > 0 {
			sb.WriteString(fmt.Sprintf("    <times srtt=\"%d\" rttvar=\"0\" to=\"0\"/>\n", int(r.LatencyMs*1000)))
		}
		sb.WriteString("  </host>\n")
	}
	sb.WriteString("</nmaprun>\n")
	return sb.String()
}

func (s *Server) renderGrepable(id string, results []ProbeResultResponse) string {
	var sb strings.Builder
	sb.WriteString("# Luminet scan report\n")
	for _, r := range results {
		status := "Down"
		if r.Alive {
			status = "Up"
		}
		addr := r.IP
		if addr == "" {
			addr = r.Target
		}
		sb.WriteString(fmt.Sprintf("Host: %s ()\tStatus: %s\n", addr, status))
	}
	sb.WriteString("# Luminet Done\n")
	return sb.String()
}

// CancelScan handles POST /api/scans/:id/cancel — cancels a running scan.
func (s *Server) CancelScan(c *gin.Context) {
	id := c.Param("id")
	if err := s.jobManager.CancelJob(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "cancelled"})
}
