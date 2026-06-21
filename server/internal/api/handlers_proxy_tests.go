package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/maybeknott/luminet/internal/jobs"
	"github.com/maybeknott/luminet/internal/proxy"
)

// CreateProxyTest handles POST /api/proxy-tests — creates a single proxy test.
func (s *Server) CreateProxyTest(c *gin.Context) {
	var req CreateProxyTestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Timeout <= 0 {
		req.Timeout = 10
	}
	if len(req.URLs) == 0 {
		req.URLs = []string{"http://cp.cloudflare.com/"}
	}

	config, _ := json.Marshal(map[string]interface{}{
		"proxy_addr":   req.ProxyURI,
		"proxy_preview": proxy.URITransportPreview(req.ProxyURI, 72),
		"target":       req.URLs[0],
		"timeout_ms":   uint32(req.Timeout * 1000),
		"use_http":     true,
		"dns_resolver": req.DnsResolver,
	})

	jobID := s.jobManager.CreateJob(jobs.JobTypeProxyTest, string(config))
	if err := s.jobManager.StartJob(jobID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusAccepted, ProxyTestResponse{
		ID:     jobID,
		Status: string(jobs.JobStatusRunning),
	})
}

// GetProxyTest handles GET /api/proxy-tests/:id — returns proxy test status.
func (s *Server) GetProxyTest(c *gin.Context) {
	id := c.Param("id")
	job, err := s.jobManager.GetJob(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	resp := ProxyTestResponse{
		ID:     job.ID,
		Status: string(job.Status),
		Error:  job.Error,
	}

	if job.Status == jobs.JobStatusCompleted && job.Results != "" {
		var row ProxyScanRowResponse
		if err := json.Unmarshal([]byte(job.Results), &row); err == nil {
			resp.Result = &row
		}
	}

	c.JSON(http.StatusOK, resp)
}

// StreamProxyTest handles GET /api/proxy-tests/:id/stream — WebSocket stream for live test results.
func (s *Server) StreamProxyTest(c *gin.Context) {
	id := c.Param("id")

	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true
			}
			u, err := url.Parse(origin)
			if err != nil {
				return false
			}
			host := u.Hostname()
			if host == "localhost" || host == "127.0.0.1" || host == "::1" {
				return true
			}
			for _, allowed := range s.config.AllowedOrigins {
				if allowed == "*" || allowed == origin {
					return true
				}
				if au, err := url.Parse(allowed); err == nil && au.Hostname() == host {
					return true
				}
			}
			return false
		},
	}

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	// For now, poll job status and push updates (v0 logic)
	for i := 0; i < 60; i++ {
		job, err := s.jobManager.GetJob(id)
		if err != nil {
			break
		}

		msg, _ := json.Marshal(map[string]interface{}{
			"type":     "progress",
			"job_id":   job.ID,
			"status":   string(job.Status),
			"progress": job.Progress,
			"results":  job.Results,
			"error":    job.Error,
		})

		if err := conn.WriteMessage(1, msg); err != nil {
			break
		}

		if job.Status == jobs.JobStatusCompleted ||
			job.Status == jobs.JobStatusFailed ||
			job.Status == jobs.JobStatusCancelled {
			break
		}

		select {
		case <-c.Request.Context().Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}
