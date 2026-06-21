package api

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// SpeedtestRequest specifies inputs for the speedtest.
type SpeedtestRequest struct {
	URL            string `json:"url,omitempty"`
	Bytes          int    `json:"bytes,omitempty"`
	Proxy          string `json:"proxy,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

// SpeedtestResponse contains the metrics computed during the speedtest.
type SpeedtestResponse struct {
	Success             bool    `json:"success"`
	DownloadSpeedMbps   float64 `json:"download_speed_mbps"`
	DownloadTimeSeconds float64 `json:"download_time_seconds"`
	TotalTimeSeconds    float64 `json:"total_time_seconds"`
	ServerTimingSeconds float64 `json:"server_timing_seconds"`
	Error               string  `json:"error,omitempty"`
}

// setupSpeedtestRoutes registers the speedtest endpoints.
func (s *Server) setupSpeedtestRoutes(rg *gin.RouterGroup) {
	rg.POST("/system/speedtest", s.RunSpeedtest)
}

func parseServerTiming(header string) float64 {
	if header == "" {
		return 0
	}
	parts := strings.Split(header, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "dur=") {
			valStr := strings.TrimPrefix(part, "dur=")
			if val, err := strconv.ParseFloat(valStr, 64); err == nil {
				return val / 1000.0 // convert ms to seconds
			}
		}
	}
	// Fallback to simple split by '='
	if idx := strings.Index(header, "="); idx != -1 {
		valStr := strings.TrimSpace(header[idx+1:])
		if val, err := strconv.ParseFloat(valStr, 64); err == nil {
			return val / 1000.0
		}
	}
	return 0
}

// RunSpeedtest runs a download speedtest through the configured endpoint or range bytes.
func (s *Server) RunSpeedtest(c *gin.Context) {
	var req SpeedtestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, SpeedtestResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid speedtest request body: %v", err),
		})
		return
	}

	if req.URL == "" {
		req.URL = "https://speed.cloudflare.com/__down"
	}
	if req.Bytes <= 0 {
		req.Bytes = 1024 * 1024 // default 1MB
	}
	if req.TimeoutSeconds <= 0 {
		req.TimeoutSeconds = 15 // default 15s
	}

	// Prepare proxy
	var proxyURL *url.URL
	if req.Proxy != "" {
		var err error
		proxyURL, err = url.Parse(req.Proxy)
		if err != nil {
			c.JSON(http.StatusBadRequest, SpeedtestResponse{
				Success: false,
				Error:   fmt.Sprintf("invalid proxy URL: %v", err),
			})
			return
		}
	}

	// Prepare request
	httpReq, err := http.NewRequest("GET", req.URL, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, SpeedtestResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to create http request: %v", err),
		})
		return
	}

	// Set query params or Range header
	u, err := url.Parse(req.URL)
	if err == nil && u.Host == "speed.cloudflare.com" {
		q := httpReq.URL.Query()
		q.Set("bytes", strconv.Itoa(req.Bytes))
		httpReq.URL.RawQuery = q.Encode()
	} else {
		// General HTTP Range header for non-Cloudflare endpoints
		httpReq.Header.Set("Range", fmt.Sprintf("bytes=0-%d", req.Bytes-1))
	}
	httpReq.Header.Set("User-Agent", "LumiNet/Speedtest")

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(req.TimeoutSeconds) * time.Second,
	}

	startTime := time.Now()
	resp, err := client.Do(httpReq)
	if err != nil {
		c.JSON(http.StatusBadGateway, SpeedtestResponse{
			Success: false,
			Error:   fmt.Sprintf("http request failed: %v", err),
		})
		return
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		c.JSON(http.StatusBadGateway, SpeedtestResponse{
			Success: false,
			Error:   fmt.Sprintf("unexpected response status: %s", resp.Status),
		})
		return
	}

	// Read body in chunks to track throughput
	buffer := make([]byte, 32*1024)
	var totalRead int64
	for {
		n, readErr := resp.Body.Read(buffer)
		totalRead += int64(n)
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			c.JSON(http.StatusBadGateway, SpeedtestResponse{
				Success: false,
				Error:   fmt.Sprintf("error reading response body: %v", readErr),
			})
			return
		}
	}

	totalTime := time.Since(startTime).Seconds()
	serverTiming := resp.Header.Get("Server-Timing")
	serverTimingSeconds := parseServerTiming(serverTiming)

	downloadTime := totalTime - serverTimingSeconds
	if downloadTime <= 0 {
		// Prevent division by zero/negative time in case of high clock skew or instant responses
		downloadTime = totalTime
		if downloadTime <= 0 {
			downloadTime = 0.001
		}
	}

	downloadSpeedMbps := (float64(totalRead) * 8.0) / (downloadTime * 1000000.0)

	c.JSON(http.StatusOK, SpeedtestResponse{
		Success:             true,
		DownloadSpeedMbps:   downloadSpeedMbps,
		DownloadTimeSeconds: downloadTime,
		TotalTimeSeconds:    totalTime,
		ServerTimingSeconds: serverTimingSeconds,
	})
}
