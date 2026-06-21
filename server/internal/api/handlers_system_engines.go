package api

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/proxy"
)

var (
	runningEngines = make(map[string]proxy.ProxyEngine)
	enginesMu      sync.RWMutex
)

// GetEnginesStatus handles GET /api/system/engines — lists status of Tor and Psiphon bypass engines.
func (s *Server) GetEnginesStatus(c *gin.Context) {
	enginesMu.RLock()
	defer enginesMu.RUnlock()

	torRunning := false
	if tor, exists := runningEngines["tor"]; exists {
		torRunning = tor.IsRunning()
	}

	psiphonRunning := false
	if psiphon, exists := runningEngines["psiphon"]; exists {
		psiphonRunning = psiphon.IsRunning()
	}

	c.JSON(http.StatusOK, gin.H{
		"engines": []gin.H{
			{
				"id":          "tor",
				"name":        "Tor Network (Onion Client)",
				"description": "Route SOCKS5 connections through the decentralized Tor network for absolute anonymity and censorship bypass.",
				"running":     torRunning,
				"socks_port":  10950,
			},
			{
				"id":          "psiphon",
				"name":        "Psiphon Client Core",
				"description": "Establish a secure tunnel utilizing Psiphon's network-aware transport protocols to bypass strict DPI censorship.",
				"running":     psiphonRunning,
				"socks_port":  10890,
			},
		},
	})
}

// ControlEngine handles POST /api/system/engines — starts/stops Tor or Psiphon bypass engine.
func (s *Server) ControlEngine(c *gin.Context) {
	var req struct {
		Engine        string `json:"engine"` // "tor" or "psiphon"
		Action        string `json:"action"` // "start" or "stop"
		SocksPort     int    `json:"socks_port,omitempty"`
		UpstreamProxy string `json:"upstream_proxy,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	enginesMu.Lock()
	defer enginesMu.Unlock()

	targetEngine, exists := runningEngines[req.Engine]

	if req.Action == "stop" {
		if exists {
			targetEngine.Stop()
			delete(runningEngines, req.Engine)
			c.JSON(http.StatusOK, gin.H{"status": "stopped", "engine": req.Engine})
		} else {
			c.JSON(http.StatusOK, gin.H{"status": "already_stopped", "engine": req.Engine})
		}
		return
	}

	if req.Action == "start" {
		if exists && targetEngine.IsRunning() {
			c.JSON(http.StatusOK, gin.H{"status": "already_running", "engine": req.Engine})
			return
		}

		var engineInst proxy.ProxyEngine
		var err error

		if req.Engine == "tor" {
			port := req.SocksPort
			if port <= 0 {
				port = 10950
			}
			engineInst, err = proxy.GetProxyEngine(proxy.EngineTor)
		} else if req.Engine == "psiphon" {
			port := req.SocksPort
			if port <= 0 {
				port = 10890
			}
			psWrapper := proxy.NewPsiphonEngineWrapper(port)
			if req.UpstreamProxy != "" {
				psWrapper.SetUpstreamProxy(req.UpstreamProxy)
			}
			engineInst = psWrapper
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("unsupported engine type: %s", req.Engine)})
			return
		}

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if err := engineInst.Start(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to start engine: %v", err)})
			return
		}

		runningEngines[req.Engine] = engineInst
		c.JSON(http.StatusOK, gin.H{"status": "started", "engine": req.Engine})
		return
	}

	c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid action: %s", req.Action)})
}
