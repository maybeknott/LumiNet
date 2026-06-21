package api

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/system"
)

type TunRouterStatusResponse struct {
	Running    bool   `json:"running"`
	DeviceName string `json:"device_name"`
	ProxyAddr  string `json:"proxy_addr"`
	MTU        int    `json:"mtu"`
}

type SetTunRouterRequest struct {
	Enabled    bool   `json:"enabled"`
	DeviceName string `json:"device_name"`
	ProxyAddr  string `json:"proxy_addr"`
}

// GetTunRouterStatus handles GET /api/system/tun-router
func (s *Server) GetTunRouterStatus(c *gin.Context) {
	mgr := system.GetTunRouterManager()
	running := mgr.IsRunning()
	dev, proxy, mtu := mgr.GetDeviceDetails()

	c.JSON(http.StatusOK, TunRouterStatusResponse{
		Running:    running,
		DeviceName: dev,
		ProxyAddr:  proxy,
		MTU:        mtu,
	})
}

// SetTunRouter handles POST /api/system/tun-router
func (s *Server) SetTunRouter(c *gin.Context) {
	var req SetTunRouterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	mgr := system.GetTunRouterManager()

	// Setup WebSocket log forwarder on demand
	mgr.SetOnLog(func(msg string) {
		s.hub.BroadcastSystemEvent("evasion_log", msg)
	})

	if req.Enabled {
		if req.DeviceName == "" {
			req.DeviceName = "wintun0"
		}
		if req.ProxyAddr == "" {
			req.ProxyAddr = "127.0.0.1:10888" // default SOCKS5 evasion port
		}

		err := mgr.BindTunToProxy(context.Background(), req.DeviceName, req.ProxyAddr)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	} else {
		mgr.Stop()
	}

	dev, proxy, mtu := mgr.GetDeviceDetails()
	c.JSON(http.StatusOK, gin.H{
		"status":      "applied",
		"enabled":     mgr.IsRunning(),
		"device_name": dev,
		"proxy_addr":  proxy,
		"mtu":         mtu,
	})
}
