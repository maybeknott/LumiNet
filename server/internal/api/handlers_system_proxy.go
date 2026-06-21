package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/system"
)

// GetProxyStatus handles GET /api/system/proxy — returns current system proxy settings.
func (s *Server) GetProxyStatus(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	settings, err := system.GetProxySettings(ctx)
	if err != nil {
		c.JSON(http.StatusOK, ProxySettingsResponse{Enabled: false})
		return
	}

	c.JSON(http.StatusOK, ProxySettingsResponse{
		Enabled: settings.Enabled,
		Server:  settings.HTTPServer,
		Bypass:  settings.BypassList,
		PacURL:  settings.PACURL,
	})
}

// SetProxy handles POST /api/system/proxy — applies system proxy settings.
func (s *Server) SetProxy(c *gin.Context) {
	var req SetProxyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if req.Enabled {
		pacURL := req.PacURL
		// If PAC is selected but no custom URL is specified, default to our local server endpoint
		if pacURL == "local" || (pacURL == "" && req.Server == "") {
			pacURL = fmt.Sprintf("http://127.0.0.1:%d/api/system/proxy.pac", s.config.Port)
		}

		if err := system.SetProxySettings(ctx, system.ProxySettings{
			Enabled:    true,
			HTTPServer: req.Server,
			BypassList: req.Bypass,
			PACURL:     pacURL,
		}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	} else {
		if err := system.DisableProxy(ctx); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": "applied", "enabled": req.Enabled})
}

// GetProxyPAC serves the dynamically generated PAC file for the proxy.
func (s *Server) GetProxyPAC(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	settings, err := system.GetProxySettings(ctx)
	proxyServer := "127.0.0.1:10888"
	if err == nil && settings.Server != "" {
		proxyServer = settings.Server
	}

	// Remove protocol prefix if exists
	if idx := strings.Index(proxyServer, "://"); idx != -1 {
		proxyServer = proxyServer[idx+3:]
	}

	pacScript := fmt.Sprintf(`function FindProxyForURL(url, host) {
    // Direct routing for local resources
    if (shExpMatch(host, "localhost") || shExpMatch(host, "127.0.0.1") || shExpMatch(host, "::1")) {
        return "DIRECT";
    }
    // Direct routing for local network segments
    if (isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
        isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
        isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
        isInNet(dnsResolve(host), "169.254.0.0", "255.255.0.0") ||
        isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")) {
        return "DIRECT";
    }
    // Route everything else through SOCKS5 proxy
    return "SOCKS5 %s; SOCKS %s; DIRECT";
}`, proxyServer, proxyServer)

	c.Header("Content-Type", "application/x-ns-proxy-autoconfig")
	c.String(http.StatusOK, pacScript)
}

// ClearProxy handles DELETE /api/system/proxy — disables system proxy.
func (s *Server) ClearProxy(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if err := system.DisableProxy(ctx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "cleared"})
}
