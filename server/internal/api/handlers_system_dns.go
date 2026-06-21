package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/system"
)

// GetDnsStatus handles GET /api/system/dns — returns current DNS configuration.
func (s *Server) GetDnsStatus(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	ifaces, err := system.GetActiveInterfaces(ctx)
	if err != nil || len(ifaces) == 0 {
		c.JSON(http.StatusOK, DNSStatusResponse{
			Interface: "unknown",
			Servers:   []string{},
			Source:    "unknown",
		})
		return
	}

	// Use the first active interface
	iface := ifaces[0]
	servers, err := system.GetDNS(ctx, iface.Name)
	if err != nil {
		servers = []string{}
	}

	source := "dhcp"
	if len(servers) > 0 {
		source = "manual"
	}

	c.JSON(http.StatusOK, DNSStatusResponse{
		Interface: iface.Name,
		Servers:   servers,
		Source:    source,
	})
}

// SetDns handles POST /api/system/dns — applies DNS server settings.
func (s *Server) SetDns(c *gin.Context) {
	var req SetDNSRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate at the trust boundary: reject anything that is not a bare IP
	// (closes the PowerShell argument-injection vector in system.SetDNS).
	if err := system.ValidateDNSServers(req.Servers); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Interface != "" {
		if err := system.ValidateInterfaceAlias(req.Interface); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	ifaceName := req.Interface
	if ifaceName == "" {
		ifaces, err := system.GetActiveInterfaces(ctx)
		if err != nil || len(ifaces) == 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not detect active network interface"})
			return
		}
		ifaceName = ifaces[0].Name
	}

	if err := system.SetDNS(ctx, ifaceName, req.Servers); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":    "applied",
		"interface": ifaceName,
		"servers":   req.Servers,
	})
}

// ClearDns handles DELETE /api/system/dns — resets DNS to DHCP defaults.
func (s *Server) ClearDns(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	ifaces, err := system.GetActiveInterfaces(ctx)
	if err != nil || len(ifaces) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not detect active network interface"})
		return
	}

	ifaceName := ifaces[0].Name
	if err := system.ClearDNS(ctx, ifaceName); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":    "cleared",
		"interface": ifaceName,
	})
}
