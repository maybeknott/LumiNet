package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/system"
)

// GetProfiles handles GET /api/system/profiles — lists all network profiles.
func (s *Server) GetProfiles(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	ifaces, _ := system.GetActiveInterfaces(ctx)
	ssid := ""
	if len(ifaces) > 0 {
		for _, iface := range ifaces {
			if iface.IsWireless {
				ssid = iface.SSID
				break
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"profiles":    []interface{}{},
		"active_ssid": ssid,
		"message":     "No profiles configured. Use the UI or config file to add profiles.",
	})
}

// ApplyProfile handles POST /api/system/profiles/:name/apply — applies a named profile.
func (s *Server) ApplyProfile(c *gin.Context) {
	name := c.Param("name")
	c.JSON(http.StatusNotFound, gin.H{
		"error": "profile not found: " + name,
	})
}
