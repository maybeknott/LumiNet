package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/proxy"
)

// setupPresetRoutes registers presets endpoints.
func (s *Server) setupPresetRoutes(rg *gin.RouterGroup) {
	presets := rg.Group("/presets")
	presets.GET("", s.GetPresets)
	presets.GET("/cdn", s.GetCDNPresets)
	presets.GET("/doh", s.GetDoHPresets)
	presets.GET("/dns", s.GetDNSPresets)
	presets.GET("/scanner", s.GetScannerPresets)
	presets.GET("/isp", s.GetISPPresets)
}

// GetPresets returns all presets (CDN, DoH, standard DNS, scanner, and ISP presets) in a single payload.
func (s *Server) GetPresets(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"cdn":     proxy.GetCDNPresets(),
		"doh":     proxy.GetDoHPresets(),
		"dns":     proxy.GetDNSPresets(),
		"scanner": proxy.GetScanPresets(),
		"isp":     proxy.GetEvasionISPPresets(),
	})
}

// GetCDNPresets returns only CDN presets.
func (s *Server) GetCDNPresets(c *gin.Context) {
	c.JSON(http.StatusOK, proxy.GetCDNPresets())
}

// GetDoHPresets returns only DoH presets.
func (s *Server) GetDoHPresets(c *gin.Context) {
	c.JSON(http.StatusOK, proxy.GetDoHPresets())
}

// GetDNSPresets returns only standard/gaming DNS presets.
func (s *Server) GetDNSPresets(c *gin.Context) {
	c.JSON(http.StatusOK, proxy.GetDNSPresets())
}

// GetScannerPresets returns only scanner presets.
func (s *Server) GetScannerPresets(c *gin.Context) {
	c.JSON(http.StatusOK, proxy.GetScanPresets())
}

// GetISPPresets returns only ISP evasion presets.
func (s *Server) GetISPPresets(c *gin.Context) {
	c.JSON(http.StatusOK, proxy.GetEvasionISPPresets())
}

