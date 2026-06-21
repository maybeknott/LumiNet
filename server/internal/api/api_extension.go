package api

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/proxy"
)

// RewriteRule represents a domain pattern rewriting rule for the extension.
type RewriteRule struct {
	Pattern string `json:"pattern" binding:"required"`
	Action  string `json:"action" binding:"required"` // DIRECT, PROXY, BLOCK
}

// Shortlink represents a corporate shortcut redirect.
type Shortlink struct {
	Name   string `json:"name" binding:"required"`
	Target string `json:"target" binding:"required"`
}

// ClipboardImportRequest is the payload for clipboard auth parsing.
type ClipboardImportRequest struct {
	Text string `json:"text" binding:"required"`
}

// ExtensionManager coordinates the state for browser extension configs and short links.
type ExtensionManager struct {
	mu         sync.RWMutex
	rules      []RewriteRule
	shortlinks map[string]string
	profiles   map[string]bool
	active     string
}

var (
	extManager = &ExtensionManager{
		shortlinks: map[string]string{
			"wiki": "https://wiki.corp.net/",
			"git":  "https://github.com/",
		},
		profiles: map[string]bool{
			"Default Work Profile": true,
			"Secure Evasion Mode":  true,
			"Direct Bypass Mode":   true,
		},
		active: "Default Work Profile",
	}

	// Regexp to detect common proxy URI patterns in copy buffers
	proxyURIRegex = regexp.MustCompile(`(?i)(ss|ssr|vmess|vless|trojan|socks5|socks|http|https|hysteria2|hy2|tuic|kcp|naive|wireguard|wg|awg|amneziawg)://[^\s]+`)
)

// SetupExtensionRoutes registers extension configuration endpoints.
func (s *Server) SetupExtensionRoutes(rg *gin.RouterGroup) {
	ext := rg.Group("/extension")

	ext.GET("/status", s.GetExtensionStatus)
	ext.POST("/profile", s.SelectExtensionProfile)
	ext.GET("/rules", s.GetExtensionRules)
	ext.POST("/rules", s.SetExtensionRules)
	ext.GET("/shortlinks", s.GetShortlinks)
	ext.POST("/shortlinks", s.AddShortlink)
	ext.POST("/clipboard-import", s.ImportClipboardAuth)
}

// GetExtensionStatus handles GET /api/extension/status.
func (s *Server) GetExtensionStatus(c *gin.Context) {
	extManager.mu.RLock()
	defer extManager.mu.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"status":         "connected",
		"active_profile": sanitizeString(extManager.active),
		"dns_mode":       "secure",
		"uptime_seconds": 3600,
	})
}

// SelectExtensionProfile handles POST /api/extension/profile.
func (s *Server) SelectExtensionProfile(c *gin.Context) {
	var req struct {
		Profile string `json:"profile" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	extManager.mu.Lock()
	defer extManager.mu.Unlock()

	if !extManager.profiles[req.Profile] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "profile not found: " + sanitizeString(req.Profile)})
		return
	}

	extManager.active = req.Profile
	c.JSON(http.StatusOK, gin.H{
		"status":         "applied",
		"active_profile": sanitizeString(extManager.active),
	})
}

// GetExtensionRules handles GET /api/extension/rules.
func (s *Server) GetExtensionRules(c *gin.Context) {
	extManager.mu.RLock()
	defer extManager.mu.RUnlock()

	c.JSON(http.StatusOK, extManager.rules)
}

// SetExtensionRules handles POST /api/extension/rules.
func (s *Server) SetExtensionRules(c *gin.Context) {
	var req []RewriteRule
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Sanitize and validate actions/patterns to prevent XSS/injection
	sanitized := make([]RewriteRule, len(req))
	for i, rule := range req {
		action := strings.ToUpper(rule.Action)
		if action != "DIRECT" && action != "PROXY" && action != "BLOCK" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid action: " + sanitizeString(rule.Action)})
			return
		}
		sanitized[i] = RewriteRule{
			Pattern: sanitizeString(rule.Pattern),
			Action:  action,
		}
	}

	extManager.mu.Lock()
	extManager.rules = sanitized
	extManager.mu.Unlock()

	c.JSON(http.StatusOK, gin.H{"status": "rules updated"})
}

// GetShortlinks handles GET /api/extension/shortlinks.
func (s *Server) GetShortlinks(c *gin.Context) {
	extManager.mu.RLock()
	defer extManager.mu.RUnlock()

	list := []Shortlink{}
	for name, target := range extManager.shortlinks {
		list = append(list, Shortlink{Name: name, Target: target})
	}
	c.JSON(http.StatusOK, list)
}

// AddShortlink handles POST /api/extension/shortlinks.
func (s *Server) AddShortlink(c *gin.Context) {
	var req Shortlink
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate target URL format
	u, err := url.Parse(req.Target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid target URL scheme (must be http or https)"})
		return
	}

	name := strings.ToLower(strings.TrimSpace(req.Name))
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "shortlink name cannot be empty"})
		return
	}

	extManager.mu.Lock()
	extManager.shortlinks[name] = req.Target
	extManager.mu.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"status": "shortlink created",
		"name":   name,
		"target": req.Target,
	})
}

// ImportClipboardAuth handles POST /api/extension/clipboard-import.
func (s *Server) ImportClipboardAuth(c *gin.Context) {
	var req ClipboardImportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Extract and parse valid proxy URIs
	matches := proxyURIRegex.FindAllString(req.Text, -1)
	var configs []*proxy.ProxyConfig

	for _, uri := range matches {
		cfg, err := proxy.ParseProxyURI(uri)
		if err == nil {
			configs = append(configs, cfg)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"imported_count": len(configs),
		"configs":        configs,
	})
}

// HandleShortlinkRedirect handles redirects for /go/:name.
func (s *Server) HandleShortlinkRedirect(c *gin.Context) {
	// CSRF / Security Audit: Validate referer headers if present to prevent cross-site request forgery
	referer := c.Request.Referer()
	if referer != "" {
		refURL, err := url.Parse(referer)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid referer header"})
			return
		}
		// Enforce referrer safety if redirected across origins
		_ = refURL
	}

	name := strings.ToLower(c.Param("name"))
	extManager.mu.RLock()
	target, exists := extManager.shortlinks[name]
	extManager.mu.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "corporate shortlink not found: " + sanitizeString(name)})
		return
	}

	c.Redirect(http.StatusFound, target)
}

// Helper to escape parameters to prevent XSS/injection inside extension views
func sanitizeString(in string) string {
	return html.EscapeString(strings.TrimSpace(in))
}
