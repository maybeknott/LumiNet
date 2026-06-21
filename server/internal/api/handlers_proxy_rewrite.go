package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/proxy"
)

// RewriteProxyContent handles POST /api/proxies/rewrite.
// It parses the incoming subscription content and maps each proxy configuration
// to the list of clean IPs, adjusting ports and names as requested.
func (s *Server) RewriteProxyContent(c *gin.Context) {
	var req RewriteProxyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.Content = strings.TrimSpace(req.Content)
	if req.Content == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "content is required"})
		return
	}

	if len(req.CleanIPs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one clean IP is required"})
		return
	}

	rewritten, err := proxy.RewriteSubscriptionContent(req.Content, req.CleanIPs, req.NewPort, req.NewName)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, RewriteProxyResponse{
		Count:   len(rewritten),
		Results: rewritten,
	})
}
