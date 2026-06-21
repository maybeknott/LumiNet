package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/config"
)

// ListProxyNodes handles GET /api/proxies — returns all registered proxy nodes.
func (s *Server) ListProxyNodes(c *gin.Context) {
	cfg := s.configManager.Get()
	c.JSON(http.StatusOK, cfg.ProxyNodes)
}

// AddProxyNode handles POST /api/proxies — registers a new proxy node.
func (s *Server) AddProxyNode(c *gin.Context) {
	var node config.ProxyNodeConfig
	if err := c.ShouldBindJSON(&node); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if node.ID == "" {
		node.ID = fmt.Sprintf("p%d", time.Now().Unix())
	}

	cfg := s.configManager.Get()
	cfg.ProxyNodes = append(cfg.ProxyNodes, node)

	if err := s.configManager.Save(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, node)
}

// DeleteProxyNode handles DELETE /api/proxies/:id — removes a registered proxy node.
func (s *Server) DeleteProxyNode(c *gin.Context) {
	id := c.Param("id")
	cfg := s.configManager.Get()

	var newNodes []config.ProxyNodeConfig
	found := false
	for _, n := range cfg.ProxyNodes {
		if n.ID == id {
			found = true
			continue
		}
		newNodes = append(newNodes, n)
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "proxy node not found"})
		return
	}

	cfg.ProxyNodes = newNodes
	if err := s.configManager.Save(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}
