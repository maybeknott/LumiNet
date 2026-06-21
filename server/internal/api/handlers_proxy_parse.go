package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/proxy"
)

const maxProxyParseBytes = 2 * 1024 * 1024

// ParseProxyContent handles POST /api/proxies/parse.
func (s *Server) ParseProxyContent(c *gin.Context) {
	var req ParseProxyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.Content = strings.TrimSpace(req.Content)
	if req.Content == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "content is required"})
		return
	}
	if len(req.Content) > maxProxyParseBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "proxy content exceeds 2 MiB limit"})
		return
	}

	configs, err := proxy.ParseSubscriptionContent(req.Content)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Dedupe {
		configs = proxy.SanitizeAndDedupe(configs)
	}

	results := make([]ParsedProxyResponse, 0, len(configs))
	for i, cfg := range configs {
		results = append(results, ParsedProxyResponse{
			Index:     i + 1,
			Protocol:  string(cfg.Protocol),
			Name:      cfg.Name,
			Address:   cfg.Address,
			Port:      cfg.Port,
			TLS:       cfg.TLS,
			SNI:       cfg.SNI,
			Transport: cfg.Transport,
			Preview:   proxy.URITransportPreview(cfg.RawURI, 110),
		})
	}

	c.JSON(http.StatusOK, ParseProxyResponse{
		Count:   len(results),
		Results: results,
	})
}
