package api

import (
	"context"
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/proxy"
)

// GetTelegramMTProtoProxies handles GET /api/telegram/mtproto
func (s *Server) GetTelegramMTProtoProxies(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	channel := c.Query("channel")
	var proxies []proxy.MTProtoProxy
	var err error

	if channel != "" {
		proxies, err = proxy.FetchAndTestMTProtoFromChannel(ctx, channel)
	} else {
		proxies, err = proxy.FetchAndTestMTProto(ctx)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Sort by latency (lowest first)
	sort.Slice(proxies, func(i, j int) bool {
		return proxies[i].PingMs < proxies[j].PingMs
	})

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"proxies": proxies,
	})
}
