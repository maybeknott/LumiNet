package api

import (
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/proxy"
)

// setupProviderCorpusRoutes registers provider corpus endpoints.
func (s *Server) setupProviderCorpusRoutes(rg *gin.RouterGroup) {
	pc := rg.Group("/provider-corpus")
	pc.GET("", s.GetProviderCorpusStatus)
	pc.POST("", s.UpdateProviderCorpus)
}

// GetProviderCorpusStatus handles GET /api/provider-corpus — returns status of the active provider corpus.
func (s *Server) GetProviderCorpusStatus(c *gin.Context) {
	status, ok := proxy.GetProviderCorpusStoreStatus()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "PROVIDER_CORPUS_UNAVAILABLE",
			"message": "provider corpus status unavailable",
		})
		return
	}
	c.JSON(http.StatusOK, status)
}

// UpdateProviderCorpus handles POST /api/provider-corpus — uploads a new JSON provider corpus.
func (s *Server) UpdateProviderCorpus(c *gin.Context) {
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body: " + err.Error()})
		return
	}

	corpus, err := proxy.ParseProviderCorpus(bodyBytes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "INVALID_CORPUS_SCHEMA",
			"message": "failed to parse corpus: " + err.Error(),
		})
		return
	}



	// Update the global store (InitBuiltin uses a similar pattern, but we do atomic swap here)
	// In order to also populate the network prefix radix tree, we can walk the new providers list
	// and register them into the index.
	// But first, let's update the active snapshot:
	// We can add a method or do it directly if we exported store. But since providerCorpusStore is
	// package-private, we should update the snapshot via a helper in package proxy.
	// Wait, we can implement proxy.UpdateActiveProviderCorpus(snapshot) or parse directly in proxy.
	// Let's implement it via a proxy package helper.
	err = proxy.UpdateProviderCorpusRegistry(corpus)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to swap provider corpus: " + err.Error()})
		return
	}

	status, _ := proxy.GetProviderCorpusStoreStatus()
	c.JSON(http.StatusOK, gin.H{
		"status": "swapped",
		"corpus": status,
	})
}
