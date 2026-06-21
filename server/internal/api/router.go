// Package api implements the HTTP/WebSocket API server for LumiNet.
package api

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/config"
	"github.com/maybeknott/luminet/internal/jobs"
	"github.com/maybeknott/luminet/internal/proxy"
	"github.com/maybeknott/luminet/internal/store"
)

// ServerConfig holds configuration for the API server.
type ServerConfig struct {
	Host           string
	Port           int
	APIKey         string
	AllowedOrigins []string
	RateLimitRPS   int
	WebDist        embed.FS
	EnableWeb      bool
}

// Server holds all dependencies for the API layer.
type Server struct {
	config        *ServerConfig
	router        *gin.Engine
	hub           *Hub
	jobManager    *jobs.JobManager
	store         *store.Store
	configManager *config.Manager
	startTime     time.Time
	httpServer    *http.Server
}

// NewServer creates a new API server with all dependencies wired.
func NewServer(config *ServerConfig, jobMgr *jobs.JobManager, st *store.Store, cfgMgr *config.Manager) *Server {
	gin.SetMode(gin.ReleaseMode)
	hub := NewHub()
	go hub.Run()
	hub.ListenToJobs(jobMgr)

	s := &Server{
		config:        config,
		hub:           hub,
		jobManager:    jobMgr,
		store:         st,
		configManager: cfgMgr,
		startTime:     time.Now(),
	}

	cfg := cfgMgr.Get()
	if cfg != nil {
		proxy.GetEvasionManager().SetHostsOverride(cfg.HostsOverride)
	}

	s.router = s.SetupRouter()
	return s
}

// SetupRouter configures all route groups, middleware, and handlers.
func (s *Server) SetupRouter() *gin.Engine {
	r := gin.New()
	s.setupMiddleware(r)
	s.setupHealthRoutes(r)
	s.setupWebSocketRoute(r)
	r.GET("/go/:name", s.HandleShortlinkRedirect)
	r.GET("/track", s.HandleCovertTrack)
	r.GET("/track/:link_id", s.HandleCovertTrack)

	api := r.Group("/api")
	api.Use(AuthMiddleware(s.config.APIKey))

	s.setupScanRoutes(api)
	s.setupProxyScanRoutes(api)
	s.setupProxyTestRoutes(api)
	s.setupDnsScanRoutes(api)
	s.setupTlsScanRoutes(api)
	s.setupSniScanRoutes(api)
	s.setupDiagnosticRoutes(api)
	s.setupSystemRoutes(api)
	s.setupHistoryRoutes(api)
	s.setupCapabilitiesRoute(api)
	s.setupServerConfigRoute(api)
	s.setupTelegramRoutes(api)
	s.setupSubscriptionRoutes(api)
	s.setupPresetRoutes(api)
	s.setupRoutingPluginRoutes(api)
	s.setupSpeedtestRoutes(api)
	s.setupProviderCorpusRoutes(api)
	s.SetupExtensionRoutes(api)

	if !s.config.EnableWeb {
		r.NoRoute(func(c *gin.Context) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		})
		return r
	}

	// Serve retired embedded React frontend only when explicitly enabled.
	subFS, err := fs.Sub(s.config.WebDist, "web/dist")
	if err != nil {
		r.NoRoute(func(c *gin.Context) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		})
	} else {
		fileServer := http.FileServer(http.FS(subFS))
		serveIndexHTML := func(c *gin.Context) {
			data, err := fs.ReadFile(subFS, "index.html")
			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "frontend not found"})
				return
			}

			// Deliver the API key to the browser as an HttpOnly, SameSite=Strict
			// cookie rather than embedding it in the page as a JS global. The
			// cookie is unreadable from JavaScript, never appears in URLs or
			// logs, and is sent automatically on same-origin REST and WebSocket
			// requests. SameSite=Strict also blocks cross-site CSRF.
			if s.config.APIKey != "" {
				http.SetCookie(c.Writer, &http.Cookie{
					Name:     SessionCookieName,
					Value:    s.config.APIKey,
					Path:     "/",
					HttpOnly: true,
					SameSite: http.SameSiteStrictMode,
				})
			}

			c.Header("Content-Type", "text/html; charset=utf-8")
			c.String(http.StatusOK, string(data))
		}

		r.NoRoute(func(c *gin.Context) {
			path := c.Request.URL.Path
			if path == "/ws" || path == "/health" || (len(path) >= 5 && path[:5] == "/api/") {
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
				return
			}

			filePath := path
			if len(filePath) > 0 && filePath[0] == '/' {
				filePath = filePath[1:]
			}
			if filePath == "" || filePath == "index.html" {
				serveIndexHTML(c)
				return
			}

			f, err := subFS.Open(filePath)
			if err == nil {
				f.Close()
				fileServer.ServeHTTP(c.Writer, c.Request)
				return
			}

			// Fallback to index.html for SPA routing
			serveIndexHTML(c)
		})
	}

	return r
}

// setupMiddleware registers global middleware on the Gin engine.
func (s *Server) setupMiddleware(r *gin.Engine) {
	r.Use(RecoveryMiddleware())
	r.Use(RequestLogger())
	r.Use(CorsMiddleware(s.config.AllowedOrigins))
	if s.config.RateLimitRPS > 0 {
		r.Use(RateLimitMiddleware(s.config.RateLimitRPS))
	}
}

// setupHealthRoutes registers the /health endpoint.
func (s *Server) setupHealthRoutes(r *gin.Engine) {
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "ok",
			"timestamp": time.Now().UTC(),
			"version":   "0.1.0",
		})
	})
}

// setupScanRoutes registers /api/scans endpoints.
func (s *Server) setupScanRoutes(rg *gin.RouterGroup) {
	scans := rg.Group("/scans")
	scans.POST("", s.CreateScan)
	scans.GET("/:id", s.GetScan)
	scans.GET("/:id/alive", s.GetScanAlive)
	scans.GET("/:id/results", s.GetScanResults)
	scans.POST("/:id/cancel", s.CancelScan)

	portScans := rg.Group("/port-scans")
	portScans.POST("", s.CreatePortScan)
	portScans.GET("/:id", s.GetPortScan)

	proxies := rg.Group("/proxies")
	proxies.GET("", s.ListProxyNodes)
	proxies.POST("", s.AddProxyNode)
	proxies.POST("/parse", s.ParseProxyContent)
	proxies.POST("/rewrite", s.RewriteProxyContent)
	proxies.DELETE("/:id", s.DeleteProxyNode)
}

// setupProxyScanRoutes registers /api/proxy-scans endpoints.
func (s *Server) setupProxyScanRoutes(rg *gin.RouterGroup) {
	ps := rg.Group("/proxy-scans")
	ps.POST("", s.CreateProxyScan)
	ps.GET("/:id", s.GetProxyScan)
	ps.GET("/:id/rows", s.GetProxyScanRows)
	ps.POST("/:id/cancel", s.CancelProxyScan)
}

// setupProxyTestRoutes registers /api/proxy-tests endpoints.
func (s *Server) setupProxyTestRoutes(rg *gin.RouterGroup) {
	pt := rg.Group("/proxy-tests")
	pt.POST("", s.CreateProxyTest)
	pt.GET("/:id", s.GetProxyTest)
	pt.GET("/:id/stream", s.StreamProxyTest)
}

// setupDnsScanRoutes registers /api/dns-scans endpoints.
func (s *Server) setupDnsScanRoutes(rg *gin.RouterGroup) {
	dns := rg.Group("/dns-scans")
	dns.POST("", s.CreateDnsScan)
	dns.GET("/:id", s.GetDnsScan)
}

// setupTlsScanRoutes registers /api/tls-scans endpoints.
func (s *Server) setupTlsScanRoutes(rg *gin.RouterGroup) {
	tls := rg.Group("/tls-scans")
	tls.POST("", s.CreateTlsScan)
	tls.GET("/:id", s.GetTlsScan)
}

// setupSniScanRoutes registers /api/sni-scans endpoints.
func (s *Server) setupSniScanRoutes(rg *gin.RouterGroup) {
	sni := rg.Group("/sni-scans")
	sni.POST("", s.CreateSniScan)
	sni.GET("/:id", s.GetSniScan)
}

// setupDiagnosticRoutes registers /api/diagnostics endpoints.
func (s *Server) setupDiagnosticRoutes(rg *gin.RouterGroup) {
	diag := rg.Group("/diagnostics")
	diag.POST("", s.RunDiagnostic)
	diag.GET("/phases", s.GetDiagnosticPhases)
	diag.GET("/:id", s.GetDiagnostic)
	diag.GET("/:id/export", s.ExportDiagnostic)
	diag.GET("/geoip", s.HandleGeoIPLookup)
}

// setupSystemRoutes registers /api/system/* endpoints.
func (s *Server) setupSystemRoutes(rg *gin.RouterGroup) {
	sys := rg.Group("/system")

	// General
	sys.GET("/status", s.GetSystemStatus)
	sys.GET("/traffic", s.GetSystemTraffic)
	sys.POST("/traffic/reset", s.ResetSystemTraffic)

	// DNS
	sys.GET("/dns", s.GetDnsStatus)
	sys.POST("/dns", s.SetDns)
	sys.DELETE("/dns", s.ClearDns)

	// Proxy
	sys.GET("/proxy", s.GetProxyStatus)
	sys.POST("/proxy", s.SetProxy)
	sys.DELETE("/proxy", s.ClearProxy)
	sys.GET("/proxy.pac", s.GetProxyPAC)

	// DDNS
	sys.GET("/ddns", s.GetDdnsStatus)
	sys.POST("/ddns", s.SetDdnsConfig)
	sys.POST("/ddns/force", s.ForceDdns)

	// Profiles
	sys.GET("/profiles", s.GetProfiles)
	sys.POST("/profiles/:name/apply", s.ApplyProfile)

	// Startup
	sys.GET("/startup", s.GetStartupStatus)
	sys.POST("/startup", s.SetStartup)

	// Settings
	sys.GET("/settings", s.GetSystemSettings)
	sys.POST("/settings", s.SetSystemSettings)

	// Evasion Tunnel
	sys.GET("/evasion-tunnel", s.GetEvasionTunnelStatus)
	sys.POST("/evasion-tunnel", s.SetEvasionTunnel)
	sys.GET("/evasion-tunnel/logs", s.GetEvasionTunnelLogs)

	// TUN Router
	sys.GET("/tun-router", s.GetTunRouterStatus)
	sys.POST("/tun-router", s.SetTunRouter)

	// Advanced Bypass Engines (Tor & Psiphon)
	sys.GET("/engines", s.GetEnginesStatus)
	sys.POST("/engines", s.ControlEngine)

	// NCSI Fix
	sys.GET("/ncsi", s.GetSystemNCSI)
	sys.POST("/ncsi", s.SetSystemNCSI)
	sys.POST("/ncsi/reset", s.ResetSystemNCSI)

	// Provisioning & Deploy (Session 9)
	sys.POST("/provision/vps", s.StartVpsProvision)
	sys.POST("/provision/worker", s.StartEdgeDeploy)

	// Covert client tracker (IP-Tracker adoption)
	covert := sys.Group("/covert")
	{
		covert.GET("/links", s.GetCovertLinks)
		covert.POST("/links", s.CreateCovertLink)
		covert.GET("/visits", s.GetCovertVisits)
		covert.POST("/visits/clear", s.ClearCovertVisits)
		covert.GET("/stats", s.GetCovertStats)
	}
}

// setupHistoryRoutes registers /api/history and /api/export endpoints.
func (s *Server) setupHistoryRoutes(rg *gin.RouterGroup) {
	rg.GET("/history", s.GetHistory)
	rg.DELETE("/history", s.ClearHistory)
	rg.GET("/export", s.ExportHistory)
	rg.GET("/jobs/:id", s.GetJob)
	rg.POST("/jobs/:id/cancel", s.CancelJob)
}

// setupCapabilitiesRoute registers /api/capabilities endpoint.
func (s *Server) setupCapabilitiesRoute(rg *gin.RouterGroup) {
	rg.GET("/capabilities", s.GetCapabilities)
}

// setupServerConfigRoute registers /api/server-config endpoint.
func (s *Server) setupServerConfigRoute(rg *gin.RouterGroup) {
	rg.GET("/server-config", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"host":    s.config.Host,
			"port":    s.config.Port,
			"version": "0.1.0",
		})
	})
}

// setupTelegramRoutes registers /api/telegram/* endpoints.
func (s *Server) setupTelegramRoutes(rg *gin.RouterGroup) {
	tg := rg.Group("/telegram")
	tg.GET("/mtproto", s.GetTelegramMTProtoProxies)
}

// setupSubscriptionRoutes registers /api/subscriptions endpoints.
func (s *Server) setupSubscriptionRoutes(rg *gin.RouterGroup) {
	subs := rg.Group("/subscriptions")
	subs.POST("/aggregate", s.AggregateSubscriptionsHandler)
	subs.POST("/shape", s.ShapeSubscriptionHandler)
}

// setupWebSocketRoute registers the /ws endpoint for the WebSocket hub.
func (s *Server) setupWebSocketRoute(r *gin.Engine) {
	r.GET("/ws", AuthMiddleware(s.config.APIKey), func(c *gin.Context) {
		s.hub.ServeWs(c.Writer, c.Request, s.config.AllowedOrigins)
	})
}

// Run starts the HTTP server and blocks until shutdown.
func (s *Server) Run() error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// Hub returns the WebSocket hub for broadcasting events.
func (s *Server) Hub() *Hub {
	return s.hub
}
