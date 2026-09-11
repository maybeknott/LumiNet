// Package api implements the HTTP/WebSocket API server for LumiNet.
package api

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/contracts/buildinfo"
	"github.com/maybeknott/luminet/internal/foundation/capabilities"
	"github.com/maybeknott/luminet/internal/foundation/config"
	"github.com/maybeknott/luminet/internal/foundation/store"
	"github.com/maybeknott/luminet/internal/integrations/sub"
	"github.com/maybeknott/luminet/internal/runtime/proxy"
	"github.com/maybeknott/luminet/internal/workflows/jobs"
)

type ServerConfig struct {
	Host           string
	Port           int
	APIKey         string
	AllowedOrigins []string
	RateLimitRPS   int
	WebDist        fs.FS
	EnableWeb      bool
}

type Server struct {
	config              *ServerConfig
	router              *gin.Engine
	hub                 *Hub
	jobManager          *jobs.JobManager
	store               *store.DB
	configManager       *config.Manager
	startTime           time.Time
	httpServer          *http.Server
	capabilities        *capabilities.Registry
	wsSessions          *websocketSessionIssuer
	browserSessions     *browserSessionIssuer
	hubCancel           context.CancelFunc
	profileService      *sub.ProfileService
	subscriptionRuntime *proxy.SubscriptionRuntime
}

func NewServer(ctx context.Context, config *ServerConfig, jobMgr *jobs.JobManager, st *store.DB, cfgMgr *config.Manager, reg *capabilities.Registry) *Server {
	gin.SetMode(gin.ReleaseMode)
	if ctx == nil {
		ctx = context.Background()
	}
	hubCtx, hubCancel := context.WithCancel(ctx)
	hub := NewHub(jobMgr)
	go hub.Run(hubCtx)

	profileService := sub.NewProfileServiceWithContext(ctx, sub.NewEgress(sub.EgressConfig{Enabled: true}))
	profileService.StartAutoRefresh(time.Minute)
	subscriptionRuntime := proxy.NewSubscriptionRuntime(proxy.NewCoreManager(proxy.CoreTypeAuto, ""))

	s := &Server{
		config:              config,
		hub:                 hub,
		jobManager:          jobMgr,
		store:               st,
		configManager:       cfgMgr,
		startTime:           time.Now(),
		capabilities:        reg,
		wsSessions:          newWebsocketSessionIssuer(),
		browserSessions:     newBrowserSessionIssuer(),
		hubCancel:           hubCancel,
		profileService:      profileService,
		subscriptionRuntime: subscriptionRuntime,
	}

	cfg := cfgMgr.Get()
	if cfg != nil {
		proxy.GetEvasionManager().SetHostsOverride(cfg.HostsOverride)
	}

	s.router = s.SetupRouter()
	return s
}

func (s *Server) SetupRouter() *gin.Engine {
	r := gin.New()
	if err := r.SetTrustedProxies(nil); err != nil {
		panic(fmt.Sprintf("failed to disable API trusted proxies: %v", err))
	}
	s.setupMiddleware(r)
	s.setupHealthRoutes(r)
	s.setupVersionRoute(r)
	s.setupRouteIntrospection(r)
	s.setupWebSocketRoute(r)

	api := r.Group("/api")
	api.Use(AuthMiddlewareWithBrowserSession(s.config.APIKey, s.browserSessions))
	routeCatalog{server: s}.register(api)

	if !s.config.EnableWeb {
		r.NoRoute(func(c *gin.Context) { c.JSON(http.StatusNotFound, gin.H{"error": "not found"}) })
		return r
	}

	webFS := s.config.WebDist
	if webFS == nil {
		r.NoRoute(func(c *gin.Context) { c.JSON(http.StatusNotFound, gin.H{"error": "not found"}) })
	} else {
		fileServer := http.FileServer(http.FS(webFS))
		serveIndexHTML := func(c *gin.Context) {
			data, err := fs.ReadFile(webFS, "index.html")
			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "frontend not found"})
				return
			}

			if s.config.APIKey != "" {
				token, expiresAt, err := s.browserSessions.issue(time.Now())
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create browser session"})
					return
				}
				http.SetCookie(c.Writer, &http.Cookie{
					Name:     SessionCookieName,
					Value:    token,
					Path:     "/",
					HttpOnly: true,
					SameSite: http.SameSiteStrictMode,
					Expires:  expiresAt,
					MaxAge:   int(time.Until(expiresAt).Seconds()),
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

			f, err := webFS.Open(filePath)
			if err == nil {
				_ = f.Close()
				fileServer.ServeHTTP(c.Writer, c.Request)
				return
			}
			serveIndexHTML(c)
		})
	}

	return r
}

func (s *Server) setupMiddleware(r *gin.Engine) {
	r.Use(AuthorityMiddleware(s.config.Host, s.config.Port))
	r.Use(RecoveryMiddleware())
	r.Use(RequestLogger())
	r.Use(CorsMiddleware(s.config.AllowedOrigins))
	if s.config.RateLimitRPS > 0 {
		r.Use(RateLimitMiddleware(s.config.RateLimitRPS))
	}
}

func (s *Server) setupHealthRoutes(r *gin.Engine) {
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "timestamp": time.Now().UTC(), "version": buildinfo.Version})
	})
}

func (s *Server) setupWebSocketRoute(r *gin.Engine) {
	r.GET("/ws", func(c *gin.Context) {
		s.hub.ServeWs(c.Writer, c.Request, s.config.AllowedOrigins, func(token string) bool {
			return s.wsSessions.consume(token, time.Now())
		})
	})
}

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

func (s *Server) Shutdown(ctx context.Context) error {
	var shutdownErrors []error
	if s.subscriptionRuntime != nil {
		if err := s.subscriptionRuntime.Close(); err != nil {
			shutdownErrors = append(shutdownErrors, err)
		}
	}
	if s.profileService != nil {
		if err := s.profileService.Close(ctx); err != nil {
			shutdownErrors = append(shutdownErrors, err)
		}
	}
	if s.hubCancel != nil {
		s.hubCancel()
	}
	if s.hub != nil {
		select {
		case <-s.hub.Done():
		case <-ctx.Done():
			shutdownErrors = append(shutdownErrors, ctx.Err())
		}
	}
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			shutdownErrors = append(shutdownErrors, err)
		}
	}
	return errors.Join(shutdownErrors...)
}

func (s *Server) Hub() *Hub { return s.hub }
