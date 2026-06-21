// Package proxy implements proxy URI parsing, testing, subscription management,
// and core instance lifecycle for various proxy protocols.
package proxy

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/geoip"
)

// ClashRuleType represents the type of Clash/Mihomo rule.
type ClashRuleType string

const (
	RuleTypeDomain        ClashRuleType = "DOMAIN"
	RuleTypeDomainSuffix  ClashRuleType = "DOMAIN-SUFFIX"
	RuleTypeDomainKeyword ClashRuleType = "DOMAIN-KEYWORD"
	RuleTypeGeoIP         ClashRuleType = "GEOIP"
	RuleTypeIPCidr        ClashRuleType = "IP-CIDR"
	RuleTypeSrcIPCidr     ClashRuleType = "SRC-IP-CIDR"
	RuleTypeMatch         ClashRuleType = "MATCH"
)

// ClashRule defines a single parsed Clash routing rule.
type ClashRule struct {
	Type        ClashRuleType `json:"type"`
	Payload     string        `json:"payload"`
	OutboundTag string        `json:"outbound_tag"`
	IPNet       *net.IPNet    `json:"-"`
}

// ClashMetaRouter handles Mihomo (Clash.Meta) routing rules evaluation.
type ClashMetaRouter struct {
	mu           sync.RWMutex
	Rules        []ClashRule
	GeoIPService *geoip.Service
	dnsCache     sync.Map
}

// NewClashMetaRouter creates a new ClashMetaRouter instance.
func NewClashMetaRouter(geoipDbPath string) (*ClashMetaRouter, error) {
	svc, err := geoip.NewService(geoipDbPath)
	if err != nil {
		return nil, err
	}
	return &ClashMetaRouter{
		GeoIPService: svc,
	}, nil
}

// ClearDNSCache flushes the routing DNS cache.
func (r *ClashMetaRouter) ClearDNSCache() {
	r.dnsCache.Range(func(key, value interface{}) bool {
		r.dnsCache.Delete(key)
		return true
	})
	log.Println("Clash router DNS cache cleared successfully to prevent DNS leak tracking")
}

// AddRules parses and appends new routing rules.
func (r *ClashMetaRouter) AddRules(ruleStrings []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var newRules []ClashRule
	for _, ruleStr := range ruleStrings {
		parts := strings.Split(ruleStr, ",")
		if len(parts) < 2 {
			continue
		}

		t := ClashRuleType(strings.ToUpper(strings.TrimSpace(parts[0])))
		var payload, tag string

		if t == RuleTypeMatch {
			tag = strings.TrimSpace(parts[1])
		} else if len(parts) >= 3 {
			payload = strings.TrimSpace(parts[1])
			tag = strings.TrimSpace(parts[2])
		} else {
			continue
		}

		rule := ClashRule{
			Type:        t,
			Payload:     payload,
			OutboundTag: tag,
		}

		if t == RuleTypeIPCidr || t == RuleTypeSrcIPCidr {
			_, ipNet, err := net.ParseCIDR(payload)
			if err == nil {
				rule.IPNet = ipNet
			}
		}

		newRules = append(newRules, rule)
	}

	r.Rules = newRules
	r.ClearDNSCache()
	return nil
}

// MatchOutbound evaluates host, destination IP, and source IP targets against Clash routing rules.
func (r *ClashMetaRouter) MatchOutbound(host string, destIP net.IP, srcIP net.IP) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	lowerHost := strings.ToLower(host)

	for _, rule := range r.Rules {
		switch rule.Type {
		case RuleTypeDomain:
			if lowerHost == strings.ToLower(rule.Payload) {
				return rule.OutboundTag
			}
		case RuleTypeDomainSuffix:
			if strings.HasSuffix(lowerHost, strings.ToLower(rule.Payload)) {
				return rule.OutboundTag
			}
		case RuleTypeDomainKeyword:
			if strings.Contains(lowerHost, strings.ToLower(rule.Payload)) {
				return rule.OutboundTag
			}
		case RuleTypeIPCidr:
			if destIP != nil && rule.IPNet != nil {
				if rule.IPNet.Contains(destIP) {
					return rule.OutboundTag
				}
			}
		case RuleTypeSrcIPCidr:
			if srcIP != nil && rule.IPNet != nil {
				if rule.IPNet.Contains(srcIP) {
					return rule.OutboundTag
				}
			}
		case RuleTypeGeoIP:
			if destIP != nil {
				// Query country code using geoip Service
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				_, code, _, _, _, _, err := r.GeoIPService.Lookup(ctx, destIP.String())
				cancel()
				if err == nil && strings.EqualFold(code, rule.Payload) {
					return rule.OutboundTag
				}
			}
		case RuleTypeMatch:
			return rule.OutboundTag
		}
	}

	return "DIRECT" // Default fallback outbound tag
}

// ProviderConfigLoader handles periodic configuration updates from remote subscription sources.
type ProviderConfigLoader struct {
	mu         sync.Mutex
	providers  map[string]*ProviderSource
	httpClient *http.Client
	router     *ClashMetaRouter
}

// ProviderSource represents a single managed provider subscription source.
type ProviderSource struct {
	Name     string
	URL      string
	Interval time.Duration
	stopChan chan struct{}
}

// NewProviderConfigLoader initializes a ProviderConfigLoader.
func NewProviderConfigLoader(router *ClashMetaRouter) *ProviderConfigLoader {
	return &ProviderConfigLoader{
		providers: make(map[string]*ProviderSource),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		router: router,
	}
}

// AddProvider registers and schedules a remote config source provider.
func (l *ProviderConfigLoader) AddProvider(name string, url string, interval time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Stop existing provider if it has the same name
	if old, exists := l.providers[name]; exists {
		close(old.stopChan)
	}

	stopChan := make(chan struct{})
	p := &ProviderSource{
		Name:     name,
		URL:      url,
		Interval: interval,
		stopChan: stopChan,
	}
	l.providers[name] = p

	go l.runUpdateLoop(p)
}

// StopAll stops all periodic configuration source updates.
func (l *ProviderConfigLoader) StopAll() {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, p := range l.providers {
		close(p.stopChan)
	}
	l.providers = make(map[string]*ProviderSource)
}

func (l *ProviderConfigLoader) runUpdateLoop(p *ProviderSource) {
	ticker := time.NewTicker(p.Interval)
	defer ticker.Stop()

	// Trigger initial update immediately
	l.triggerUpdate(p)

	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			l.triggerUpdate(p)
		}
	}
}

func (l *ProviderConfigLoader) triggerUpdate(p *ProviderSource) {
	log.Printf("Triggering provider config source update for: %s", p.Name)
	resp, err := l.httpClient.Get(p.URL)
	if err != nil {
		log.Printf("Provider %s fetch failed: %v", p.Name, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Provider %s fetch returned status code: %d", p.Name, resp.StatusCode)
		return
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Provider %s body read failed: %v", p.Name, err)
		return
	}

	// Dynamic update of routing configuration rules
	var rulesContainer struct {
		Rules []string `yaml:"rules"`
	}

	// Simple parser or unmarshaler (yaml/json) depending on header content-type
	if strings.Contains(resp.Header.Get("Content-Type"), "yaml") || strings.HasSuffix(p.URL, ".yaml") {
		// Mock parse rules from yaml string blocks
		lines := strings.Split(string(data), "\n")
		var extractedRules []string
		inRulesBlock := false
		for _, line := range lines {
			lineTrimmed := strings.TrimSpace(line)
			if lineTrimmed == "rules:" {
				inRulesBlock = true
				continue
			}
			if inRulesBlock {
				if strings.HasPrefix(lineTrimmed, "-") {
					extractedRules = append(extractedRules, strings.TrimPrefix(lineTrimmed, "- "))
				} else if lineTrimmed != "" && !strings.Contains(lineTrimmed, ":") {
					extractedRules = append(extractedRules, lineTrimmed)
				} else if strings.Contains(lineTrimmed, ":") {
					break
				}
			}
		}
		rulesContainer.Rules = extractedRules
	} else {
		_ = json.Unmarshal(data, &rulesContainer)
	}

	if len(rulesContainer.Rules) > 0 {
		_ = l.router.AddRules(rulesContainer.Rules)
		log.Printf("Provider %s updated: %d rules loaded and DNS cache cleared", p.Name, len(rulesContainer.Rules))
	}
}

// TokenAuthMiddleware verifies API token auth credentials.
func TokenAuthMiddleware(secretToken string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if secretToken == "" {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		token := c.Query("token")

		if authHeader != "" {
			parts := strings.Split(authHeader, " ")
			if len(parts) == 2 && parts[0] == "Bearer" {
				token = parts[1]
			}
		}

		if token != secretToken {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Unauthorized: invalid secret token parameters",
			})
			return
		}
		c.Next()
	}
}

// RegisterDashboardRoutes configures web routing for local Yacd/Metacubexd dashboards and APIs.
func RegisterDashboardRoutes(router *gin.Engine, staticDir string, secretToken string, clashRouter *ClashMetaRouter) {
	// API Group with token authentication audit safety
	api := router.Group("/api/v1")
	api.Use(TokenAuthMiddleware(secretToken))
	{
		api.GET("/rules", func(c *gin.Context) {
			clashRouter.mu.RLock()
			defer clashRouter.mu.RUnlock()
			c.JSON(http.StatusOK, gin.H{
				"rules": clashRouter.Rules,
			})
		})

		api.POST("/rules", func(c *gin.Context) {
			var req struct {
				Rules []string `json:"rules"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			if err := clashRouter.AddRules(req.Rules); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "Rules updated successfully"})
		})

		api.POST("/dns/flush", func(c *gin.Context) {
			clashRouter.ClearDNSCache()
			c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "DNS cache flushed"})
		})
	}

	// Serve Static Dashboard files
	if _, err := os.Stat(staticDir); err == nil {
		router.StaticFS("/dashboard", http.Dir(staticDir))
		router.GET("/", func(c *gin.Context) {
			c.Redirect(http.StatusMovedPermanently, "/dashboard")
		})
		log.Printf("Serving local Yacd/Metacubexd dashboard console from: %s at /dashboard", staticDir)
	} else {
		// Mock default console index response if directory is missing
		router.GET("/dashboard", func(c *gin.Context) {
			c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(`
				<!DOCTYPE html>
				<html>
				<head>
					<title>LumiNet Metacubexd Console Mock</title>
					<style>
						body { font-family: sans-serif; background: #121212; color: #ffffff; padding: 40px; text-align: center; }
						.box { border: 1px solid #333; padding: 20px; border-radius: 8px; max-width: 500px; margin: 40px auto; background: #1e1e1e; }
					</style>
				</head>
				<body>
					<div class="box">
						<h2>LumiNet Metacubexd Console Mock</h2>
						<p>Standard static UI console mock. REST API is active under <code>/api/v1/</code>.</p>
					</div>
				</body>
				</html>
			`))
		})
	}
}
