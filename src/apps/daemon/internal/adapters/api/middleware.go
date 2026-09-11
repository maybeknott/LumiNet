package api

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/foundation/redact"
)

// SessionCookieName identifies the opaque browser control-session cookie. The
// API key itself is never persisted in a browser cookie.
const SessionCookieName = "luminet_session"

// AuthMiddleware validates header-based API-key authentication for non-browser
// clients. Browser sessions are intentionally handled by
// AuthMiddlewareWithBrowserSession so the raw API key never becomes a cookie.
func AuthMiddleware(apiKey string) gin.HandlerFunc {
	return authMiddleware(apiKey, nil)
}

// AuthMiddlewareWithBrowserSession accepts either the X-API-Key header or a
// separately generated, short-lived opaque browser session cookie.
func AuthMiddlewareWithBrowserSession(apiKey string, sessions *browserSessionIssuer) gin.HandlerFunc {
	return authMiddleware(apiKey, sessions)
}

func authMiddleware(apiKey string, sessions *browserSessionIssuer) gin.HandlerFunc {
	if apiKey == "" {
		return func(c *gin.Context) {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error":  "authentication unavailable",
				"reason": "API_KEY_UNINITIALIZED",
			})
		}
	}
	want := []byte(apiKey)
	return func(c *gin.Context) {
		key := c.GetHeader("X-API-Key")
		if key != "" && subtle.ConstantTimeCompare([]byte(key), want) == 1 {
			c.Next()
			return
		}
		if sessions != nil {
			if cookie, err := c.Cookie(SessionCookieName); err == nil && sessions.valid(cookie, time.Now()) {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "unauthorized: invalid or missing API credential",
		})
	}
}

// AuthorityMiddleware rejects requests whose HTTP Host authority does not
// identify the configured listener or an explicit loopback alias. This makes a
// browser unable to carry a privileged opaque session through DNS rebinding to
// the local daemon.
func AuthorityMiddleware(configuredHost string, configuredPort int) gin.HandlerFunc {
	if configuredPort <= 0 {
		return func(c *gin.Context) { c.Next() }
	}
	allowedHosts := map[string]struct{}{
		"localhost": {},
		"127.0.0.1": {},
		"::1":       {},
	}
	if host := strings.TrimSpace(strings.Trim(configuredHost, "[]")); host != "" {
		allowedHosts[strings.ToLower(host)] = struct{}{}
	}
	return func(c *gin.Context) {
		host, port, err := splitAuthority(c.Request.Host)
		if err != nil || port != configuredPort {
			c.AbortWithStatusJSON(http.StatusMisdirectedRequest, gin.H{"error": "unrecognized request authority"})
			return
		}
		if _, ok := allowedHosts[strings.ToLower(host)]; !ok {
			c.AbortWithStatusJSON(http.StatusMisdirectedRequest, gin.H{"error": "unrecognized request authority"})
			return
		}
		c.Next()
	}
}

func splitAuthority(authority string) (string, int, error) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", 0, fmt.Errorf("empty authority")
	}
	host, portText, err := net.SplitHostPort(authority)
	if err != nil {
		return "", 0, err
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		return "", 0, err
	}
	return strings.Trim(host, "[]"), port, nil
}

// CorsMiddleware is also an origin gate for browser control requests. Unknown
// non-empty origins are rejected rather than merely being denied response-read
// permission by CORS.
func CorsMiddleware(allowedOrigins []string) gin.HandlerFunc {
	originSet := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		if o != "*" {
			originSet[o] = true
		}
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" && !originSet[origin] {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "origin not allowed"})
			return
		}
		if origin != "" {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Vary", "Origin")
		}

		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization, X-API-Key")
		c.Header("Access-Control-Expose-Headers", "Content-Length, Content-Type")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

type tokenBucket struct {
	tokens     float64
	lastRefill time.Time
	mu         sync.Mutex
}

func RateLimitMiddleware(rps int) gin.HandlerFunc {
	if rps <= 0 {
		return func(c *gin.Context) { c.Next() }
	}

	buckets := make(map[string]*tokenBucket)
	var mu sync.Mutex
	rate := float64(rps)
	lastSweep := time.Now()

	return func(c *gin.Context) {
		ip := c.ClientIP()

		mu.Lock()
		now := time.Now()
		if now.Sub(lastSweep) >= 10*time.Minute {
			for key, existing := range buckets {
				existing.mu.Lock()
				idle := now.Sub(existing.lastRefill)
				existing.mu.Unlock()
				if idle > time.Hour {
					delete(buckets, key)
				}
			}
			lastSweep = now
		}
		bucket, exists := buckets[ip]
		if !exists {
			bucket = &tokenBucket{tokens: rate, lastRefill: time.Now()}
			buckets[ip] = bucket
		}
		mu.Unlock()

		bucket.mu.Lock()
		defer bucket.mu.Unlock()

		now = time.Now()
		elapsed := now.Sub(bucket.lastRefill).Seconds()
		bucket.tokens += elapsed * rate
		if bucket.tokens > rate {
			bucket.tokens = rate
		}
		bucket.lastRefill = now

		if bucket.tokens < 1.0 {
			c.Header("Retry-After", "1")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}
		bucket.tokens--
		c.Next()
	}
}

func RecoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[PANIC] %v", r)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			}
		}()
		c.Next()
	}
}

func sanitizeQuery(raw string) string {
	return redact.String(raw)
}

func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		method := c.Request.Method
		clientIP := c.ClientIP()
		if raw != "" {
			path = path + "?" + sanitizeQuery(raw)
		}
		if strings.HasPrefix(path, "/health") {
			return
		}
		log.Printf("[API] %s %s %d %s %s", method, path, status, latency.Round(time.Millisecond), clientIP)
	}
}
