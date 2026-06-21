package api

import (
	"crypto/subtle"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// SessionCookieName is the name of the HttpOnly, SameSite=Strict cookie used to
// carry the API key to browser clients (including the WebSocket handshake, which
// cannot set custom headers). Browsers send it automatically on same-origin
// requests, and SameSite=Strict prevents it from riding cross-site requests —
// providing CSRF protection for the privileged control API.
const SessionCookieName = "luminet_session"

// AuthMiddleware returns a Gin middleware that validates API key authentication.
// If apiKey is empty, the middleware is a no-op (all requests are allowed). In
// normal operation the serve command always supplies a key (auto-generated when
// none is passed), so the no-op branch is exercised only by tests.
//
// The key is accepted via the X-API-Key header (CLI/REST clients) or the
// SessionCookieName cookie (browser clients). The ?api_key= query parameter is
// intentionally NOT accepted, to keep the secret out of URLs, logs, history,
// and Referer headers.
func AuthMiddleware(apiKey string) gin.HandlerFunc {
	if apiKey == "" {
		return func(c *gin.Context) { c.Next() }
	}
	want := []byte(apiKey)
	return func(c *gin.Context) {
		key := c.GetHeader("X-API-Key")
		if key == "" {
			if cookie, err := c.Cookie(SessionCookieName); err == nil {
				key = cookie
			}
		}
		if subtle.ConstantTimeCompare([]byte(key), want) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized: invalid or missing API key",
			})
			return
		}
		c.Next()
	}
}

// CorsMiddleware returns a Gin middleware that handles Cross-Origin Resource Sharing headers.
func CorsMiddleware(allowedOrigins []string) gin.HandlerFunc {
	originSet := make(map[string]bool, len(allowedOrigins))
	allowAll := false
	for _, o := range allowedOrigins {
		if o == "*" {
			allowAll = true
		}
		originSet[o] = true
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		// Only ever reflect an explicitly allowed origin. There is no wildcard
		// fallback: an unknown cross-origin caller receives no CORS grant, so
		// the browser blocks it from reading responses. Credentials are enabled
		// so the SameSite cookie flows on same-origin requests.
		if origin != "" && (allowAll || originSet[origin]) {
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

// tokenBucket is a simple per-IP token bucket for rate limiting.
type tokenBucket struct {
	tokens     float64
	lastRefill time.Time
	mu         sync.Mutex
}

// RateLimitMiddleware returns a Gin middleware that enforces per-client rate limiting.
// rps is the maximum number of requests per second per client IP.
func RateLimitMiddleware(rps int) gin.HandlerFunc {
	if rps <= 0 {
		return func(c *gin.Context) { c.Next() }
	}

	buckets := make(map[string]*tokenBucket)
	var mu sync.Mutex
	rate := float64(rps)

	// Periodic sweep of idle buckets to prevent memory leaks (F-15)
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		for range ticker.C {
			mu.Lock()
			now := time.Now()
			for ip, bucket := range buckets {
				bucket.mu.Lock()
				idle := now.Sub(bucket.lastRefill)
				bucket.mu.Unlock()
				if idle > 1*time.Hour {
					delete(buckets, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return func(c *gin.Context) {
		ip := c.ClientIP()

		mu.Lock()
		bucket, exists := buckets[ip]
		if !exists {
			bucket = &tokenBucket{
				tokens:     rate,
				lastRefill: time.Now(),
			}
			buckets[ip] = bucket
		}
		mu.Unlock()

		bucket.mu.Lock()
		defer bucket.mu.Unlock()

		now := time.Now()
		elapsed := now.Sub(bucket.lastRefill).Seconds()
		bucket.tokens += elapsed * rate
		if bucket.tokens > rate {
			bucket.tokens = rate
		}
		bucket.lastRefill = now

		if bucket.tokens < 1.0 {
			c.Header("Retry-After", "1")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
			})
			return
		}
		bucket.tokens--
		c.Next()
	}
}

// RecoveryMiddleware returns a Gin middleware that recovers from panics
// and returns a 500 Internal Server Error with structured error JSON.
func RecoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[PANIC] %v", r)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "internal server error",
				})
			}
		}()
		c.Next()
	}
}

// sanitizeQuery masks sensitive query parameter values (like api_key) to prevent log leakage.
func sanitizeQuery(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	for i, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			k := strings.ToLower(kv[0])
			if k == "api_key" || k == "api-key" || k == "token" || k == "secret" {
				parts[i] = kv[0] + "=***"
			}
		}
	}
	return strings.Join(parts, "&")
}

// RequestLogger returns a Gin middleware that logs each incoming request
// with method, path, status code, latency, and client IP using structured logging.
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

		// Skip health check noise
		if strings.HasPrefix(path, "/health") {
			return
		}

		log.Printf("[API] %s %s %d %s %s",
			method, path, status, latency.Round(time.Millisecond), clientIP)
	}
}
