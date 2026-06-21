package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/acme/autocert"
)

// OIDCClaims defines the standard claims inside an OpenID Connect token.
type OIDCClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
}

// ValidateOIDCToken parses and validates claims in an OIDC JWT token.
// If secretKey is provided, it verifies the signature of the token.
func ValidateOIDCToken(tokenString string, secretKey []byte, expectedIssuer string, expectedAudience string) (*OIDCClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	// Validate signature if secretKey is provided
	if len(secretKey) > 0 {
		signingInput := parts[0] + "." + parts[1]
		expectedSig := hmacSHA256(signingInput, secretKey)
		actualSig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			return nil, fmt.Errorf("failed to decode signature: %w", err)
		}
		if !hmac.Equal(actualSig, expectedSig) {
			return nil, errors.New("invalid signature")
		}
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var claims OIDCClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	now := time.Now().Unix()
	if claims.ExpiresAt > 0 && claims.ExpiresAt < now {
		return nil, errors.New("token has expired")
	}

	if expectedIssuer != "" && claims.Issuer != expectedIssuer {
		return nil, fmt.Errorf("issuer mismatch: expected %q, got %q", expectedIssuer, claims.Issuer)
	}

	if expectedAudience != "" && claims.Audience != expectedAudience {
		return nil, fmt.Errorf("audience mismatch: expected %q, got %q", expectedAudience, claims.Audience)
	}

	return &claims, nil
}

func hmacSHA256(data string, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// OIDCAuthMiddleware returns a Gin middleware that validates OIDC tokens.
func OIDCAuthMiddleware(secretKey []byte, expectedIssuer string, expectedAudience string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header must be Bearer token"})
			return
		}

		claims, err := ValidateOIDCToken(parts[1], secretKey, expectedIssuer, expectedAudience)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("invalid token: %v", err)})
			return
		}

		c.Set("oidc_claims", claims)
		c.Next()
	}
}

// OIDCAuthHandler returns a standard http.Handler middleware validating OIDC tokens.
func OIDCAuthHandler(next http.Handler, secretKey []byte, expectedIssuer string, expectedAudience string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header is required", http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			http.Error(w, "Authorization header must be Bearer token", http.StatusUnauthorized)
			return
		}

		_, err := ValidateOIDCToken(parts[1], secretKey, expectedIssuer, expectedAudience)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid token: %v", err), http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// SanitizeRedirectURL parses and sanitizes redirect URLs to prevent Open Redirect vulnerability.
func SanitizeRedirectURL(rawURL string, allowedHosts []string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	host := parsed.Hostname()
	if host == "" {
		// Relative path redirects are safe
		return rawURL, nil
	}

	allowed := false
	for _, allowedHost := range allowedHosts {
		if strings.EqualFold(host, allowedHost) {
			allowed = true
			break
		}
	}

	if !allowed {
		return "", fmt.Errorf("redirect URL target %q is not in whitelist of allowed hosts", host)
	}

	return rawURL, nil
}

// SignPayload generates a hex encoded HMAC-SHA256 signature of a payload.
func SignPayload(payload []byte, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyPayloadSignature validates a hex encoded HMAC-SHA256 signature of a payload.
func VerifyPayloadSignature(payload []byte, signatureHex string, secret []byte) bool {
	actualSig, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false
	}
	h := hmac.New(sha256.New, secret)
	h.Write(payload)
	expectedSig := h.Sum(nil)
	return hmac.Equal(actualSig, expectedSig)
}

// AutoTLSManager coordinates dynamic TLS certificate requests and renewals using ACME (autocert).
type AutoTLSManager struct {
	manager *autocert.Manager
}

// NewAutoTLSManager creates an ACME auto-TLS manager configured to cache certs.
func NewAutoTLSManager(cacheDir string, domains ...string) *AutoTLSManager {
	return &AutoTLSManager{
		manager: &autocert.Manager{
			Cache:      autocert.DirCache(cacheDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domains...),
		},
	}
}

// GetTLSConfig returns a tls.Config hooked to Let's Encrypt certificate resolution.
func (m *AutoTLSManager) GetTLSConfig() *tls.Config {
	return m.manager.TLSConfig()
}
