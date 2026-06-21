package proxy

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func makeTestToken(claims OIDCClaims, secret []byte) string {
	header := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" // {"alg": "HS256", "typ": "JWT"}
	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signingInput := header + "." + payload
	sig := hmacSHA256(signingInput, secret)
	sigStr := base64.RawURLEncoding.EncodeToString(sig)

	return header + "." + payload + "." + sigStr
}

func TestValidateOIDCToken(t *testing.T) {
	secret := []byte("my-test-secret-key-12345678")
	claims := OIDCClaims{
		Issuer:    "https://auth.example.com",
		Subject:   "usr_100",
		Audience:  "luminet_app",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	validToken := makeTestToken(claims, secret)

	// 1. Success case
	parsed, err := ValidateOIDCToken(validToken, secret, "https://auth.example.com", "luminet_app")
	if err != nil {
		t.Fatalf("Expected valid token to pass, got: %v", err)
	}
	if parsed.Subject != "usr_100" {
		t.Errorf("Expected subject 'usr_100', got %q", parsed.Subject)
	}

	// 2. Expired token case
	expiredClaims := claims
	expiredClaims.ExpiresAt = time.Now().Add(-5 * time.Minute).Unix()
	expiredToken := makeTestToken(expiredClaims, secret)
	_, err = ValidateOIDCToken(expiredToken, secret, "https://auth.example.com", "luminet_app")
	if err == nil || err.Error() != "token has expired" {
		t.Errorf("Expected token has expired error, got: %v", err)
	}

	// 3. Signature verification failure case
	wrongSecret := []byte("wrong-secret-key-99999")
	_, err = ValidateOIDCToken(validToken, wrongSecret, "https://auth.example.com", "luminet_app")
	if err == nil || err.Error() != "invalid signature" {
		t.Errorf("Expected invalid signature error, got: %v", err)
	}

	// 4. Issuer mismatch case
	_, err = ValidateOIDCToken(validToken, secret, "https://wrong.issuer.com", "luminet_app")
	if err == nil || !testingMatchIssuerError(err) {
		t.Errorf("Expected issuer mismatch error, got: %v", err)
	}

	// 5. Audience mismatch case
	_, err = ValidateOIDCToken(validToken, secret, "https://auth.example.com", "wrong_app")
	if err == nil || !testingMatchAudienceError(err) {
		t.Errorf("Expected audience mismatch error, got: %v", err)
	}
}

func testingMatchIssuerError(err error) bool {
	return len(err.Error()) > 15 && err.Error()[:15] == "issuer mismatch"
}

func testingMatchAudienceError(err error) bool {
	return len(err.Error()) > 17 && err.Error()[:17] == "audience mismatch"
}

func TestOIDCAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	secret := []byte("secret")
	r.Use(OIDCAuthMiddleware(secret, "https://issuer", "audience"))

	r.GET("/protected", func(c *gin.Context) {
		claims, _ := c.Get("oidc_claims")
		c.JSON(http.StatusOK, gin.H{"subject": claims.(*OIDCClaims).Subject})
	})

	claims := OIDCClaims{
		Issuer:    "https://issuer",
		Subject:   "admin",
		Audience:  "audience",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}

	token := makeTestToken(claims, secret)

	// Call protected route with valid token
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Call protected route with missing authorization header
	reqMissing, _ := http.NewRequest("GET", "/protected", nil)
	wMissing := httptest.NewRecorder()
	r.ServeHTTP(wMissing, reqMissing)
	if wMissing.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 on missing auth, got %d", wMissing.Code)
	}
}

func TestOIDCAuthHandler(t *testing.T) {
	secret := []byte("secret")
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := OIDCAuthHandler(nextHandler, secret, "https://issuer", "audience")

	claims := OIDCClaims{
		Issuer:    "https://issuer",
		Subject:   "admin",
		Audience:  "audience",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}
	token := makeTestToken(claims, secret)

	// Case 1: Success
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Case 2: Expired
	expiredClaims := claims
	expiredClaims.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix()
	expiredToken := makeTestToken(expiredClaims, secret)
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("Authorization", "Bearer "+expiredToken)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w2.Code)
	}
}

func TestSanitizeRedirectURL(t *testing.T) {
	allowedHosts := []string{"localhost", "127.0.0.1", "luminet.io"}

	// Case 1: Valid absolute URL
	val, err := SanitizeRedirectURL("http://localhost:8080/callback", allowedHosts)
	if err != nil {
		t.Errorf("Expected success, got error: %v", err)
	}
	if val != "http://localhost:8080/callback" {
		t.Errorf("Expected original URL, got %q", val)
	}

	// Case 2: Valid relative URL
	valRel, err := SanitizeRedirectURL("/relative/path?code=123", allowedHosts)
	if err != nil {
		t.Errorf("Expected relative URL to pass, got: %v", err)
	}
	if valRel != "/relative/path?code=123" {
		t.Errorf("Expected relative path unchanged, got %q", valRel)
	}

	// Case 3: Invalid open redirect URL
	_, err = SanitizeRedirectURL("https://attacker.com/malicious", allowedHosts)
	if err == nil {
		t.Errorf("Expected open redirect URL to fail, but it succeeded")
	}
}

func TestHMACPayloadSignatures(t *testing.T) {
	secret := []byte("super-secret-key-value")
	payload := []byte("some-request-block-data")

	sig := SignPayload(payload, secret)
	if !VerifyPayloadSignature(payload, sig, secret) {
		t.Errorf("HMAC signature verification failed")
	}

	if VerifyPayloadSignature([]byte("modified-payload"), sig, secret) {
		t.Errorf("HMAC signature verification should have failed on modified payload")
	}
}

func TestAutoTLSManager(t *testing.T) {
	// Creating an AutoTLSManager should return a non-nil TLS Config
	tDir := t.TempDir()
	mgr := NewAutoTLSManager(tDir, "luminet.io", "www.luminet.io")
	tlsConfig := mgr.GetTLSConfig()

	if tlsConfig == nil {
		t.Fatalf("Expected TLS configuration, got nil")
	}
	if tlsConfig.GetCertificate == nil {
		t.Errorf("Expected GetCertificate callback to be configured")
	}
}
