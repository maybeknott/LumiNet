package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

func newAuthEngine(key string) *gin.Engine {
	r := gin.New()
	r.Use(AuthMiddleware(key))
	r.GET("/protected", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func TestAuthMiddleware_RejectsMissingKey(t *testing.T) {
	r := newAuthEngine("secret-key")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing key: got %d, want 401", w.Code)
	}
}

func TestAuthMiddleware_RejectsWrongKey(t *testing.T) {
	r := newAuthEngine("secret-key")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-API-Key", "wrong")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key: got %d, want 401", w.Code)
	}
}

func TestAuthMiddleware_AcceptsHeaderKey(t *testing.T) {
	r := newAuthEngine("secret-key")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-API-Key", "secret-key")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("header key: got %d, want 200", w.Code)
	}
}

func TestAuthMiddleware_AcceptsCookieKey(t *testing.T) {
	r := newAuthEngine("secret-key")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "secret-key"})
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("cookie key: got %d, want 200", w.Code)
	}
}

func TestAuthMiddleware_IgnoresQueryParamKey(t *testing.T) {
	// The query parameter must NOT be honored — keeps the secret out of URLs.
	r := newAuthEngine("secret-key")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected?api_key=secret-key", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("query-param key should be rejected: got %d, want 401", w.Code)
	}
}

func TestCorsMiddleware_NoWildcardForUnknownOrigin(t *testing.T) {
	r := gin.New()
	r.Use(CorsMiddleware([]string{"http://127.0.0.1:8470"}))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", "https://evil.example")
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unknown origin should get no ACAO header, got %q", got)
	}
}

func TestCorsMiddleware_ReflectsAllowedOrigin(t *testing.T) {
	allowed := "http://127.0.0.1:8470"
	r := gin.New()
	r.Use(CorsMiddleware([]string{allowed}))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", allowed)
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != allowed {
		t.Fatalf("allowed origin: got ACAO %q, want %q", got, allowed)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("allowed origin should set credentials true, got %q", got)
	}
}
