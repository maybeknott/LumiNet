package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/protected", nil))
	if w.Code != http.StatusUnauthorized { t.Fatalf("missing key: got %d, want 401", w.Code) }
}

func TestAuthMiddleware_FailsClosedWithoutConfiguredKey(t *testing.T) {
	r := newAuthEngine("")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/protected", nil))
	if w.Code != http.StatusServiceUnavailable { t.Fatalf("empty configured key: got %d, want 503", w.Code) }
}

func TestAuthMiddleware_RejectsWrongKey(t *testing.T) {
	r := newAuthEngine("secret-key")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-API-Key", "wrong")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized { t.Fatalf("wrong key: got %d, want 401", w.Code) }
}

func TestAuthMiddleware_AcceptsHeaderKey(t *testing.T) {
	r := newAuthEngine("secret-key")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-API-Key", "secret-key")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK { t.Fatalf("header key: got %d, want 200", w.Code) }
}

func TestAuthMiddleware_RejectsRawAPIKeyCookie(t *testing.T) {
	r := newAuthEngine("secret-key")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "secret-key"})
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized { t.Fatalf("raw key cookie: got %d, want 401", w.Code) }
}

func TestBrowserSessionMiddleware_AcceptsOpaqueCookie(t *testing.T) {
	sessions := newBrowserSessionIssuer()
	token, _, err := sessions.issue(time.Now())
	if err != nil { t.Fatal(err) }
	r := gin.New()
	r.Use(AuthMiddlewareWithBrowserSession("secret-key", sessions))
	r.GET("/protected", func(c *gin.Context) { c.Status(http.StatusOK) })
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK { t.Fatalf("opaque cookie: got %d, want 200", w.Code) }
}

func TestAuthMiddleware_IgnoresQueryParamKey(t *testing.T) {
	r := newAuthEngine("secret-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/protected?api_key=secret-key", nil))
	if w.Code != http.StatusUnauthorized { t.Fatalf("query-param key should be rejected: got %d, want 401", w.Code) }
}

func TestCorsMiddleware_RejectsUnknownOrigin(t *testing.T) {
	r := gin.New()
	r.Use(CorsMiddleware([]string{"http://127.0.0.1:8470"}))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", "https://evil.example")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden { t.Fatalf("unknown origin: got %d want 403", w.Code) }
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" { t.Fatalf("unknown origin should get no ACAO header, got %q", got) }
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
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != allowed { t.Fatalf("allowed origin: got ACAO %q, want %q", got, allowed) }
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" { t.Fatalf("allowed origin should set credentials true, got %q", got) }
}

func TestCorsMiddleware_NeverHonorsWildcard(t *testing.T) {
	r := gin.New()
	r.Use(CorsMiddleware([]string{"*"}))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", "https://evil.example")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden { t.Fatalf("wildcard origin: got %d want 403", w.Code) }
}

func TestAuthorityMiddlewareRejectsForeignHost(t *testing.T) {
	r := gin.New()
	r.Use(AuthorityMiddleware("127.0.0.1", 8470))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://evil.example:8470/x", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusMisdirectedRequest { t.Fatalf("foreign authority: got %d want 421", w.Code) }
}

func TestAuthorityMiddlewareAcceptsLoopbackAliases(t *testing.T) {
	for _, authority := range []string{"127.0.0.1:8470", "localhost:8470", "[::1]:8470"} {
		r := gin.New()
		r.Use(AuthorityMiddleware("127.0.0.1", 8470))
		r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://"+authority+"/x", nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK { t.Fatalf("authority %s: got %d want 200", authority, w.Code) }
	}
}
