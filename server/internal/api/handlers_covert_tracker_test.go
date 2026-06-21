package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/config"
	"github.com/maybeknott/luminet/internal/jobs"
	"github.com/maybeknott/luminet/internal/store"
)

func TestCovertTracker(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create temporary SQLite database
	tmpDir, err := os.MkdirTemp("", "covert-test-*")
	if err != nil {
		t.Fatalf("failed to create tmp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	st, err := store.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer st.Close()

	if err := st.Migrate(); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	cfgMgr := config.NewManager(filepath.Join(tmpDir, "config.json"))
	jobMgr := jobs.NewJobManager(st)

	serverCfg := &ServerConfig{
		Host:         "127.0.0.1",
		Port:         8080,
		APIKey:       "test-key",
		RateLimitRPS: 100,
	}

	server := NewServer(serverCfg, jobMgr, st, cfgMgr)
	router := server.router

	// 1. Send tracking hit to /track (default link)
	reqTrack, _ := http.NewRequest("GET", "/track", nil)
	reqTrack.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36")
	reqTrack.Header.Set("Accept-Language", "en-US,en;q=0.9")
	wTrack := httptest.NewRecorder()
	router.ServeHTTP(wTrack, reqTrack)

	if wTrack.Code != http.StatusOK {
		t.Errorf("expected track status 200, got %d", wTrack.Code)
	}
	if !strings.Contains(wTrack.Body.String(), "🔗 Loading resource...") {
		t.Errorf("expected track response to contain decoy HTML, got %q", wTrack.Body.String())
	}

	// 2. Create a new tracking link via /api/system/covert/links
	linkBody := map[string]string{"label": "Test Mobile Ingestion Client"}
	bodyBytes, _ := json.Marshal(linkBody)
	reqCreate, _ := http.NewRequest("POST", "/api/system/covert/links", bytes.NewReader(bodyBytes))
	reqCreate.Header.Set("X-API-Key", "test-key")
	reqCreate.Header.Set("Content-Type", "application/json")
	wCreate := httptest.NewRecorder()
	router.ServeHTTP(wCreate, reqCreate)

	if wCreate.Code != http.StatusOK {
		t.Errorf("expected create status 200, got %d. Body: %s", wCreate.Code, wCreate.Body.String())
	}

	var createResp struct {
		Status string `json:"status"`
		LinkID string `json:"link_id"`
	}
	if err := json.Unmarshal(wCreate.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if createResp.Status != "ok" || createResp.LinkID == "" {
		t.Errorf("invalid create link response: %+v", createResp)
	}

	// 3. Track with custom link token
	reqTrackCustom, _ := http.NewRequest("GET", "/track/"+createResp.LinkID, nil)
	reqTrackCustom.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1")
	wTrackCustom := httptest.NewRecorder()
	router.ServeHTTP(wTrackCustom, reqTrackCustom)

	if wTrackCustom.Code != http.StatusOK {
		t.Errorf("expected track custom status 200, got %d", wTrackCustom.Code)
	}

	// 4. Retrieve visits via /api/system/covert/visits
	reqVisits, _ := http.NewRequest("GET", "/api/system/covert/visits", nil)
	reqVisits.Header.Set("X-API-Key", "test-key")
	wVisits := httptest.NewRecorder()
	router.ServeHTTP(wVisits, reqVisits)

	if wVisits.Code != http.StatusOK {
		t.Errorf("expected get visits status 200, got %d", wVisits.Code)
	}

	var visits []CovertVisit
	if err := json.Unmarshal(wVisits.Body.Bytes(), &visits); err != nil {
		t.Fatalf("failed to unmarshal visits: %v", err)
	}

	// We expect 2 visits (default, then custom)
	if len(visits) != 2 {
		t.Errorf("expected 2 visits, got %d", len(visits))
	}

	// Verify custom visit user agent parsed values
	var customVisit CovertVisit
	for _, v := range visits {
		if v.LinkID == createResp.LinkID {
			customVisit = v
			break
		}
	}

	if customVisit.Browser != "Safari" {
		t.Errorf("expected browser 'Safari', got %q", customVisit.Browser)
	}
	if customVisit.OS != "iOS" {
		t.Errorf("expected OS 'iOS', got %q", customVisit.OS)
	}
	if customVisit.Device != "Mobile" {
		t.Errorf("expected device 'Mobile', got %q", customVisit.Device)
	}

	// 5. Query stats via /api/system/covert/stats
	reqStats, _ := http.NewRequest("GET", "/api/system/covert/stats", nil)
	reqStats.Header.Set("X-API-Key", "test-key")
	wStats := httptest.NewRecorder()
	router.ServeHTTP(wStats, reqStats)

	if wStats.Code != http.StatusOK {
		t.Errorf("expected stats status 200, got %d", wStats.Code)
	}

	var stats map[string]int
	if err := json.Unmarshal(wStats.Body.Bytes(), &stats); err != nil {
		t.Fatalf("failed to unmarshal stats: %v", err)
	}

	if stats["total_visits"] != 2 {
		t.Errorf("expected total visits 2, got %d", stats["total_visits"])
	}
	if stats["mobile_visits"] != 1 {
		t.Errorf("expected mobile visits 1, got %d", stats["mobile_visits"])
	}

	// 6. Clear visits via /api/system/covert/visits/clear
	reqClear, _ := http.NewRequest("POST", "/api/system/covert/visits/clear", nil)
	reqClear.Header.Set("X-API-Key", "test-key")
	wClear := httptest.NewRecorder()
	router.ServeHTTP(wClear, reqClear)

	if wClear.Code != http.StatusOK {
		t.Errorf("expected clear status 200, got %d", wClear.Code)
	}

	// Check that visits are gone
	wVisits2 := httptest.NewRecorder()
	router.ServeHTTP(wVisits2, reqVisits)
	var visits2 []CovertVisit
	json.Unmarshal(wVisits2.Body.Bytes(), &visits2)
	if len(visits2) != 0 {
		t.Errorf("expected 0 visits after clear, got %d", len(visits2))
	}
}
