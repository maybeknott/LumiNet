package api

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/geoip"
)

// CovertLink represents a tracking link and its hits.
type CovertLink struct {
	LinkID    string `json:"link_id"`
	Label     string `json:"label"`
	CreatedAt int64  `json:"created_at"`
	Hits      int    `json:"hits"`
}

// CovertVisit represents a captured visit and its enriched GeoIP metadata.
type CovertVisit struct {
	ID          int     `json:"id"`
	Timestamp   int64   `json:"timestamp"`
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ISP         string  `json:"isp"`
	Browser     string  `json:"browser"`
	OS          string  `json:"os"`
	Device      string  `json:"device"`
	UserAgent   string  `json:"user_agent"`
	Referrer    string  `json:"referrer"`
	Language    string  `json:"language"`
	LinkID      string  `json:"link_id"`
}

const covertDecoyHTML = `<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Loading...</title>
<style>*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,sans-serif;display:flex;align-items:center;
justify-content:center;min-height:100vh;background:#f5f7fa}
.c{background:#fff;border-radius:14px;padding:48px;text-align:center;
box-shadow:0 4px 24px rgba(0,0,0,.08);max-width:400px}
h1{font-size:22px;color:#333;margin-bottom:10px}p{color:#999;font-size:14px}
</style></head><body><div class="c">
<h1>🔗 Loading resource...</h1>
<p>Please wait while content is being prepared.</p>
</div></body></html>`

// parseUserAgent extracts the browser, OS, and device categories from a user agent string.
func parseUserAgent(ua string) (browser, os, device string) {
	u := strings.ToLower(ua)

	// Browser
	if strings.Contains(u, "edg/") {
		browser = "Edge"
	} else if strings.Contains(u, "opr/") || strings.Contains(u, "opera") {
		browser = "Opera"
	} else if strings.Contains(u, "chrome/") && strings.Contains(u, "safari/") {
		browser = "Chrome"
	} else if strings.Contains(u, "firefox/") {
		browser = "Firefox"
	} else if strings.Contains(u, "safari/") {
		browser = "Safari"
	} else if strings.Contains(u, "curl") {
		browser = "cURL"
	} else if strings.Contains(u, "python") {
		browser = "Python"
	} else {
		browser = "Unknown"
	}

	// OS
	if strings.Contains(u, "windows nt 10") {
		os = "Windows 10/11"
	} else if strings.Contains(u, "windows") {
		os = "Windows"
	} else if strings.Contains(u, "android") {
		os = "Android"
	} else if strings.Contains(u, "iphone") {
		os = "iOS"
	} else if strings.Contains(u, "ipad") {
		os = "iPadOS"
	} else if strings.Contains(u, "mac os x") {
		os = "macOS"
	} else if strings.Contains(u, "linux") {
		os = "Linux"
	} else {
		os = "Unknown"
	}

	// Device
	if strings.Contains(u, "iphone") || strings.Contains(u, "android") || strings.Contains(u, "mobile") {
		device = "Mobile"
	} else if strings.Contains(u, "ipad") || strings.Contains(u, "tablet") {
		device = "Tablet"
	} else {
		device = "Desktop"
	}

	return
}

// HandleCovertTrack registers user clicks and redirects them to the decoy page.
func (s *Server) HandleCovertTrack(c *gin.Context) {
	linkID := c.Param("link_id")
	if linkID == "" {
		linkID = "default"
	}

	ip := c.ClientIP()
	ua := c.Request.UserAgent()
	browser, os, device := parseUserAgent(ua)

	referrer := c.Request.Referer()
	if referrer == "" {
		referrer = "Direct"
	}

	language := c.Request.Header.Get("Accept-Language")
	if len(language) > 80 {
		language = language[:80]
	}

	ctx := c.Request.Context()
	var country, code, region, city string
	var lat, lon float64

	// Fallback-safe GeoIP Enrichment
	svc, err := geoip.NewService("")
	if err == nil {
		country, code, region, city, lat, lon, _ = svc.Lookup(ctx, ip)
	}

	if country == "" {
		if geoip.IsPrivateIP(ip) {
			country = "Private Network"
			code = "LAN"
		} else {
			country = "Unknown"
			code = "?"
		}
	}

	// Persist visit record
	_, _ = s.store.Conn().ExecContext(ctx,
		`INSERT INTO covert_visits 
		(timestamp, ip, country, country_code, region, city, latitude, longitude, isp, browser, os, device, user_agent, referrer, language, link_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Now().Unix(), ip, country, code, region, city, lat, lon, "", browser, os, device, ua, referrer, language, linkID,
	)

	// Increment hit counter
	if linkID != "default" {
		_, _ = s.store.Conn().ExecContext(ctx, "UPDATE covert_links SET hits = hits + 1 WHERE link_id = ?", linkID)
	}

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(covertDecoyHTML))
}

// GetCovertLinks handles GET /api/system/covert/links — returns the dynamic tracking links.
func (s *Server) GetCovertLinks(c *gin.Context) {
	rows, err := s.store.Conn().Query("SELECT link_id, label, created_at, hits FROM covert_links ORDER BY created_at DESC")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var links []CovertLink
	for rows.Next() {
		var l CovertLink
		if err := rows.Scan(&l.LinkID, &l.Label, &l.CreatedAt, &l.Hits); err == nil {
			links = append(links, l)
		}
	}
	c.JSON(http.StatusOK, links)
}

// CreateCovertLink handles POST /api/system/covert/links — creates a new tracking link token.
func (s *Server) CreateCovertLink(c *gin.Context) {
	var req struct {
		Label string `json:"label" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	bytes := make([]byte, 8)
	_, _ = rand.Read(bytes)
	token := base64.RawURLEncoding.EncodeToString(bytes)

	_, err := s.store.Conn().Exec("INSERT INTO covert_links (link_id, label, created_at, hits) VALUES (?, ?, ?, 0)",
		token, req.Label, time.Now().Unix())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "link_id": token})
}

// GetCovertVisits handles GET /api/system/covert/visits — returns tracking ledger visit logs.
func (s *Server) GetCovertVisits(c *gin.Context) {
	rows, err := s.store.Conn().Query(`
		SELECT id, timestamp, ip, country, country_code, region, city, latitude, longitude, isp, browser, os, device, user_agent, referrer, language, link_id 
		FROM covert_visits ORDER BY id DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var visits []CovertVisit
	for rows.Next() {
		var v CovertVisit
		if err := rows.Scan(
			&v.ID, &v.Timestamp, &v.IP, &v.Country, &v.CountryCode, &v.Region, &v.City,
			&v.Latitude, &v.Longitude, &v.ISP, &v.Browser, &v.OS, &v.Device, &v.UserAgent,
			&v.Referrer, &v.Language, &v.LinkID,
		); err == nil {
			visits = append(visits, v)
		}
	}
	c.JSON(http.StatusOK, visits)
}

// ClearCovertVisits handles POST /api/system/covert/visits/clear — resets client visits history ledger.
func (s *Server) ClearCovertVisits(c *gin.Context) {
	_, err := s.store.Conn().Exec("DELETE FROM covert_visits")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "Visits history cleared."})
}

// GetCovertStats handles GET /api/system/covert/stats — returns summaries of client tracking activities.
func (s *Server) GetCovertStats(c *gin.Context) {
	var totalVisits int
	_ = s.store.Conn().QueryRow("SELECT COUNT(*) FROM covert_visits").Scan(&totalVisits)

	var uniqueIPs int
	_ = s.store.Conn().QueryRow("SELECT COUNT(DISTINCT ip) FROM covert_visits").Scan(&uniqueIPs)

	var countryCount int
	_ = s.store.Conn().QueryRow("SELECT COUNT(DISTINCT country) FROM covert_visits").Scan(&countryCount)

	var mobileCount int
	_ = s.store.Conn().QueryRow("SELECT COUNT(*) FROM covert_visits WHERE device = 'Mobile'").Scan(&mobileCount)

	var linkCount int
	_ = s.store.Conn().QueryRow("SELECT COUNT(*) FROM covert_links").Scan(&linkCount)

	c.JSON(http.StatusOK, gin.H{
		"total_visits":  totalVisits,
		"unique_ips":    uniqueIPs,
		"countries":     countryCount,
		"mobile_visits": mobileCount,
		"links_count":   linkCount,
	})
}
