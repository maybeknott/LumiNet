// Package geoip delivers geographic coordinate lookup for IPv4/IPv6 addresses.
// Uses ip-api.com as a free online fallback when no local database is configured.
package geoip

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Service provides capabilities to query GeoIP databases or endpoints.
type Service struct {
	dbPath     string
	httpClient *http.Client
}

// NewService creates a geoip Service. If dbPath is empty or the file doesn't exist,
// it falls back to the ip-api.com online service.
func NewService(dbPath string) (*Service, error) {
	return &Service{
		dbPath: dbPath,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}, nil
}

// Lookup queries the GeoIP database for the specified IP and returns geographic coordinates and location names using a sequential fallback chain.
func (s *Service) Lookup(ctx context.Context, ip string) (country, code, region, city string, lat, lon float64, err error) {
	country, code, region, city, lat, lon, err = s.lookupIPAPI(ctx, ip)
	if err == nil {
		return country, code, region, city, lat, lon, nil
	}

	country, code, region, city, lat, lon, err = s.lookupIPWhois(ctx, ip)
	if err == nil {
		return country, code, region, city, lat, lon, nil
	}

	country, code, region, city, lat, lon, err = s.lookupIPAPI_Co(ctx, ip)
	if err == nil {
		return country, code, region, city, lat, lon, nil
	}

	return "", "", "", "", 0, 0, fmt.Errorf("all geoip lookup providers failed")
}

func (s *Service) lookupIPAPI(ctx context.Context, ip string) (country, code, region, city string, lat, lon float64, err error) {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,regionName,city,lat,lon", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", "", "", "", 0, 0, err
	}
	req.Header.Set("User-Agent", "LumiNet/1.0")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", "", "", "", 0, 0, err
	}
	defer resp.Body.Close()

	var result struct {
		Status      string  `json:"status"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		Region      string  `json:"regionName"`
		City        string  `json:"city"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		Message     string  `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", "", "", 0, 0, err
	}
	if result.Status != "success" {
		return "", "", "", "", 0, 0, fmt.Errorf("ip-api error: %s", result.Message)
	}
	return result.Country, result.CountryCode, result.Region, result.City, result.Lat, result.Lon, nil
}

func (s *Service) lookupIPWhois(ctx context.Context, ip string) (country, code, region, city string, lat, lon float64, err error) {
	url := fmt.Sprintf("https://ipwhois.app/json/%s", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", "", "", "", 0, 0, err
	}
	req.Header.Set("User-Agent", "LumiNet/1.0")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", "", "", "", 0, 0, err
	}
	defer resp.Body.Close()

	var result struct {
		Success     bool    `json:"success"`
		Country     string  `json:"country"`
		CountryCode string  `json:"country_code"`
		Region      string  `json:"region"`
		City        string  `json:"city"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
		Message     string  `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", "", "", 0, 0, err
	}
	if !result.Success {
		return "", "", "", "", 0, 0, fmt.Errorf("ipwhois error: %s", result.Message)
	}
	return result.Country, result.CountryCode, result.Region, result.City, result.Latitude, result.Longitude, nil
}

func (s *Service) lookupIPAPI_Co(ctx context.Context, ip string) (country, code, region, city string, lat, lon float64, err error) {
	url := fmt.Sprintf("https://ipapi.co/%s/json/", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", "", "", "", 0, 0, err
	}
	req.Header.Set("User-Agent", "LumiNet/1.0")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", "", "", "", 0, 0, err
	}
	defer resp.Body.Close()

	var result struct {
		Error       bool    `json:"error"`
		Reason      string  `json:"reason"`
		Country     string  `json:"country_name"`
		CountryCode string  `json:"country_code"`
		Region      string  `json:"region"`
		City        string  `json:"city"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", "", "", 0, 0, err
	}
	if result.Error {
		return "", "", "", "", 0, 0, fmt.Errorf("ipapi.co error: %s", result.Reason)
	}
	return result.Country, result.CountryCode, result.Region, result.City, result.Latitude, result.Longitude, nil
}

// Close closes any underlying open database reader connections.
func (s *Service) Close() error {
	return nil
}

// IPMetadata holds fully enriched information about an IP address.
type IPMetadata struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ASN         string  `json:"asn"`
	ISP         string  `json:"isp"`
	Hostname    string  `json:"hostname"`
	IsPrivate   bool    `json:"is_private"`
}

// IsPrivateIP checks if the IP address is private, loopback, or link-local unicast.
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// ReverseDNS performs a reverse DNS lookup on the specified IP address,
// returning the first hostname (with any trailing dot trimmed) or an error.
func ReverseDNS(ctx context.Context, ipStr string) (string, error) {
	resolver := net.DefaultResolver
	hostnames, err := resolver.LookupAddr(ctx, ipStr)
	if err != nil || len(hostnames) == 0 {
		return "", err
	}
	hostname := hostnames[0]
	if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
		hostname = hostname[:len(hostname)-1]
	}
	return hostname, nil
}

// Enrich queries basic GeoIP data and resolves additional hostname details to build a complete IPMetadata record.
func (s *Service) Enrich(ctx context.Context, ip string) (*IPMetadata, error) {
	meta := &IPMetadata{IP: ip}

	// Check if private
	meta.IsPrivate = IsPrivateIP(ip)

	// Reverse DNS lookup
	if hostname, err := ReverseDNS(ctx, ip); err == nil {
		meta.Hostname = hostname
	}

	// GeoIP lookup (skip for private IPs)
	if !meta.IsPrivate {
		country, code, region, city, lat, lon, err := s.Lookup(ctx, ip)
		if err == nil {
			meta.Country = country
			meta.CountryCode = code
			meta.Region = region
			meta.City = city
			meta.Latitude = lat
			meta.Longitude = lon
		}
	} else {
		meta.Country = "Private Network"
		meta.CountryCode = "LAN"
	}

	if meta.Country == "" && !meta.IsPrivate {
		return nil, fmt.Errorf("could not enrich IP %s", ip)
	}

	return meta, nil
}

