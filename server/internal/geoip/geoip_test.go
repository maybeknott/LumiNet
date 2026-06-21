package geoip

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
)

type mockTransport struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

func TestLookup_SequentialFallbacks(t *testing.T) {
	svc, err := NewService("")
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	t.Run("IP-API Success", func(t *testing.T) {
		svc.httpClient.Transport = &mockTransport{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				if req.URL.Host == "ip-api.com" {
					resp := `{
						"status": "success",
						"country": "United States",
						"countryCode": "US",
						"regionName": "California",
						"city": "Mountain View",
						"lat": 37.386,
						"lon": -122.0838
					}`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(resp)),
					}, nil
				}
				return nil, errors.New("unexpected request to " + req.URL.Host)
			},
		}

		country, code, region, city, lat, lon, err := svc.Lookup(context.Background(), "8.8.8.8")
		if err != nil {
			t.Errorf("Expected nil error, got: %v", err)
		}
		if country != "United States" || code != "US" || region != "California" || city != "Mountain View" || lat != 37.386 || lon != -122.0838 {
			t.Errorf("Unexpected lookup results: country=%s, code=%s, region=%s, city=%s, lat=%f, lon=%f", country, code, region, city, lat, lon)
		}
	})

	t.Run("IP-API Fails, IPWhois Success", func(t *testing.T) {
		svc.httpClient.Transport = &mockTransport{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				if req.URL.Host == "ip-api.com" {
					return nil, errors.New("network error on ip-api")
				}
				if req.URL.Host == "ipwhois.app" {
					resp := `{
						"success": true,
						"country": "Germany",
						"country_code": "DE",
						"region": "Berlin",
						"city": "Berlin",
						"latitude": 52.5200,
						"longitude": 13.4050
					}`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(resp)),
					}, nil
				}
				return nil, errors.New("unexpected request to " + req.URL.Host)
			},
		}

		country, code, region, city, lat, lon, err := svc.Lookup(context.Background(), "8.8.8.8")
		if err != nil {
			t.Errorf("Expected nil error, got: %v", err)
		}
		if country != "Germany" || code != "DE" || region != "Berlin" || city != "Berlin" || lat != 52.52 || lon != 13.405 {
			t.Errorf("Unexpected lookup results: country=%s, code=%s, region=%s, city=%s, lat=%f, lon=%f", country, code, region, city, lat, lon)
		}
	})

	t.Run("IP-API and IPWhois Fail, IPAPI.co Success", func(t *testing.T) {
		svc.httpClient.Transport = &mockTransport{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				if req.URL.Host == "ip-api.com" {
					return nil, errors.New("network error on ip-api")
				}
				if req.URL.Host == "ipwhois.app" {
					return &http.Response{
						StatusCode: http.StatusInternalServerError,
						Body:       io.NopCloser(bytes.NewBufferString(`{"success": false, "message": "error"}`)),
					}, nil
				}
				if req.URL.Host == "ipapi.co" {
					resp := `{
						"country_name": "Canada",
						"country_code": "CA",
						"region": "Ontario",
						"city": "Ottawa",
						"latitude": 45.4215,
						"longitude": -75.6972
					}`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewBufferString(resp)),
					}, nil
				}
				return nil, errors.New("unexpected request to " + req.URL.Host)
			},
		}

		country, code, region, city, lat, lon, err := svc.Lookup(context.Background(), "8.8.8.8")
		if err != nil {
			t.Errorf("Expected nil error, got: %v", err)
		}
		if country != "Canada" || code != "CA" || region != "Ontario" || city != "Ottawa" || lat != 45.4215 || lon != -75.6972 {
			t.Errorf("Unexpected lookup results: country=%s, code=%s, region=%s, city=%s, lat=%f, lon=%f", country, code, region, city, lat, lon)
		}
	})

	t.Run("All Fail", func(t *testing.T) {
		svc.httpClient.Transport = &mockTransport{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("general network failure")
			},
		}

		_, _, _, _, _, _, err := svc.Lookup(context.Background(), "8.8.8.8")
		if err == nil {
			t.Errorf("Expected error when all providers fail, got nil")
		}
	})
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"192.168.1.1", true},
		{"172.16.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"invalid", false},
	}

	for _, tc := range tests {
		res := IsPrivateIP(tc.ip)
		if res != tc.expected {
			t.Errorf("IsPrivateIP(%s) = %v; expected %v", tc.ip, res, tc.expected)
		}
	}
}

func TestReverseDNS(t *testing.T) {
	// ReverseDNS will try to perform actual DNS lookup, which might fail or be slow.
	// We can test it with a localhost IP or a known address that usually succeeds.
	_, _ = ReverseDNS(context.Background(), "127.0.0.1")
}

func TestEnrich(t *testing.T) {
	svc, _ := NewService("")
	
	// Test private IP enrichment
	meta, err := svc.Enrich(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("Enrich failed: %v", err)
	}
	if meta.Country != "Private Network" || meta.CountryCode != "LAN" || !meta.IsPrivate {
		t.Errorf("Unexpected private IP metadata: %+v", meta)
	}
}
