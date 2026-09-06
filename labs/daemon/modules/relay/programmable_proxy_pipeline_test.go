package relay

import (
	"strings"
	"testing"
)

func TestProgrammableProxyPipeline(t *testing.T) {
	pipeline := NewProgrammableProxyPipeline()
	pipeline.AddHook(NewHeaderInjectorHook("X-Proxy-By", "LumiNet"))
	pipeline.AddHook(NewBlockPathHook("/admin/secret"))

	headers := []HeaderPair{
		{Key: "Host", Value: "api.com"},
	}

	code, body, err := pipeline.ProcessRequest("GET", "/public/data", &headers)
	if err != nil || code != 200 {
		t.Fatalf("expected 200 OK, got %d, %v", code, err)
	}

	foundHeader := false
	for _, h := range headers {
		if h.Key == "X-Proxy-By" && h.Value == "LumiNet" {
			foundHeader = true
			break
		}
	}
	if !foundHeader {
		t.Fatal("expected X-Proxy-By header to be injected")
	}

	badHeaders := []HeaderPair{}
	code, body, err = pipeline.ProcessRequest("GET", "/admin/secret/keys", &badHeaders)
	if err == nil || code != 403 {
		t.Fatalf("expected 403 Forbidden, got %d, err %v", code, err)
	}
	if !strings.Contains(string(body), "Forbidden") {
		t.Fatalf("expected body to contain Forbidden, got %s", string(body))
	}
}
