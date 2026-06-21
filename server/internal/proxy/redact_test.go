package proxy

import (
	"strings"
	"testing"
)

func TestURITransportPreviewRedactsCredentials(t *testing.T) {
	preview := URITransportPreview("socks5://user:secret@example.com:1080#office-node", 72)
	if strings.Contains(preview, "secret") || strings.Contains(preview, "user:") {
		t.Fatalf("preview leaked credentials: %s", preview)
	}
	if preview != "socks5://***@example.com:1080#office-node" {
		t.Fatalf("unexpected preview: %s", preview)
	}
}

func TestURITransportPreviewOpaquePayload(t *testing.T) {
	preview := URITransportPreview("vmess://very-long-opaque-payload-that-may-contain-secrets", 32)
	if strings.Contains(preview, "very-long") {
		t.Fatalf("preview leaked opaque payload: %s", preview)
	}
	if !strings.HasPrefix(preview, "vmess://") {
		t.Fatalf("preview lost scheme: %s", preview)
	}
}
