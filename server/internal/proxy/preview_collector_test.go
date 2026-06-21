package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPreviewCollector_IranianIntranetFiltration(t *testing.T) {
	pc := NewPreviewCollector([]string{"test"}, 5, 500*time.Millisecond, true)

	irConfigs := []string{
		"vless://uuid-123@my-iran-server.ir:443?type=tcp#IR-Node",
		"ss://chacha20-ietf-poly1305:password@1.1.1.1:8388#%D8%A7%DB%8C%D8%B1%D8%A7%D9%86%20%D9%87%D9%85%D8%B1%D8%A7%D9%87%20%D8%A7%D9%88%D9%84", // remarks: "ایران همراه اول"
		"vmess://eyJhZGQiOiJzYW1hbmVoaGEuY28iLCJwb3J0Ijo0NDMsImlkIjoiMWEyYjNjNGQtNWU2Zi03YThiLTljMGQtMWUyZjNhNGI1YzZkIn0=",
	}

	for _, cfg := range irConfigs {
		if !pc.isIranianIntranet(cfg) {
			t.Errorf("expected config to be classified as Iranian intranet: %s", cfg)
		}
	}

	validConfigs := []string{
		"vless://uuid-123@exit-node.com:443?type=tcp#Germany-Node",
		"ss://chacha20-ietf-poly1305:password@8.8.8.8:8388#GoogleDNS",
	}

	for _, cfg := range validConfigs {
		if pc.isIranianIntranet(cfg) {
			t.Errorf("expected config to be classified as valid exit node: %s", cfg)
		}
	}
}

func TestPreviewCollector_CollectAndCompile(t *testing.T) {
	mockHtml := `
		<html>
		<body>
		Here are some configs:
		vless://uuid-123@exit-node.com:443?type=tcp#Germany-Node
		ss://chacha20-ietf-poly1305:password@8.8.8.8:8388#GoogleDNS
		</body>
		</html>
	`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockHtml))
	}))
	defer srv.Close()

	pc := NewPreviewCollector([]string{srv.URL}, 5, 200*time.Millisecond, true)
	configs, err := pc.fetchChannelConfigs(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("failed to fetch channel configs: %v", err)
	}

	if len(configs) != 2 {
		t.Fatalf("expected 2 configs parsed, got: %d (%v)", len(configs), configs)
	}

	sub := CompileSubscription(configs)
	if sub == "" {
		t.Errorf("expected subscription compilation base64 string")
	}
}
