package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestParseProxyURI_Valid(t *testing.T) {
	tests := []struct {
		name string
		uri  string
		want ProxyProtocol
	}{
		{
			name: "VLESS URI",
			uri:  "vless://9de78a2e-4b7b-4171-ba47-19ad0d7f9503@example.com:443?type=tcp&security=tls#VlessTest",
			want: ProtocolVLESS,
		},
		{
			name: "Trojan URI",
			uri:  "trojan://trojanpass@example.com:443?sni=example.com#TrojanTest",
			want: ProtocolTrojan,
		},
		{
			name: "Shadowsocks URI SIP002",
			uri:  "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@example.com:8388#SSTest", // aes-128-gcm:password base64
			want: ProtocolShadowsocks,
		},
		{
			name: "Shadowsocks URI Legacy",
			uri:  "ss://YWVzLTEyOC1nY206cGFzc3dvcmRAZXhhbXBsZS5jb206ODM4OA==#SSTestLegacy", // aes-128-gcm:password@example.com:8388 base64
			want: ProtocolShadowsocks,
		},
		{
			name: "Hysteria2 URI",
			uri:  "hysteria2://hy2pass@example.com:443?up=10&down=50#Hy2Test",
			want: ProtocolHysteria2,
		},
		{
			name: "TUIC URI",
			uri:  "tuic://9de78a2e-4b7b-4171-ba47-19ad0d7f9503:tuicpass@example.com:443#TuicTest",
			want: ProtocolTUIC,
		},
		{
			name: "NaiveProxy URI",
			uri:  "naive://username:password@example.com:443#NaiveTest",
			want: ProtocolNaive,
		},
		{
			name: "WireGuard URI",
			uri:  "wireguard://privatekey@example.com:51820?publickey=publickey#WgTest",
			want: ProtocolWireGuard,
		},
		{
			name: "AmneziaWG URI (awg)",
			uri:  "awg://privatekey@example.com:51820?publickey=publickey&jc=4&jmin=20&jmax=50&s1=10&s2=20&s3=30&s4=40&h1=1234&h2=5678&h3=9012&h4=3456#AwgTest",
			want: ProtocolAmneziaWG,
		},
		{
			name: "HTTP Proxy URI",
			uri:  "http://user:pass@example.com:8080#HTTPTest",
			want: ProtocolHTTP,
		},
		{
			name: "SOCKS5 Proxy URI",
			uri:  "socks5://user:pass@example.com:1080#SOCKS5Test",
			want: ProtocolSOCKS5,
		},
		{
			name: "KCP URI",
			uri:  "kcp://kcppassword@example.com:29900?crypt=aes-128&nodelay=1&interval=20&resend=2&nc=1&sndwnd=128&rcvwnd=128&mtu=1350#KCPTest",
			want: ProtocolKCP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseProxyURI(tt.uri)
			if err != nil {
				t.Fatalf("ParseProxyURI() error = %v", err)
			}
			if cfg.Protocol != tt.want {
				t.Errorf("cfg.Protocol = %v, want %v", cfg.Protocol, tt.want)
			}
		})
	}
}

func TestParseProxyURI_Invalid(t *testing.T) {
	tests := []struct {
		name string
		uri  string
	}{
		{
			name: "Empty URI",
			uri:  "",
		},
		{
			name: "Unsupported scheme",
			uri:  "ftp://example.com:21",
		},
		{
			name: "VLESS missing host",
			uri:  "vless://9de78a2e-4b7b-4171-ba47-19ad0d7f9503@:443",
		},
		{
			name: "VLESS missing UUID",
			uri:  "vless://@example.com:443",
		},
		{
			name: "Trojan missing host",
			uri:  "trojan://trojanpass@:443",
		},
		{
			name: "Trojan missing password",
			uri:  "trojan://@example.com:443",
		},
		{
			name: "Shadowsocks missing host",
			uri:  "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@:8388",
		},
		{
			name: "Shadowsocks missing password",
			uri:  "ss://YWVzLTEyOC1nY206@example.com:8388", // YWVzLTEyOC1nY206 is base64 of aes-128-gcm:
		},
		{
			name: "Hysteria2 missing host",
			uri:  "hysteria2://hy2pass@:443",
		},
		{
			name: "Hysteria2 missing password",
			uri:  "hysteria2://@example.com:443",
		},
		{
			name: "TUIC missing host",
			uri:  "tuic://9de78a2e-4b7b-4171-ba47-19ad0d7f9503:tuicpass@:443",
		},
		{
			name: "TUIC missing credentials",
			uri:  "tuic://@example.com:443",
		},
		{
			name: "NaiveProxy missing host",
			uri:  "naive://username:password@:443",
		},
		{
			name: "NaiveProxy missing credentials",
			uri:  "naive://@example.com:443",
		},
		{
			name: "WireGuard missing host",
			uri:  "wireguard://privatekey@:51820?publickey=publickey",
		},
		{
			name: "WireGuard missing keys",
			uri:  "wireguard://@example.com:51820",
		},
		{
			name: "HTTP missing host",
			uri:  "http://user:pass@:8080",
		},
		{
			name: "SOCKS5 missing host",
			uri:  "socks5://user:pass@:1080",
		},
		{
			name: "KCP missing host",
			uri:  "kcp://kcppass@:29900",
		},
		{
			name: "KCP missing password",
			uri:  "kcp://@example.com:29900",
		},
		{
			name: "Suspicious keyword i_love_",
			uri:  "vless://9de78a2e-4b7b-4171-ba47-19ad0d7f9503@example.com:443?i_love_test=1",
		},
		{
			name: "Suspicious double encoding",
			uri:  "vless://9de78a2e-4b7b-4171-ba47-19ad0d7f9503@example.com:443?path=%25252f",
		},
		{
			name: "Suspicious excessive %25 counts",
			uri:  "vless://9de78a2e-4b7b-4171-ba47-19ad0d7f9503@example.com:443?path=%25%25%25%25%25%25%25%25%25%25%25%25%25%25%25",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseProxyURI(tt.uri)
			if err == nil {
				t.Errorf("ParseProxyURI() expected error for %q, got nil", tt.uri)
			}
		})
	}
}

func TestParseProxyURI_VlessReality(t *testing.T) {
	uri := "vless://9de78a2e-4b7b-4171-ba47-19ad0d7f9503@example.com:443?type=tcp&security=reality&pbk=reality_pub_key&sid=reality_short_id#VlessRealityTest"
	cfg, err := ParseProxyURI(uri)
	if err != nil {
		t.Fatalf("Failed to parse VLESS Reality URI: %v", err)
	}

	if cfg.Protocol != ProtocolVLESS {
		t.Errorf("Expected protocol VLESS, got %v", cfg.Protocol)
	}
	if cfg.Security != "reality" {
		t.Errorf("Expected security reality, got %s", cfg.Security)
	}
	if !cfg.TLS {
		t.Errorf("Expected TLS to be enabled for Reality")
	}
	if cfg.PublicKey != "reality_pub_key" {
		t.Errorf("Expected PublicKey 'reality_pub_key', got %q", cfg.PublicKey)
	}
	if cfg.ShortID != "reality_short_id" {
		t.Errorf("Expected ShortID 'reality_short_id', got %q", cfg.ShortID)
	}

	// Test Sing-Box config builder incorporates reality details
	mgr := NewCoreManager(CoreTypeSingBox, "")
	configBytes, err := mgr.BuildSingBoxConfig(cfg, 1080)
	if err != nil {
		t.Fatalf("Failed to build sing-box config: %v", err)
	}

	var configObj map[string]interface{}
	if err := json.Unmarshal(configBytes, &configObj); err != nil {
		t.Fatalf("Failed to unmarshal built config: %v", err)
	}

	outbounds := configObj["outbounds"].([]interface{})
	proxyOutbound := outbounds[0].(map[string]interface{})
	tlsConfig := proxyOutbound["tls"].(map[string]interface{})
	realityConfig := tlsConfig["reality"].(map[string]interface{})

	if realityConfig["enabled"] != true {
		t.Errorf("Expected reality enabled to be true")
	}
	if realityConfig["public_key"] != "reality_pub_key" {
		t.Errorf("Expected reality public_key to be 'reality_pub_key'")
	}
	if realityConfig["short_id"] != "reality_short_id" {
		t.Errorf("Expected reality short_id to be 'reality_short_id'")
	}
}

func TestParseProxyURI_AmneziaWG(t *testing.T) {
	uri := "awg://privatekey@example.com:51820?address=10.0.0.2%2F24&h1=1111111111&h2=2222222222&h3=3333333333&h4=4444444444&jc=4&jmax=50&jmin=20&mtu=1400&publickey=publickey&reserved=0%2C0%2C0&s1=10&s2=20&s3=30&s4=40#AwgTest"
	cfg, err := ParseProxyURI(uri)
	if err != nil {
		t.Fatalf("Failed to parse AmneziaWG URI: %v", err)
	}

	if cfg.Protocol != ProtocolAmneziaWG {
		t.Errorf("Expected protocol AmneziaWG, got %v", cfg.Protocol)
	}
	if cfg.Jc != 4 {
		t.Errorf("Expected Jc 4, got %d", cfg.Jc)
	}
	if cfg.Jmin != 20 {
		t.Errorf("Expected Jmin 20, got %d", cfg.Jmin)
	}
	if cfg.Jmax != 50 {
		t.Errorf("Expected Jmax 50, got %d", cfg.Jmax)
	}
	if cfg.S1 != 10 {
		t.Errorf("Expected S1 10, got %d", cfg.S1)
	}
	if cfg.S2 != 20 {
		t.Errorf("Expected S2 20, got %d", cfg.S2)
	}
	if cfg.S3 != 30 {
		t.Errorf("Expected S3 30, got %d", cfg.S3)
	}
	if cfg.S4 != 40 {
		t.Errorf("Expected S4 40, got %d", cfg.S4)
	}
	if cfg.H1 != "1111111111" {
		t.Errorf("Expected H1 '1111111111', got %q", cfg.H1)
	}
	if cfg.H2 != "2222222222" {
		t.Errorf("Expected H2 '2222222222', got %q", cfg.H2)
	}
	if cfg.H3 != "3333333333" {
		t.Errorf("Expected H3 '3333333333', got %q", cfg.H3)
	}
	if cfg.H4 != "4444444444" {
		t.Errorf("Expected H4 '4444444444', got %q", cfg.H4)
	}
	if cfg.MTU != 1400 {
		t.Errorf("Expected MTU 1400, got %d", cfg.MTU)
	}
	if len(cfg.Reserved) != 3 || cfg.Reserved[0] != 0 {
		t.Errorf("Expected Reserved [0,0,0], got %v", cfg.Reserved)
	}

	// Test ToURI reconstruction matches
	reconstructed := cfg.ToURI()
	if reconstructed != uri {
		t.Errorf("ToURI() =\n%q\nwant\n%q", reconstructed, uri)
	}

	// Test Sing-Box config builder incorporates AmneziaWG details
	mgr := NewCoreManager(CoreTypeSingBox, "")
	configBytes, err := mgr.BuildSingBoxConfig(cfg, 1080)
	if err != nil {
		t.Fatalf("Failed to build sing-box config: %v", err)
	}

	var configObj map[string]interface{}
	if err := json.Unmarshal(configBytes, &configObj); err != nil {
		t.Fatalf("Failed to unmarshal built config: %v", err)
	}

	outbounds := configObj["outbounds"].([]interface{})
	proxyOutbound := outbounds[0].(map[string]interface{})

	if proxyOutbound["type"] != "wireguard" {
		t.Errorf("Expected outbound type 'wireguard', got %q", proxyOutbound["type"])
	}
	if fmt.Sprintf("%.0f", proxyOutbound["awg_jc"]) != "4" {
		t.Errorf("Expected awg_jc 4, got %v", proxyOutbound["awg_jc"])
	}
	if fmt.Sprintf("%.0f", proxyOutbound["awg_h1"]) != "1111111111" {
		t.Errorf("Expected awg_h1 1111111111, got %v", proxyOutbound["awg_h1"])
	}

	// Test Clash exporter converts correctly
	clashYaml, err := ExportToClashYaml([]*ProxyConfig{cfg})
	if err != nil {
		t.Fatalf("Failed to export to Clash YAML: %v", err)
	}

	// Verify the presence of amnezia-wg-option in Clash config
	if !strings.Contains(clashYaml, "amnezia-wg-option:") {
		t.Errorf("Expected Clash YAML to contain 'amnezia-wg-option', got:\n%s", clashYaml)
	}
	if !strings.Contains(clashYaml, "jc: 4") {
		t.Errorf("Expected Clash YAML to contain 'jc: 4', got:\n%s", clashYaml)
	}
}

func TestParseProxyURI_ShadowsocksPrefix(t *testing.T) {
	uri := "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@example.com:8388?prefix=someprefix#SSTest"
	cfg, err := ParseProxyURI(uri)
	if err != nil {
		t.Fatalf("ParseProxyURI failed: %v", err)
	}
	if cfg.Prefix != "someprefix" {
		t.Errorf("Expected Prefix 'someprefix', got %q", cfg.Prefix)
	}
}

func TestParseProxyURI_AnyTLS(t *testing.T) {
	uri := "anytls://mypassword@example.com:443?allowInsecure=true&minIdleSessions=5&sni=example.com#AnyTLSTest"
	cfg, err := ParseProxyURI(uri)
	if err != nil {
		t.Fatalf("Failed to parse AnyTLS URI: %v", err)
	}

	if cfg.Protocol != ProtocolAnyTLS {
		t.Errorf("Expected protocol AnyTLS, got %v", cfg.Protocol)
	}
	if cfg.Password != "mypassword" {
		t.Errorf("Expected Password 'mypassword', got %q", cfg.Password)
	}
	if cfg.Address != "example.com" {
		t.Errorf("Expected Address 'example.com', got %q", cfg.Address)
	}
	if cfg.Port != 443 {
		t.Errorf("Expected Port 443, got %d", cfg.Port)
	}
	if cfg.SNI != "example.com" {
		t.Errorf("Expected SNI 'example.com', got %q", cfg.SNI)
	}
	if !cfg.SkipCertVerify {
		t.Errorf("Expected SkipCertVerify to be true")
	}
	if cfg.MinIdleSessions != 5 {
		t.Errorf("Expected MinIdleSessions 5, got %d", cfg.MinIdleSessions)
	}
	if cfg.Name != "AnyTLSTest" {
		t.Errorf("Expected Name 'AnyTLSTest', got %q", cfg.Name)
	}

	reconstructed := cfg.ToURI()
	if reconstructed != uri {
		t.Errorf("ToURI() =\n%q\nwant\n%q", reconstructed, uri)
	}
}

func TestParseProxyURI_Juicity(t *testing.T) {
	uri := "juicity://myuuid:mypassword@example.com:443?allowInsecure=true&congestion=bbr&pinnedCertchain=sha256&sni=example.com#JuicityTest"
	cfg, err := ParseProxyURI(uri)
	if err != nil {
		t.Fatalf("Failed to parse Juicity URI: %v", err)
	}

	if cfg.Protocol != ProtocolJuicity {
		t.Errorf("Expected protocol Juicity, got %v", cfg.Protocol)
	}
	if cfg.UUID != "myuuid" {
		t.Errorf("Expected UUID 'myuuid', got %q", cfg.UUID)
	}
	if cfg.Password != "mypassword" {
		t.Errorf("Expected Password 'mypassword', got %q", cfg.Password)
	}
	if cfg.Address != "example.com" {
		t.Errorf("Expected Address 'example.com', got %q", cfg.Address)
	}
	if cfg.Port != 443 {
		t.Errorf("Expected Port 443, got %d", cfg.Port)
	}
	if cfg.SNI != "example.com" {
		t.Errorf("Expected SNI 'example.com', got %q", cfg.SNI)
	}
	if !cfg.SkipCertVerify {
		t.Errorf("Expected SkipCertVerify to be true")
	}
	if cfg.CongestionControl != "bbr" {
		t.Errorf("Expected CongestionControl 'bbr', got %q", cfg.CongestionControl)
	}
	if cfg.PinnedCertChainSHA256 != "sha256" {
		t.Errorf("Expected PinnedCertChainSHA256 'sha256', got %q", cfg.PinnedCertChainSHA256)
	}
	if cfg.Name != "JuicityTest" {
		t.Errorf("Expected Name 'JuicityTest', got %q", cfg.Name)
	}

	reconstructed := cfg.ToURI()
	if reconstructed != uri {
		t.Errorf("ToURI() =\n%q\nwant\n%q", reconstructed, uri)
	}
}

func TestParseProxyURI_WireGuardNextGen(t *testing.T) {
	uri := "wireguard://privatekey@example.com:51820?address=172.16.0.3%2F32&fake_packets=1-3&fake_packets_delay=10-30&fake_packets_mode=m4&fake_packets_size=10-30&publickey=publickey&reserved=4Zev4Zep4ZaH4ZGt8J%2BXveGRreGWh08%3D&wnoise=quic&wnoisecount=10-15&wnoisedelay=1&wpayloadsize=5-10#WgNextGenTest"
	cfg, err := ParseProxyURI(uri)
	if err != nil {
		t.Fatalf("Failed to parse WireGuard next-gen URI: %v", err)
	}

	if cfg.Protocol != ProtocolWireGuard {
		t.Errorf("Expected protocol WireGuard, got %v", cfg.Protocol)
	}
	if cfg.WNoise != "quic" {
		t.Errorf("Expected WNoise 'quic', got %q", cfg.WNoise)
	}
	if cfg.WNoiseCount != "10-15" {
		t.Errorf("Expected WNoiseCount '10-15', got %q", cfg.WNoiseCount)
	}
	if cfg.WPayloadSize != "5-10" {
		t.Errorf("Expected WPayloadSize '5-10', got %q", cfg.WPayloadSize)
	}
	if cfg.WNoiseDelay != "1" {
		t.Errorf("Expected WNoiseDelay '1', got %q", cfg.WNoiseDelay)
	}
	if cfg.FakePackets != "1-3" {
		t.Errorf("Expected FakePackets '1-3', got %q", cfg.FakePackets)
	}
	if cfg.FakePacketsSize != "10-30" {
		t.Errorf("Expected FakePacketsSize '10-30', got %q", cfg.FakePacketsSize)
	}
	if cfg.FakePacketsDelay != "10-30" {
		t.Errorf("Expected FakePacketsDelay '10-30', got %q", cfg.FakePacketsDelay)
	}
	if cfg.FakePacketsMode != "m4" {
		t.Errorf("Expected FakePacketsMode 'm4', got %q", cfg.FakePacketsMode)
	}
	if len(cfg.Reserved) == 0 {
		t.Errorf("Expected decoded reserved slice to not be empty")
	}

	// Test ToURI reconstruction matches
	reconstructed := cfg.ToURI()
	if reconstructed != uri {
		t.Errorf("ToURI() =\n%q\nwant\n%q", reconstructed, uri)
	}

	// Test Sing-Box outbound builder maps fake packets correctly
	mgr := NewCoreManager(CoreTypeSingBox, "")
	outbound, err := mgr.buildSingBoxOutbound(cfg, "test")
	if err != nil {
		t.Fatalf("Failed to build sing-box outbound: %v", err)
	}
	if outbound["fake_packets"] != "1-3" {
		t.Errorf("Expected outbound fake_packets '1-3', got %v", outbound["fake_packets"])
	}

	// Test Xray outbound builder maps noise correctly
	xrayOutbound, err := mgr.buildXrayOutbound(cfg, "test")
	if err != nil {
		t.Fatalf("Failed to build xray outbound: %v", err)
	}
	settings := xrayOutbound["settings"].(map[string]interface{})
	if settings["wnoise"] != "quic" {
		t.Errorf("Expected xray outbound settings wnoise 'quic', got %v", settings["wnoise"])
	}
}

func TestParseProxyURI_VLESS_gRPC(t *testing.T) {
	uri := "vless://uuid-789@grpc.example.com:443/?type=grpc&serviceName=grpc-service&authority=grpc-host&multiMode=true&security=reality&pbk=test-pbk&fp=chrome&sni=grpc.example.com&sid=ab12cd34"
	cfg, err := ParseProxyURI(uri)
	if err != nil {
		t.Fatalf("Failed to parse VLESS gRPC URI: %v", err)
	}

	if cfg.Protocol != ProtocolVLESS {
		t.Errorf("Expected Protocol VLESS, got %q", cfg.Protocol)
	}
	if cfg.Transport != "grpc" {
		t.Errorf("Expected Transport grpc, got %q", cfg.Transport)
	}
	if cfg.ServiceName != "grpc-service" {
		t.Errorf("Expected ServiceName grpc-service, got %q", cfg.ServiceName)
	}
	if cfg.Authority != "grpc-host" {
		t.Errorf("Expected Authority grpc-host, got %q", cfg.Authority)
	}
	if !cfg.MultiMode {
		t.Errorf("Expected MultiMode true, got false")
	}

	mgr := NewCoreManager(CoreTypeXray, "")
	xrayOutbound, err := mgr.buildXrayOutbound(cfg, "test")
	if err != nil {
		t.Fatalf("Failed to build xray outbound config: %v", err)
	}

	streamSettings, ok := xrayOutbound["streamSettings"].(map[string]interface{})
	if !ok {
		t.Fatal("Failed to extract streamSettings from outbound")
	}

	if streamSettings["network"] != "grpc" {
		t.Errorf("Expected network grpc, got %v", streamSettings["network"])
	}
	if streamSettings["security"] != "reality" {
		t.Errorf("Expected security reality, got %v", streamSettings["security"])
	}

	reality, ok := streamSettings["realitySettings"].(map[string]interface{})
	if !ok {
		t.Fatal("Failed to extract realitySettings")
	}
	if reality["publicKey"] != "test-pbk" {
		t.Errorf("Expected publicKey test-pbk, got %v", reality["publicKey"])
	}
	if reality["serverName"] != "grpc.example.com" {
		t.Errorf("Expected serverName grpc.example.com, got %v", reality["serverName"])
	}
	if reality["shortId"] != "ab12cd34" {
		t.Errorf("Expected shortId ab12cd34, got %v", reality["shortId"])
	}

	grpc, ok := streamSettings["grpcSettings"].(map[string]interface{})
	if !ok {
		t.Fatal("Failed to extract grpcSettings")
	}
	if grpc["serviceName"] != "grpc-service" {
		t.Errorf("Expected serviceName grpc-service, got %v", grpc["serviceName"])
	}
	if grpc["authority"] != "grpc-host" {
		t.Errorf("Expected authority grpc-host, got %v", grpc["authority"])
	}
	if grpc["multiMode"] != true {
		t.Errorf("Expected multiMode true, got %v", grpc["multiMode"])
	}
}

func TestParseProxyURI_VLESS_Fragmentation(t *testing.T) {
	uri := "vless://uuid-789@example.com:443/?security=tls&fragment=10-20,20-30,tlshello"
	cfg, err := ParseProxyURI(uri)
	if err != nil {
		t.Fatalf("Failed to parse VLESS URI: %v", err)
	}

	if cfg.FragmentLength != "10-20" {
		t.Errorf("Expected FragmentLength '10-20', got %q", cfg.FragmentLength)
	}
	if cfg.FragmentInterval != "20-30" {
		t.Errorf("Expected FragmentInterval '20-30', got %q", cfg.FragmentInterval)
	}
	if cfg.FragmentPackets != "tlshello" {
		t.Errorf("Expected FragmentPackets 'tlshello', got %q", cfg.FragmentPackets)
	}

	mgr := NewCoreManager(CoreTypeXray, "")
	xrayOutbound, err := mgr.buildXrayOutbound(cfg, "test")
	if err != nil {
		t.Fatalf("Failed to build xray outbound: %v", err)
	}

	streamSettings, ok := xrayOutbound["streamSettings"].(map[string]interface{})
	if !ok {
		t.Fatal("Failed to extract streamSettings")
	}

	sockopt, ok := streamSettings["sockopt"].(map[string]interface{})
	if !ok {
		t.Fatal("Failed to extract sockopt settings")
	}

	fragment, ok := sockopt["fragment"].(map[string]interface{})
	if !ok {
		t.Fatal("Failed to extract fragment settings from sockopt")
	}

	if fragment["packets"] != "tlshello" {
		t.Errorf("Expected fragment packets 'tlshello', got %v", fragment["packets"])
	}
	if fragment["length"] != "10-20" {
		t.Errorf("Expected fragment length '10-20', got %v", fragment["length"])
	}
	if fragment["interval"] != "20-30" {
		t.Errorf("Expected fragment interval '20-30', got %v", fragment["interval"])
	}
}

func TestParseProxyURI_Nipo(t *testing.T) {
	nipoJSON := `{
		"name": "Nipo Test Node",
		"config": {
			"serverIp": "127.0.0.10",
			"serverPort": "443",
			"token": "my-secret-token",
			"protocol": "socks5",
			"fakeUrls": "google.com\nsudoer.ir",
			"endPoints": "api\nlogin",
			"tlsEnable": true
		}
	}`

	b64 := base64.StdEncoding.EncodeToString([]byte(nipoJSON))
	uri := "nipovpn://" + b64

	cfg, err := ParseProxyURI(uri)
	if err != nil {
		t.Fatalf("Failed to parse Nipo URI: %v", err)
	}

	if cfg.Protocol != ProtocolNipo {
		t.Errorf("Expected Protocol Nipo, got %q", cfg.Protocol)
	}
	if cfg.Address != "127.0.0.10" {
		t.Errorf("Expected Address '127.0.0.10', got %q", cfg.Address)
	}
	if cfg.Port != 443 {
		t.Errorf("Expected Port 443, got %d", cfg.Port)
	}
	if cfg.Password != "my-secret-token" {
		t.Errorf("Expected Password 'my-secret-token', got %q", cfg.Password)
	}
	if cfg.SNI != "google.com" {
		t.Errorf("Expected SNI 'google.com', got %q", cfg.SNI)
	}
	if cfg.Path != "/api" {
		t.Errorf("Expected Path '/api', got %q", cfg.Path)
	}
	if cfg.Transport != "socks5" {
		t.Errorf("Expected Transport 'socks5', got %q", cfg.Transport)
	}
	if cfg.Name != "Nipo Test Node" {
		t.Errorf("Expected Name 'Nipo Test Node', got %q", cfg.Name)
	}

	// Test ToURI reconstruction matches
	reconstructed := cfg.ToURI()
	cfg2, err := ParseProxyURI(reconstructed)
	if err != nil {
		t.Fatalf("Failed to parse reconstructed Nipo URI: %v", err)
	}
	if cfg2.Address != cfg.Address || cfg2.Port != cfg.Port || cfg2.Password != cfg.Password || cfg2.Name != cfg.Name {
		t.Errorf("Reconstructed config does not match original: %+v vs %+v", cfg2, cfg)
	}
}

func TestParseProxyURI_Warp(t *testing.T) {
	uri := "warp://A1@188.114.97.170:894?ifp=1-3&ifpm=m4#MyWarp"
	cfg, err := ParseProxyURI(uri)
	if err != nil {
		t.Fatalf("Failed to parse warp URI: %v", err)
	}
	if cfg.Protocol != ProtocolWireGuard {
		t.Errorf("Expected ProtocolWireGuard, got %v", cfg.Protocol)
	}
	if cfg.FakePackets != "1-3" {
		t.Errorf("Expected FakePackets '1-3', got %q", cfg.FakePackets)
	}
	if cfg.FakePacketsMode != "m4" {
		t.Errorf("Expected FakePacketsMode 'm4', got %q", cfg.FakePacketsMode)
	}
	if cfg.Port != 894 {
		t.Errorf("Expected Port 894, got %d", cfg.Port)
	}
}

func TestParseProxyURI_DNSTT(t *testing.T) {
	uri := "dnstt://?tunnel_per_resolver=4&resolver=8.8.8.8:53&resolver=8.8.4.4:53&domain=dnstt.hiddify.com&publicKey=xxxx#DNSTTTest"
	cfg, err := ParseProxyURI(uri)
	if err != nil {
		t.Fatalf("Failed to parse dnstt URI: %v", err)
	}
	if cfg.Protocol != ProtocolDNSTT {
		t.Errorf("Expected ProtocolDNSTT, got %v", cfg.Protocol)
	}
	if cfg.Address != "dnstt.hiddify.com" {
		t.Errorf("Expected Address 'dnstt.hiddify.com', got %q", cfg.Address)
	}
	if cfg.PublicKey != "xxxx" {
		t.Errorf("Expected PublicKey 'xxxx', got %q", cfg.PublicKey)
	}
	if len(cfg.Resolvers) != 2 || cfg.Resolvers[0] != "8.8.8.8:53" || cfg.Resolvers[1] != "8.8.4.4:53" {
		t.Errorf("Expected Resolvers ['8.8.8.8:53', '8.8.4.4:53'], got %v", cfg.Resolvers)
	}
	if cfg.TunnelPerResolver != 4 {
		t.Errorf("Expected TunnelPerResolver 4, got %d", cfg.TunnelPerResolver)
	}

	mgr := NewCoreManager(CoreTypeSingBox, "")
	outbound, err := mgr.buildSingBoxOutbound(cfg, "dns-tunnel")
	if err != nil {
		t.Fatalf("Failed to build sing-box outbound: %v", err)
	}
	if outbound["type"] != "dnstt" {
		t.Errorf("Expected outbound type 'dnstt', got %v", outbound["type"])
	}
	if outbound["domain"] != "dnstt.hiddify.com" {
		t.Errorf("Expected domain 'dnstt.hiddify.com', got %v", outbound["domain"])
	}
	if outbound["publicKey"] != "xxxx" {
		t.Errorf("Expected publicKey 'xxxx', got %v", outbound["publicKey"])
	}
}

func TestParseProxyURI_DetourChain(t *testing.T) {
	uri := "socks://127.0.0.1:1080#socks-chain -> dnstt://?tunnel_per_resolver=4&resolver=8.8.8.8:53&domain=dnstt.hiddify.com&publicKey=xxxx#dnstt-chain"
	cfg, err := ParseProxyURI(uri)
	if err != nil {
		t.Fatalf("Failed to parse detour chain URI: %v", err)
	}

	if cfg.Protocol != ProtocolSOCKS5 {
		t.Errorf("Expected first protocol SOCKS5, got %v", cfg.Protocol)
	}
	if cfg.DialerProxy != "dnstt-chain" {
		t.Errorf("Expected DialerProxy 'dnstt-chain', got %q", cfg.DialerProxy)
	}
	if cfg.Detour == nil {
		t.Fatal("Expected Detour config to be parsed and not nil")
	}
	if cfg.Detour.Protocol != ProtocolDNSTT {
		t.Errorf("Expected detour protocol DNSTT, got %v", cfg.Detour.Protocol)
	}

	// Test building singbox config with detour
	mgr := NewCoreManager(CoreTypeSingBox, "")
	configData, err := mgr.BuildSingBoxConfig(cfg, 12345)
	if err != nil {
		t.Fatalf("Failed to build sing-box config: %v", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(configData, &config); err != nil {
		t.Fatalf("Failed to parse generated json: %v", err)
	}

	outbounds := config["outbounds"].([]interface{})
	if len(outbounds) < 3 {
		t.Errorf("Expected at least 3 outbounds (proxy, detour, direct-out), got %d", len(outbounds))
	}

	// First outbound should be socks and detour to next
	firstOut := outbounds[0].(map[string]interface{})
	if firstOut["type"] != "socks" {
		t.Errorf("Expected first outbound type 'socks', got %v", firstOut["type"])
	}
	if firstOut["dialer_proxy"] != "dnstt-chain" {
		t.Errorf("Expected first outbound dialer_proxy 'dnstt-chain', got %v", firstOut["dialer_proxy"])
	}

	// Second outbound should be dnstt
	secondOut := outbounds[1].(map[string]interface{})
	if secondOut["type"] != "dnstt" {
		t.Errorf("Expected second outbound type 'dnstt', got %v", secondOut["type"])
	}
}



