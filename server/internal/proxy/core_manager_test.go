package proxy

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestCoreManager_BuildConfigs_AnyTLS(t *testing.T) {
	anytlsProxy := &ProxyConfig{
		Protocol:        ProtocolAnyTLS,
		Address:         "example-anytls.com",
		Port:            8443,
		Password:        "pass123",
		TLS:             true,
		SNI:             "sni-anytls.com",
		SkipCertVerify:  true,
		MinIdleSessions: 7,
	}

	mgr := NewCoreManager(CoreTypeAuto, "")

	// 1. Test Sing-Box Outbound Generation
	sbOut, err := mgr.buildSingBoxOutbound(anytlsProxy, "anytls-sb")
	if err != nil {
		t.Fatalf("buildSingBoxOutbound failed for AnyTLS: %v", err)
	}

	if sbOut["type"] != "anytls" {
		t.Errorf("Expected sing-box outbound type to be 'anytls', got %v", sbOut["type"])
	}
	if sbOut["password"] != "pass123" {
		t.Errorf("Expected password 'pass123', got %v", sbOut["password"])
	}
	if sbOut["min_idle_sessions"] != 7 {
		t.Errorf("Expected min_idle_sessions 7, got %v", sbOut["min_idle_sessions"])
	}
	tlsMap, ok := sbOut["tls"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected tls map in sing-box outbound")
	}
	if tlsMap["enabled"] != true || tlsMap["insecure"] != true || tlsMap["server_name"] != "sni-anytls.com" {
		t.Errorf("TLS configuration invalid in sing-box AnyTLS: %v", tlsMap)
	}

	// 2. Test Xray Outbound Generation
	xrOut, err := mgr.buildXrayOutbound(anytlsProxy, "anytls-xr")
	if err != nil {
		t.Fatalf("buildXrayOutbound failed for AnyTLS: %v", err)
	}

	if xrOut["protocol"] != "anytls" {
		t.Errorf("Expected xray outbound protocol to be 'anytls', got %v", xrOut["protocol"])
	}
	settings, ok := xrOut["settings"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected settings map in xray outbound")
	}
	if settings["address"] != "example-anytls.com" || settings["port"] != 8443 || settings["password"] != "pass123" {
		t.Errorf("Xray settings invalid in AnyTLS: %v", settings)
	}
	if settings["sni"] != "sni-anytls.com" || settings["allow_insecure"] != true || settings["min_idle_sessions"] != 7 {
		t.Errorf("Xray settings properties invalid: %v", settings)
	}
}

func TestCoreManager_BuildConfigs_Juicity(t *testing.T) {
	juicityProxy := &ProxyConfig{
		Protocol:              ProtocolJuicity,
		Address:               "example-juicity.com",
		Port:                  9443,
		UUID:                  "uuid-456",
		Password:              "pass-456",
		TLS:                   true,
		SNI:                   "sni-juicity.com",
		SkipCertVerify:        true,
		CongestionControl:     "bbr",
		PinnedCertChainSHA256: "sha256-hash",
	}

	mgr := NewCoreManager(CoreTypeAuto, "")

	// 1. Test Sing-Box Outbound Generation
	sbOut, err := mgr.buildSingBoxOutbound(juicityProxy, "juicity-sb")
	if err != nil {
		t.Fatalf("buildSingBoxOutbound failed for Juicity: %v", err)
	}

	if sbOut["type"] != "juicity" {
		t.Errorf("Expected sing-box outbound type to be 'juicity', got %v", sbOut["type"])
	}
	if sbOut["uuid"] != "uuid-456" || sbOut["password"] != "pass-456" {
		t.Errorf("Expected uuid 'uuid-456' and password 'pass-456', got %v, %v", sbOut["uuid"], sbOut["password"])
	}
	if sbOut["congestion_control"] != "bbr" || sbOut["pinned_certchain_sha256"] != "sha256-hash" {
		t.Errorf("Expected congestion 'bbr' and pinned chain 'sha256-hash', got %v, %v", sbOut["congestion_control"], sbOut["pinned_certchain_sha256"])
	}

	// 2. Test Xray Outbound Generation
	xrOut, err := mgr.buildXrayOutbound(juicityProxy, "juicity-xr")
	if err != nil {
		t.Fatalf("buildXrayOutbound failed for Juicity: %v", err)
	}

	if xrOut["protocol"] != "juicity" {
		t.Errorf("Expected xray outbound protocol to be 'juicity', got %v", xrOut["protocol"])
	}
	settings, ok := xrOut["settings"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected settings map in xray outbound")
	}
	if settings["address"] != "example-juicity.com:9443" || settings["uuid"] != "uuid-456" || settings["password"] != "pass-456" {
		t.Errorf("Xray settings invalid in Juicity: %v", settings)
	}
	if settings["congestion_control"] != "bbr" || settings["pinned_certchain_sha256"] != "sha256-hash" {
		t.Errorf("Xray settings properties invalid: %v", settings)
	}
}

func TestCoreManager_BuildConfigs_JSONOutput(t *testing.T) {
	anytlsProxy := &ProxyConfig{
		Protocol:        ProtocolAnyTLS,
		Address:         "example-anytls.com",
		Port:            8443,
		Password:        "pass123",
		TLS:             true,
		SNI:             "sni-anytls.com",
		SkipCertVerify:  true,
		MinIdleSessions: 7,
	}

	mgr := NewCoreManager(CoreTypeSingBox, "sing-box")

	// Verify Sing-Box Full JSON Config Generation
	sbData, err := mgr.BuildSingBoxConfig(anytlsProxy, 1080)
	if err != nil {
		t.Fatalf("BuildSingBoxConfig failed: %v", err)
	}

	var sbConfig map[string]interface{}
	if err := json.Unmarshal(sbData, &sbConfig); err != nil {
		t.Fatalf("Failed to parse generated Sing-Box JSON: %v", err)
	}

	outbounds, ok := sbConfig["outbounds"].([]interface{})
	if !ok || len(outbounds) == 0 {
		t.Fatalf("Outbounds missing or empty in Sing-Box config")
	}
	outbound := outbounds[0].(map[string]interface{})
	if outbound["type"] != "anytls" {
		t.Errorf("Expected outbound type to be 'anytls', got %v", outbound["type"])
	}

	// Verify Xray Full JSON Config Generation
	mgrXr := NewCoreManager(CoreTypeXray, "xray")
	xrData, err := mgrXr.BuildXrayConfig(anytlsProxy, 1080)
	if err != nil {
		t.Fatalf("BuildXrayConfig failed: %v", err)
	}

	var xrConfig map[string]interface{}
	if err := json.NewDecoder(bytes.NewReader(xrData)).Decode(&xrConfig); err != nil {
		t.Fatalf("Failed to parse generated Xray JSON: %v", err)
	}

	xrOutbounds, ok := xrConfig["outbounds"].([]interface{})
	if !ok || len(xrOutbounds) == 0 {
		t.Fatalf("Outbounds missing or empty in Xray config")
	}
	xrOutbound := xrOutbounds[0].(map[string]interface{})
	if xrOutbound["protocol"] != "anytls" {
		t.Errorf("Expected outbound protocol to be 'anytls', got %v", xrOutbound["protocol"])
	}
}
