package proxy

import (
	"testing"
)

func TestMultiEngineProxyManager(t *testing.T) {
	engine, err := GetProxyEngine(EngineSingBox)
	if err != nil {
		t.Fatalf("Failed to resolve SingBoxEngine: %v", err)
	}

	if engine.IsRunning() {
		t.Errorf("Expected engine to be idle initially")
	}

	err = engine.Start()
	if err != nil {
		t.Fatalf("Failed to start engine: %v", err)
	}

	if !engine.IsRunning() {
		t.Errorf("Expected engine to be running after Start")
	}

	engine.Stop()

	if engine.IsRunning() {
		t.Errorf("Expected engine to be idle after Stop")
	}

	// Test Psiphon Engine resolving
	psiphon, err := GetProxyEngine(EnginePsiphon)
	if err != nil {
		t.Fatalf("Failed to resolve PsiphonEngine: %v", err)
	}
	if psiphon.IsRunning() {
		t.Errorf("Expected engine to be idle initially")
	}

	// Test unsupported engine types
	_, err = GetProxyEngine("invalid-engine")
	if err == nil {
		t.Errorf("Expected error when requesting invalid engine type, got nil")
	}
}
