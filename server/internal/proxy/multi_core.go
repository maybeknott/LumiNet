package proxy

import (
	"fmt"
	"sync"
)

// ProxyEngine defines the interface for managing proxy backend cores.
type ProxyEngine interface {
	Start() error
	Stop()
	IsRunning() bool
}

// EngineType defines the supported backend proxy engine drivers.
type EngineType string

const (
	// EngineSingBox driver manages the Sing-box core.
	EngineSingBox EngineType = "sing-box"
	// EnginePsiphon driver manages the Psiphon core.
	EnginePsiphon EngineType = "psiphon"
	// EngineTor driver manages the Tor client core.
	EngineTor EngineType = "tor"
	// EngineTailscale driver manages the Tailscale mesh VPN node core.
	EngineTailscale EngineType = "tailscale"
)

// SingBoxEngine implements ProxyEngine for Sing-box.
type SingBoxEngine struct {
	mu        sync.Mutex
	isRunning bool
}

// Start starts the Sing-box engine.
func (e *SingBoxEngine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.isRunning = true
	return nil
}

// Stop stops the Sing-box engine.
func (e *SingBoxEngine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.isRunning = false
}

// IsRunning returns status of the Sing-box engine.
func (e *SingBoxEngine) IsRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.isRunning
}

// TailscaleEngine wraps TailscaleAdapter to implement ProxyEngine.
type TailscaleEngine struct {
	adapter *TailscaleAdapter
}

// NewTailscaleEngineWrapper creates a new TailscaleEngine wrapper.
func NewTailscaleEngineWrapper(authKey, hostname, stateDir string) *TailscaleEngine {
	return &TailscaleEngine{
		adapter: NewTailscaleAdapter(authKey, hostname, stateDir),
	}
}

// Start starts the Tailscale engine.
func (e *TailscaleEngine) Start() error {
	return e.adapter.Start()
}

// Stop stops the Tailscale engine.
func (e *TailscaleEngine) Stop() {
	e.adapter.Stop()
}

// IsRunning returns status of the Tailscale engine.
func (e *TailscaleEngine) IsRunning() bool {
	return e.adapter.IsRunning()
}

// PsiphonEngine wraps RealPsiphonEngine to implement ProxyEngine.
type PsiphonEngine struct {
	realEngine *RealPsiphonEngine
}

// NewPsiphonEngineWrapper creates a new wrapper instance.
func NewPsiphonEngineWrapper(socksPort int) *PsiphonEngine {
	return &PsiphonEngine{
		realEngine: NewPsiphonEngine(socksPort),
	}
}

// Start starts the Psiphon engine.
func (e *PsiphonEngine) Start() error {
	if e.realEngine == nil {
		e.realEngine = NewPsiphonEngine(10890)
	}
	return e.realEngine.Start()
}

// Stop stops the Psiphon engine.
func (e *PsiphonEngine) Stop() {
	if e.realEngine != nil {
		e.realEngine.Stop()
	}
}

// IsRunning returns status of the Psiphon engine.
func (e *PsiphonEngine) IsRunning() bool {
	if e.realEngine == nil {
		return false
	}
	return e.realEngine.IsRunning()
}

// SetUpstreamProxy configures upstream proxy URL for chaining.
func (e *PsiphonEngine) SetUpstreamProxy(proxyURL string) {
	if e.realEngine != nil {
		e.realEngine.SetUpstreamProxy(proxyURL)
	}
}

// GetProxyEngine resolves and instantiates the requested proxy driver type.
func GetProxyEngine(t EngineType) (ProxyEngine, error) {
	switch t {
	case EngineSingBox:
		return &SingBoxEngine{}, nil
	case EnginePsiphon:
		return NewPsiphonEngineWrapper(10890), nil
	case EngineTor:
		return NewTorEngine(10950, 10951), nil
	case EngineTailscale:
		return NewTailscaleEngineWrapper("mock-key", "luminet-node", "./state"), nil
	default:
		return nil, fmt.Errorf("unsupported proxy engine type: %s", t)
	}
}

