// Package plugins implements dynamic plugin loading, invocation lifecycle events, and monitoring extensions.
package plugins

import (
	"context"
	"fmt"
	"sync"
)

// Plugin defines functions that all loadable custom system components must implement.
type Plugin interface {
	Name() string
	Version() string
	Init(ctx context.Context) error
	OnEvent(ctx context.Context, eventType string, payload interface{}) error
	Stop() error
}

// Manager orchestrates searching, registering, and notifying functional plugin modules.
type Manager struct {
	pluginsDir string
	mu         sync.RWMutex
	registry   map[string]Plugin
}

// NewManager constructs a Manager reading from the specified plugins directory.
func NewManager(pluginsDir string) *Manager {
	return &Manager{
		pluginsDir: pluginsDir,
		registry:   make(map[string]Plugin),
	}
}

// LoadPlugins walks the plugins directory to discover and load plugins.
// Currently supports in-process plugins registered via RegisterPlugin.
// Dynamic .so loading can be added here in the future.
func (m *Manager) LoadPlugins(ctx context.Context) error {
	// Dynamic plugin loading via plugin.Open requires CGO and Linux .so files.
	// For now, this is a no-op — plugins are registered programmatically.
	return nil
}

// RegisterPlugin inserts a programmatically instantiated plugin directly into the manager registry.
func (m *Manager) RegisterPlugin(p Plugin) error {
	if p == nil {
		return fmt.Errorf("cannot register nil plugin")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	name := p.Name()
	if _, exists := m.registry[name]; exists {
		return fmt.Errorf("plugin %q is already registered", name)
	}
	m.registry[name] = p
	return nil
}

// InitAll calls Init on all registered plugins.
func (m *Manager) InitAll(ctx context.Context) []error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var errs []error
	for _, p := range m.registry {
		if err := p.Init(ctx); err != nil {
			errs = append(errs, fmt.Errorf("plugin %q init failed: %w", p.Name(), err))
		}
	}
	return errs
}

// DispatchEvent sends an event to all registered plugins.
func (m *Manager) DispatchEvent(ctx context.Context, eventType string, payload interface{}) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.registry {
		// Non-blocking: ignore individual plugin errors
		_ = p.OnEvent(ctx, eventType, payload)
	}
}

// UnloadPlugins halts all plugins in the active registry and purges their loaded memories.
func (m *Manager) UnloadPlugins() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var firstErr error
	for name, p := range m.registry {
		if err := p.Stop(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("plugin %q stop failed: %w", name, err)
		}
		delete(m.registry, name)
	}
	return firstErr
}

// List returns the names and versions of all registered plugins.
func (m *Manager) List() []map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []map[string]string
	for _, p := range m.registry {
		result = append(result, map[string]string{
			"name":    p.Name(),
			"version": p.Version(),
		})
	}
	return result
}
