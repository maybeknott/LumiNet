package proxy

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/maybeknott/luminet/internal/config"
)

// ConfigWatcher monitors configuration files for modifications and dynamically reloads them.
type ConfigWatcher struct {
	manager    *config.Manager
	configPath string
	interval   time.Duration
	callbacks  []func(*config.Config)
	mu         sync.Mutex
	lastMod    time.Time
	running    bool
	cancel     context.CancelFunc
}

// NewConfigWatcher creates a new ConfigWatcher instance.
func NewConfigWatcher(manager *config.Manager, configPath string, interval time.Duration) *ConfigWatcher {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return &ConfigWatcher{
		manager:    manager,
		configPath: configPath,
		interval:   interval,
	}
}

// OnChange registers a callback to trigger on config file changes.
func (w *ConfigWatcher) OnChange(callback func(*config.Config)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.callbacks = append(w.callbacks, callback)
}

// Start launches the background filesystem monitoring polling loop.
func (w *ConfigWatcher) Start(ctx context.Context) {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return
	}
	w.running = true
	subCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.mu.Unlock()

	if info, err := os.Stat(w.configPath); err == nil {
		w.lastMod = info.ModTime()
	}

	go w.watchLoop(subCtx)
}

// Stop terminates the file monitor watcher.
func (w *ConfigWatcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.running {
		return
	}
	w.running = false
	if w.cancel != nil {
		w.cancel()
	}
}

func (w *ConfigWatcher) watchLoop(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			info, err := os.Stat(w.configPath)
			if err != nil {
				continue
			}

			w.mu.Lock()
			modTime := info.ModTime()
			if modTime.After(w.lastMod) {
				w.lastMod = modTime
				w.mu.Unlock()

				cfg, err := w.manager.Load()
				if err == nil {
					w.mu.Lock()
					callbacks := w.callbacks
					w.mu.Unlock()

					for _, cb := range callbacks {
						cb(cfg)
					}
				}
			} else {
				w.mu.Unlock()
			}
		}
	}
}
