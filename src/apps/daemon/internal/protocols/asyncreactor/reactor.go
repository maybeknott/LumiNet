package asyncreactor

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/xtaci/gaio"
)

// ConnectionPair holds references to two paired connections.
type ConnectionPair struct {
	Client   net.Conn
	Target   net.Conn
	Closed   bool
	observer Observer
}

// Observer reports bytes only after a successful async read has produced data
// to forward. OnClose runs exactly once when the pair is released.
type Observer struct {
	OnClientToTarget func(int)
	OnTargetToClient func(int)
	OnClose          func()
}

// AsyncReactor manages async connection forwarding using gaio.
type AsyncReactor struct {
	watcher *gaio.Watcher
	pairs   map[net.Conn]*ConnectionPair
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewAsyncReactor creates a new AsyncReactor instance.
func NewAsyncReactor() (*AsyncReactor, error) {
	w, err := gaio.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create gaio watcher: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	r := &AsyncReactor{
		watcher: w,
		pairs:   make(map[net.Conn]*ConnectionPair),
		ctx:     ctx,
		cancel:  cancel,
	}

	r.wg.Add(1)
	go r.reactorLoop()

	return r, nil
}

// Register registers a paired client and target connection.
func (r *AsyncReactor) Register(client, target net.Conn) error {
	return r.RegisterObserved(client, target, Observer{})
}

// RegisterObserved registers a pair with optional flow-observability hooks.
// The hooks do not own the connections and must not block.
func (r *AsyncReactor) RegisterObserved(client, target net.Conn, observer Observer) error {
	pair := &ConnectionPair{Client: client, Target: target, observer: observer}

	r.mu.Lock()
	r.pairs[client] = pair
	r.pairs[target] = pair

	// Submit initial read requests while the lifecycle lock prevents a
	// concurrent Close from releasing the pair mid-registration.
	buf1 := make([]byte, 4096)
	buf2 := make([]byte, 4096)
	if err := r.watcher.Read(nil, client, buf1); err != nil {
		callback := r.freePairLocked(pair)
		r.mu.Unlock()
		callObserver(callback)
		return fmt.Errorf("failed to submit read for client: %w", err)
	}
	if err := r.watcher.Read(nil, target, buf2); err != nil {
		callback := r.freePairLocked(pair)
		r.mu.Unlock()
		callObserver(callback)
		return fmt.Errorf("failed to submit read for target: %w", err)
	}
	r.mu.Unlock()
	return nil
}

func (r *AsyncReactor) reactorLoop() {
	defer r.wg.Done()

	for {
		select {
		case <-r.ctx.Done():
			return
		default:
			results, err := r.watcher.WaitIO()
			if err != nil {
				return
			}

			for _, res := range results {
				r.handleEvent(res)
			}
		}
	}
}

func (r *AsyncReactor) handleEvent(res gaio.OpResult) {
	// Pair membership and Closed are one lifecycle state protected by mu.
	r.mu.Lock()
	pair, exists := r.pairs[res.Conn]
	if !exists || pair.Closed {
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()

	if res.Error != nil {
		r.releasePair(pair)
		return
	}

	var peer net.Conn
	if res.Conn == pair.Client {
		peer = pair.Target
	} else {
		peer = pair.Client
	}

	switch res.Operation {
	case gaio.OpRead:
		if res.Size > 0 {
			if res.Conn == pair.Client {
				if pair.observer.OnClientToTarget != nil {
					pair.observer.OnClientToTarget(res.Size)
				}
			} else if pair.observer.OnTargetToClient != nil {
				pair.observer.OnTargetToClient(res.Size)
			}

			writeBuf := make([]byte, res.Size)
			copy(writeBuf, res.Buffer[:res.Size])
			if err := r.watcher.Write(nil, peer, writeBuf); err != nil {
				r.releasePair(pair)
				return
			}

			readBuf := make([]byte, 4096)
			if err := r.watcher.Read(nil, res.Conn, readBuf); err != nil {
				r.releasePair(pair)
			}
		} else {
			r.releasePair(pair)
		}
	case gaio.OpWrite:
		// Write completed. The OpRead path already keeps the read pump active.
	}
}

func callObserver(callback func()) {
	if callback != nil {
		callback()
	}
}

// freePairLocked releases lifecycle-owned pair resources and returns the
// observer callback for invocation after mu is released. r.mu must be held.
func (r *AsyncReactor) freePairLocked(pair *ConnectionPair) func() {
	if pair.Closed {
		return nil
	}
	pair.Closed = true

	delete(r.pairs, pair.Client)
	delete(r.pairs, pair.Target)

	_ = r.watcher.Free(pair.Client)
	_ = r.watcher.Free(pair.Target)
	_ = pair.Client.Close()
	_ = pair.Target.Close()
	return pair.observer.OnClose
}

func (r *AsyncReactor) releasePair(pair *ConnectionPair) {
	r.mu.Lock()
	callback := r.freePairLocked(pair)
	r.mu.Unlock()
	callObserver(callback)
}

// Close stops the reactor loop and closes all registered connections.
func (r *AsyncReactor) Close() error {
	r.cancel()
	err := r.watcher.Close()

	var callbacks []func()
	r.mu.Lock()
	for _, pair := range r.pairs {
		if callback := r.freePairLocked(pair); callback != nil {
			callbacks = append(callbacks, callback)
		}
	}
	r.mu.Unlock()
	for _, callback := range callbacks {
		callObserver(callback)
	}

	r.wg.Wait()
	return err
}
