package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/xtaci/gaio"
)

// ConnectionPair holds references to two paired connections.
type ConnectionPair struct {
	Client net.Conn
	Target net.Conn
	Closed bool
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
	r.mu.Lock()
	defer r.mu.Unlock()

	pair := &ConnectionPair{
		Client: client,
		Target: target,
	}

	r.pairs[client] = pair
	r.pairs[target] = pair

	// Submit initial read requests (4KB buffer size)
	buf1 := make([]byte, 4096)
	buf2 := make([]byte, 4096)

	if err := r.watcher.Read(nil, client, buf1); err != nil {
		r.freePair(pair)
		return fmt.Errorf("failed to submit read for client: %w", err)
	}

	if err := r.watcher.Read(nil, target, buf2); err != nil {
		r.freePair(pair)
		return fmt.Errorf("failed to submit read for target: %w", err)
	}

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
				// Watcher closed or stopped
				return
			}

			for _, res := range results {
				r.handleEvent(res)
			}
		}
	}
}

func (r *AsyncReactor) handleEvent(res gaio.OpResult) {
	r.mu.Lock()
	pair, exists := r.pairs[res.Conn]
	r.mu.Unlock()

	if !exists || pair.Closed {
		return
	}

	if res.Error != nil {
		r.mu.Lock()
		r.freePair(pair)
		r.mu.Unlock()
		return
	}

	// Determine peer connection
	var peer net.Conn
	if res.Conn == pair.Client {
		peer = pair.Target
	} else {
		peer = pair.Client
	}

	switch res.Operation {
	case gaio.OpRead:
		if res.Size > 0 {
			// Submit async write to the peer connection
			writeBuf := make([]byte, res.Size)
			copy(writeBuf, res.Buffer[:res.Size])
			
			if err := r.watcher.Write(nil, peer, writeBuf); err != nil {
				r.mu.Lock()
				r.freePair(pair)
				r.mu.Unlock()
				return
			}

			// Submit next read on the same connection immediately to keep the read pump active
			readBuf := make([]byte, 4096)
			if err := r.watcher.Read(nil, res.Conn, readBuf); err != nil {
				r.mu.Lock()
				r.freePair(pair)
				r.mu.Unlock()
			}
		} else {
			// EOF read, tear down connection pair
			r.mu.Lock()
			r.freePair(pair)
			r.mu.Unlock()
		}

	case gaio.OpWrite:
		// Write completed. No further action needed since the read pump is kept active by OpRead.
	}
}

func (r *AsyncReactor) freePair(pair *ConnectionPair) {
	if pair.Closed {
		return
	}
	pair.Closed = true

	delete(r.pairs, pair.Client)
	delete(r.pairs, pair.Target)

	_ = r.watcher.Free(pair.Client)
	_ = r.watcher.Free(pair.Target)
	_ = pair.Client.Close()
	_ = pair.Target.Close()
}

// Close stops the reactor loop and closes all registered connections.
func (r *AsyncReactor) Close() error {
	r.cancel()
	err := r.watcher.Close()

	r.mu.Lock()
	for _, pair := range r.pairs {
		r.freePair(pair)
	}
	r.mu.Unlock()

	r.wg.Wait()
	return err
}
