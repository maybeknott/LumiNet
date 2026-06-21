package jobs

import (
	"sync"
	"time"
)

// JobEvent represents an event emitted by a job during its lifecycle.
type JobEvent struct {
	// JobID is the job that emitted this event.
	JobID string `json:"job_id"`
	// Type is the event type (progress, status_change, result, error).
	Type string `json:"type"`
	// Data is the event payload (varies by type).
	Data interface{} `json:"data"`
	// Timestamp is when the event was emitted.
	Timestamp time.Time `json:"timestamp"`
}

// Broadcaster provides event fan-out to multiple subscribers per job.
// It allows WebSocket clients to subscribe to specific job events
// and receive real-time updates.
type Broadcaster struct {
	// subscribers maps job IDs to their subscriber channels.
	subscribers map[string][]chan JobEvent
	// globalSubs are channels that receive events from all jobs.
	globalSubs []chan JobEvent
	// mu protects the subscribers maps.
	mu sync.RWMutex
}

// NewBroadcaster creates a new event broadcaster.
func NewBroadcaster() *Broadcaster {
	return &Broadcaster{
		subscribers: make(map[string][]chan JobEvent),
		globalSubs:  make([]chan JobEvent, 0),
	}
}

// Subscribe registers a channel to receive events for a specific job ID.
// Returns a channel that will receive JobEvent values.
// The caller is responsible for unsubscribing when done.
func (b *Broadcaster) Subscribe(jobID string) <-chan JobEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan JobEvent, 100) // Buffer to prevent blockages
	b.subscribers[jobID] = append(b.subscribers[jobID], ch)
	return ch
}

// SubscribeAll registers a channel to receive events from all jobs.
// Returns a channel that will receive JobEvent values.
func (b *Broadcaster) SubscribeAll() <-chan JobEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan JobEvent, 500)
	b.globalSubs = append(b.globalSubs, ch)
	return ch
}

// Unsubscribe removes a previously registered subscription channel for a job ID.
func (b *Broadcaster) Unsubscribe(jobID string, ch <-chan JobEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	subs := b.subscribers[jobID]
	for i, sub := range subs {
		if sub == ch {
			close(sub)
			b.subscribers[jobID] = append(subs[:i], subs[i+1:]...)
			break
		}
	}
	if len(b.subscribers[jobID]) == 0 {
		delete(b.subscribers, jobID)
	}
}

// UnsubscribeAll removes a previously registered global subscription channel.
func (b *Broadcaster) UnsubscribeAll(ch <-chan JobEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, sub := range b.globalSubs {
		if sub == ch {
			close(sub)
			b.globalSubs = append(b.globalSubs[:i], b.globalSubs[i+1:]...)
			break
		}
	}
}

// Publish sends an event to all subscribers of the event's job ID
// and to all global subscribers. Non-blocking: if a subscriber's channel
// is full, the event is dropped for that subscriber.
func (b *Broadcaster) Publish(event JobEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Publish to job-specific subscribers
	if subs, ok := b.subscribers[event.JobID]; ok {
		for _, ch := range subs {
			select {
			case ch <- event:
			default:
				// Drop event if channel is full
			}
		}
	}

	// Publish to global subscribers
	for _, ch := range b.globalSubs {
		select {
		case ch <- event:
		default:
			// Drop event if channel is full
		}
	}
}
