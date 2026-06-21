package system

import (
	"fmt"
	"log"
	"time"

	"github.com/nats-io/nats.go"
)

// AgentBus provides a messaging backbone for distributed diagnostics and sidecars.
type AgentBus struct {
	nc *nats.Conn
}

// NewAgentBus connects to a NATS server or returns a new AgentBus instance.
func NewAgentBus(url string) (*AgentBus, error) {
	if url == "" {
		url = nats.DefaultURL
	}
	nc, err := nats.Connect(url, nats.Timeout(5*time.Second))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}
	log.Printf("AgentBus connected to %s", nc.ConnectedUrl())
	return &AgentBus{nc: nc}, nil
}

// Publish broadcasts a message to a specific subject.
func (b *AgentBus) Publish(subject string, data []byte) error {
	if b.nc == nil {
		return fmt.Errorf("AgentBus not connected")
	}
	return b.nc.Publish(subject, data)
}

// Subscribe registers a handler for a specific subject.
func (b *AgentBus) Subscribe(subject string, handler nats.MsgHandler) (*nats.Subscription, error) {
	if b.nc == nil {
		return nil, fmt.Errorf("AgentBus not connected")
	}
	return b.nc.Subscribe(subject, handler)
}

// Close gracefully closes the connection to the NATS server.
func (b *AgentBus) Close() {
	if b.nc != nil {
		b.nc.Close()
	}
}
