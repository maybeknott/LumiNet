package api

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/maybeknott/luminet/internal/jobs"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 512
)

type wsBroadcast struct {
	jobID     string
	eventType string
	data      interface{}
}

// Client represents a single WebSocket client connection.
type Client struct {
	hub           *Hub
	conn          *websocket.Conn
	send          chan []byte
	subscriptions map[string]bool
	mu            sync.RWMutex
}

// Hub manages all active WebSocket clients and message broadcasting.
type Hub struct {
	clients    map[*Client]bool
	broadcast  chan *wsBroadcast
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
}

// Command represents a client-to-server WS command. (Legacy name for compatibility in this file)
type Command = WSCommand

// NewHub creates a new WebSocket hub ready to accept clients.
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan *wsBroadcast, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

// Run starts the hub's main event loop, processing register/unregister/broadcast events.
// This should be run in a dedicated goroutine.
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()

		case broadcast := <-h.broadcast:
			msg := WSMessage{
				Type:      broadcast.eventType,
				JobID:     broadcast.jobID,
				Data:      broadcast.data,
				Timestamp: time.Now(),
			}
			payload, err := json.Marshal(msg)
			if err != nil {
				continue
			}

			h.mu.RLock()
			for client := range h.clients {
				client.mu.RLock()
				isSubscribed := broadcast.jobID == "" || client.subscriptions[broadcast.jobID] || client.subscriptions["*"]
				client.mu.RUnlock()

				if isSubscribed {
					// Non-blocking write to avoid blocking the hub if a client is slow
					select {
					case client.send <- payload:
					default:
						// Evict slow/stalled client (B-3)
						h.mu.RUnlock()
						h.mu.Lock()
						if _, ok := h.clients[client]; ok {
							delete(h.clients, client)
							close(client.send)
						}
						h.mu.Unlock()
						h.mu.RLock()
					}
				}
			}
			h.mu.RUnlock()
		}
	}
}

// ListenToJobs subscribes to the job manager's broadcaster and routes events to connected clients.
func (h *Hub) ListenToJobs(jobMgr *jobs.JobManager) {
	broadcaster := jobMgr.GetBroadcaster()
	if broadcaster == nil {
		return
	}

	ch := broadcaster.SubscribeAll()
	go func() {
		for event := range ch {
			h.BroadcastJobEvent(event.JobID, event.Type, event.Data)
		}
	}()
}

// ServeWs upgrades an HTTP request to a WebSocket connection and registers the client.
func (h *Hub) ServeWs(w http.ResponseWriter, r *http.Request, allowedOrigins []string) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true
			}
			u, err := url.Parse(origin)
			if err != nil {
				return false
			}
			host := u.Hostname()
			if host == "localhost" || host == "127.0.0.1" || host == "::1" {
				return true
			}
			for _, allowed := range allowedOrigins {
				if allowed == "*" || allowed == origin {
					return true
				}
				if au, err := url.Parse(allowed); err == nil && au.Hostname() == host {
					return true
				}
			}
			return false
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade websocket: %v", err)
		return
	}

	client := &Client{
		hub:           h,
		conn:          conn,
		send:          make(chan []byte, 256),
		subscriptions: make(map[string]bool),
	}

	h.register <- client

	// Start reader and writer pumps
	go client.writePump()
	go client.readPump()
}

// BroadcastJobEvent sends a job-related event to all connected clients
// that are subscribed to the given job ID, or to all clients if jobID is empty.
func (h *Hub) BroadcastJobEvent(jobID string, eventType string, data interface{}) {
	select {
	case h.broadcast <- &wsBroadcast{jobID: jobID, eventType: eventType, data: data}:
	default:
		// Drop message if hub broadcast queue is full
	}
}

// BroadcastSystemEvent sends a system-level event to all connected clients.
func (h *Hub) BroadcastSystemEvent(eventType string, data interface{}) {
	select {
	case h.broadcast <- &wsBroadcast{jobID: "", eventType: eventType, data: data}:
	default:
		// Drop message if hub broadcast queue is full
	}
}

// readPump pumps messages from the WebSocket connection to the hub.
// It handles client commands like subscribe/unsubscribe.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			break
		}

		var cmd Command
		if err := json.Unmarshal(message, &cmd); err != nil {
			continue
		}

		c.mu.Lock()
		switch cmd.Action {
		case "subscribe":
			c.subscriptions[cmd.JobID] = true
		case "unsubscribe":
			delete(c.subscriptions, cmd.JobID)
		}
		c.mu.Unlock()
	}
}

// writePump pumps messages from the hub to the WebSocket connection.
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			_, _ = w.Write(message)

			// Add queued chat messages to the current websocket message.
			n := len(c.send)
			for i := 0; i < n; i++ {
				_, _ = w.Write([]byte{'\n'})
				_, _ = w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
