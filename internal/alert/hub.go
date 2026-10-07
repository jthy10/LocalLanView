// Package alert fans events out to the dashboard (Server-Sent Events),
// desktop notifications and an optional local webhook.
package alert

import (
	"encoding/json"
	"sync"
)

// Message is pushed to connected dashboards.
type Message struct {
	Type string `json:"type"` // "device", "event", "scan"
	Data any    `json:"data"`
}

// Hub broadcasts messages to subscribers. Slow subscribers drop messages
// rather than block scanning.
type Hub struct {
	mu   sync.Mutex
	subs map[chan []byte]struct{}
}

func NewHub() *Hub { return &Hub{subs: map[chan []byte]struct{}{}} }

// Subscribe returns a channel of JSON-encoded messages and a cancel func.
func (h *Hub) Subscribe() (<-chan []byte, func()) {
	ch := make(chan []byte, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
}

// Publish sends m to every subscriber.
func (h *Hub) Publish(m Message) {
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- b:
		default:
		}
	}
}
