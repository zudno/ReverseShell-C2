package server

import (
	"encoding/json"
	"sync"

	"reverseshell/internal/api"
)

// EventBus fans session events out to operator API subscribers (SSE). Slow
// subscribers drop events; the core never blocks on the control plane.
type EventBus struct {
	mu   sync.Mutex
	subs map[chan api.Event]struct{}
}

// NewEventBus returns a bus with no subscribers.
func NewEventBus() *EventBus {
	return &EventBus{subs: make(map[chan api.Event]struct{})}
}

// Subscribe returns a buffered event channel and its cancel function.
func (b *EventBus) Subscribe() (<-chan api.Event, func()) {
	ch := make(chan api.Event, 64)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subs, ch)
		b.mu.Unlock()
	}
}

// Emit marshals data and delivers it to every subscriber without blocking.
func (b *EventBus) Emit(typ string, data any) {
	raw, err := json.Marshal(data)
	if err != nil {
		raw = []byte("{}")
	}
	ev := api.Event{Type: typ, Data: raw}
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}
