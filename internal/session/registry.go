package session

import (
	"errors"
	"sort"
	"sync"
	"time"

	"reverseshell/internal/protocol"
)

// State enumerates the session lifecycle (README §4.6).
type State string

const (
	StateRegistered State = "registered"
	StateReady      State = "ready"
	StateTasked     State = "tasked"
	StateClosed     State = "closed"
)

// Session is the teamserver's view of one connected agent. Outbound is the
// FIFO of envelopes waiting to be written to the agent; a single writer
// goroutine per connection drains it. All other fields are guarded by the
// owning Registry: readers must use List (copies), never held pointers.
type Session struct {
	SID         string
	Peer        string
	Transport   string
	Agent       protocol.AgentInfo
	State       State
	ConnectedAt time.Time
	LastSeen    time.Time

	Outbound chan *protocol.Envelope
}

// ErrNotFound reports an unknown session id.
var ErrNotFound = errors.New("session not found")

// ErrDuplicate reports a session id that already exists.
var ErrDuplicate = errors.New("duplicate session id")

// Registry is the concurrency-safe sid → Session map.
type Registry struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{sessions: make(map[string]*Session)}
}

// Add stores a new session; duplicate ids are rejected.
func (r *Registry) Add(s *Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.sessions[s.SID]; ok {
		return ErrDuplicate
	}
	r.sessions[s.SID] = s
	return nil
}

// Get returns the live session by id. Callers may use the returned pointer
// only to feed Outbound; field reads must go through List.
func (r *Registry) Get(sid string) (*Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[sid]
	if !ok {
		return nil, ErrNotFound
	}
	return s, nil
}

// List returns copies of live sessions, oldest connection first.
func (r *Registry) List() []Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ConnectedAt.Before(out[j].ConnectedAt) })
	return out
}

// Touch updates last-seen time and (optionally) the state of a session.
func (r *Registry) Touch(sid string, st State) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[sid]; ok {
		s.LastSeen = time.Now().UTC()
		if st != "" {
			s.State = st
		}
	}
}

// Remove drops a session from the registry.
func (r *Registry) Remove(sid string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, sid)
}

// Len returns the number of live sessions.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}
