package session

import (
	"errors"
	"testing"
	"time"

	"reverseshell/internal/protocol"
)

func newTestSession(sid string) *Session {
	return &Session{
		SID:      sid,
		Outbound: make(chan *protocol.Envelope, 4),
		Agent:    protocol.AgentInfo{Hostname: "lab-01", OS: "windows", User: "labuser"},
		State:    StateRegistered,
	}
}

func TestRegistryAddGetRemove(t *testing.T) {
	r := NewRegistry()
	s := newTestSession("s1")
	if err := r.Add(s); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := r.Add(newTestSession("s1")); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate add err = %v", err)
	}
	got, err := r.Get("s1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.SID != "s1" {
		t.Fatalf("got sid %q", got.SID)
	}
	r.Remove("s1")
	if r.Len() != 0 {
		t.Fatalf("len = %d, want 0", r.Len())
	}
	if _, err := r.Get("s1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get missing err = %v", err)
	}
}

func TestRegistryTouchUpdatesState(t *testing.T) {
	r := NewRegistry()
	if err := r.Add(newTestSession("s1")); err != nil {
		t.Fatal(err)
	}
	r.Touch("s1", StateTasked)
	list := r.List()
	if len(list) != 1 {
		t.Fatalf("len = %d", len(list))
	}
	if list[0].State != StateTasked {
		t.Fatalf("state = %q, want tasked", list[0].State)
	}
	if list[0].LastSeen.IsZero() {
		t.Fatal("LastSeen not updated")
	}
}

func TestRegistryListOrdersByConnectionTime(t *testing.T) {
	r := NewRegistry()
	older := newTestSession("older")
	older.ConnectedAt = time.Now().Add(-2 * time.Hour).UTC()
	newer := newTestSession("newer")
	newer.ConnectedAt = time.Now().UTC()
	if err := r.Add(newer); err != nil {
		t.Fatal(err)
	}
	if err := r.Add(older); err != nil {
		t.Fatal(err)
	}
	list := r.List()
	if len(list) != 2 {
		t.Fatalf("len = %d", len(list))
	}
	if list[0].SID != "older" || list[1].SID != "newer" {
		t.Fatalf("order = %s, %s", list[0].SID, list[1].SID)
	}
}
