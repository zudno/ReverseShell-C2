package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"reverseshell/internal/protocol"
)

type fakeBackend struct {
	sessions []SessionView
	tasks    map[string]TaskView
	events   chan Event
}

func (b *fakeBackend) Sessions() []SessionView { return b.sessions }

func (b *fakeBackend) CreateTask(_ context.Context, sid string, _ protocol.TaskSpec) (string, error) {
	if sid == "missing" {
		return "", ErrUnknownSession
	}
	return "t-1", nil
}

func (b *fakeBackend) Task(tid string) (TaskView, bool) {
	v, ok := b.tasks[tid]
	return v, ok
}

func (b *fakeBackend) SubscribeEvents() (<-chan Event, func()) {
	return b.events, func() {}
}

func (b *fakeBackend) Shutdown(context.Context) error { return nil }

func newTestServer(t *testing.T, b Backend) *httptest.Server {
	t.Helper()
	s, err := New(Config{Addr: "127.0.0.1:0", Token: "secret", Backend: b})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestAuthRequired(t *testing.T) {
	ts := newTestServer(t, &fakeBackend{events: make(chan Event, 1)})
	for _, tc := range []struct {
		auth string
		code int
	}{
		{"", http.StatusUnauthorized},
		{"Bearer wrong", http.StatusUnauthorized},
		{"Bearer secret", http.StatusOK},
	} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/sessions", nil)
		if tc.auth != "" {
			req.Header.Set("Authorization", tc.auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.code {
			t.Fatalf("auth %q = %d, want %d", tc.auth, resp.StatusCode, tc.code)
		}
	}
}

func TestSessionsList(t *testing.T) {
	b := &fakeBackend{
		sessions: []SessionView{{SID: "abc", OS: "windows", State: "ready"}},
		events:   make(chan Event, 1),
	}
	ts := newTestServer(t, b)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var list []SessionView
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].SID != "abc" || list[0].OS != "windows" {
		t.Fatalf("list = %+v", list)
	}
}

func TestCreateTaskValidation(t *testing.T) {
	ts := newTestServer(t, &fakeBackend{events: make(chan Event, 1)})
	cases := []struct {
		name string
		body string
		code int
	}{
		{"bad json", "{", http.StatusBadRequest},
		{"unknown kind", `{"kind":"ftp"}`, http.StatusBadRequest},
		{"shell without cmd", `{"kind":"shell"}`, http.StatusBadRequest},
		{"shell empty cmd", `{"kind":"shell","args":{"cmd":""}}`, http.StatusBadRequest},
		{"shell ok", `{"kind":"shell","args":{"cmd":"whoami"}}`, http.StatusAccepted},
		{"sysinfo ok", `{"kind":"sysinfo"}`, http.StatusAccepted},
		{"exit ok", `{"kind":"exit"}`, http.StatusAccepted},
		{"negative timeout", `{"kind":"sysinfo","timeout":-1}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/sessions/sid/tasks", strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.code {
			t.Fatalf("%s: got %d, want %d", tc.name, resp.StatusCode, tc.code)
		}
	}
}

func TestCreateTaskUnknownSessionIs404(t *testing.T) {
	ts := newTestServer(t, &fakeBackend{events: make(chan Event, 1)})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/sessions/missing/tasks",
		strings.NewReader(`{"kind":"sysinfo"}`))
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got %d, want 404", resp.StatusCode)
	}
}

func TestTaskEndpoint(t *testing.T) {
	b := &fakeBackend{
		tasks:  map[string]TaskView{"t-1": {TID: "t-1", Status: "done"}},
		events: make(chan Event, 1),
	}
	ts := newTestServer(t, b)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/tasks/t-1", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var view TaskView
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	if view.TID != "t-1" || view.Status != "done" {
		t.Fatalf("view = %+v", view)
	}

	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/tasks/nope", nil)
	req2.Header.Set("Authorization", "Bearer secret")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("missing task: got %d, want 404", resp2.StatusCode)
	}
}

func TestEventsStream(t *testing.T) {
	b := &fakeBackend{events: make(chan Event, 4)}
	ts := newTestServer(t, b)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/v1/events", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("events status = %d", resp.StatusCode)
	}

	rd := bufio.NewReader(resp.Body)
	line, err := rd.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, ":") {
		t.Fatalf("hello line = %q (%v)", line, err)
	}
	// Consume the blank line that terminates the SSE comment block.
	if _, err := rd.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	b.events <- Event{Type: "session.register", Data: json.RawMessage(`{"sid":"abc"}`)}
	line, err = rd.ReadString('\n')
	if err != nil || !strings.Contains(line, "event: session.register") {
		t.Fatalf("event line = %q (%v)", line, err)
	}
	line, err = rd.ReadString('\n')
	if err != nil || !strings.Contains(line, `"sid":"abc"`) {
		t.Fatalf("data line = %q (%v)", line, err)
	}
}
