package api

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"reverseshell/internal/protocol"
	"reverseshell/internal/testutil"
)

type fakeBackend struct {
	sessions   []SessionView
	tasks      map[string]TaskView
	events     chan Event
	lastOp     string
	uploadView UploadView
	uploadData map[string][]byte // tid → payload
}

func (b *fakeBackend) Sessions() []SessionView { return b.sessions }

func (b *fakeBackend) CreateTask(_ context.Context, sid string, _ protocol.TaskSpec, operator string) (string, error) {
	b.lastOp = operator
	if sid == "missing" {
		return "", ErrUnknownSession
	}
	return "t-1", nil
}

func (b *fakeBackend) CreateUpload(_ context.Context, sid, _ string, data []byte, operator string) (UploadView, error) {
	b.lastOp = operator
	if sid == "missing" {
		return UploadView{}, ErrUnknownSession
	}
	sum := sha256.Sum256(data)
	b.uploadView = UploadView{FinalTID: "t-up", Chunks: 1, Bytes: len(data),
		SHA256: hex.EncodeToString(sum[:])}
	return b.uploadView, nil
}

func (b *fakeBackend) Task(tid string) (TaskView, bool) {
	v, ok := b.tasks[tid]
	return v, ok
}

func (b *fakeBackend) TaskData(tid string) ([]byte, string, bool) {
	data, ok := b.uploadData[tid]
	if !ok {
		return nil, "", false
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), true
}

func (b *fakeBackend) SubscribeEvents() (<-chan Event, func()) {
	return b.events, func() {}
}

func (b *fakeBackend) Shutdown(context.Context) error { return nil }

// TestNonLoopbackRequiresTLS: exposing the operator API off-loopback without
// TLS is a hard startup error (README §9.2).
func TestNonLoopbackRequiresTLS(t *testing.T) {
	_, err := New(Config{
		Addr:    "0.0.0.0:5555",
		Token:   "secret",
		Backend: &fakeBackend{events: make(chan Event, 1)},
	})
	if err == nil {
		t.Fatal("expected error for non-loopback bind without TLS")
	}
}

// TestAPIServesTLS proves the control plane serves real TLS when configured.
func TestAPIServesTLS(t *testing.T) {
	certPath, keyPath := testutil.WriteTLSCert(t)
	s, err := New(Config{
		Addr:        "127.0.0.1:0",
		Token:       "secret",
		Backend:     &fakeBackend{events: make(chan Event, 1)},
		TLSCertFile: certPath,
		TLSKeyFile:  keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx) }()

	pool := x509.NewCertPool()
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("bad cert PEM")
	}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
	req, _ := http.NewRequest(http.MethodGet, "https://"+s.Addr()+"/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("https request: %v", err)
	}
	defer resp.Body.Close()
	if resp.TLS == nil {
		t.Fatal("connection is not TLS")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// TestOperatorHeaderThreadsIdentity: X-RS-Operator reaches the backend for
// audit attribution (multi-operator accountability, F5).
func TestOperatorHeaderThreadsIdentity(t *testing.T) {
	b := &fakeBackend{events: make(chan Event, 1)}
	ts := newTestServer(t, b)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/sessions/sid/tasks",
		strings.NewReader(`{"kind":"sysinfo"}`))
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("X-RS-Operator", "alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if b.lastOp != "alice" {
		t.Fatalf("operator = %q, want alice", b.lastOp)
	}
}

func TestUploadEndpoint(t *testing.T) {
	b := &fakeBackend{events: make(chan Event, 1)}
	ts := newTestServer(t, b)

	// Missing path → 400.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/sessions/sid/upload", strings.NewReader("x"))
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing path = %d, want 400", resp.StatusCode)
	}

	// Happy path → 202 with the upload view.
	payload := []byte("file-content")
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/v1/sessions/sid/upload?path=/tmp/blob",
		strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "Bearer secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("upload = %d, want 202", resp.StatusCode)
	}
	var view UploadView
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	if view.FinalTID != "t-up" || view.Bytes != len(payload) ||
		view.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("view = %+v", view)
	}
}

func TestTaskDownloadEndpoint(t *testing.T) {
	b := &fakeBackend{
		events:     make(chan Event, 1),
		uploadData: map[string][]byte{"t-dl": []byte("exfiltrated-bytes")},
	}
	ts := newTestServer(t, b)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/tasks/t-dl/download", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "exfiltrated-bytes" {
		t.Fatalf("body = %q", body)
	}
	if resp.Header.Get("X-RS-SHA256") == "" {
		t.Fatal("X-RS-SHA256 header missing")
	}

	// Unknown tid → 404.
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/v1/tasks/nope/download", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing download = %d, want 404", resp.StatusCode)
	}
}

// TestUIServedAndRedirected: the single-file web console is served at /ui
// and / redirects to it (README §5, F5).
func TestUIServedAndRedirected(t *testing.T) {
	ts := newTestServer(t, &fakeBackend{events: make(chan Event, 1)})

	resp, err := http.Get(ts.URL + "/ui")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/ui = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "operator console") {
		t.Fatalf("/ui does not look like the web console:\n%.200s", body)
	}

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err = noRedirect.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/ui" {
		t.Fatalf("/ = %d %q, want 302 /ui", resp.StatusCode, resp.Header.Get("Location"))
	}
}

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
		{"download without path", `{"kind":"download"}`, http.StatusBadRequest},
		{"download ok", `{"kind":"download","args":{"path":"/tmp/x"}}`, http.StatusAccepted},
		{"upload on tasks endpoint", `{"kind":"upload","args":{"path":"/x"}}`, http.StatusBadRequest},
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
