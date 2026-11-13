package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"reverseshell/internal/agent"
	"reverseshell/internal/api"
	"reverseshell/internal/protocol"
	"reverseshell/internal/server"
	"reverseshell/internal/session"
)

// TestEndToEndLoopback drives the full F1 stack in-process: agent → embedded
// listener → dispatcher → operator API, all on 127.0.0.1 with ephemeral
// ports. Roadmap F1 criteria: a shell command round-trips from the API, and
// the audit trail reproduces the session (README §9.3).
func TestEndToEndLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	srv, err := server.New(server.Config{
		TransportName: "tcp",
		ListenerAddr:  "127.0.0.1:0",
		MaxFrameBytes: protocol.DefaultMaxFrameBytes,
		AuditLogPath:  auditPath,
		SessionCfg: protocol.SessionConfig{
			HeartbeatInterval: 15,
			HeartbeatJitter:   0.2,
			MaxFrameBytes:     protocol.DefaultMaxFrameBytes,
		},
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	apiSrv, err := api.New(api.Config{
		Addr:    "127.0.0.1:0",
		Token:   "e2e-token",
		Backend: srv,
		Audit:   srv.Audit(),
	})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	t.Cleanup(func() { _ = apiSrv.Close() })
	ts := httptest.NewServer(apiSrv.Handler())
	t.Cleanup(ts.Close)

	go func() { _ = srv.Run(ctx) }()

	nonce, err := session.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	hostname, _ := os.Hostname()
	u, err := user.Current()
	if err != nil {
		u = &user.User{}
	}
	go func() {
		_ = agent.Run(ctx, agent.Config{
			Addr:          srv.ListenAddr(),
			TransportName: "tcp",
			MaxFrameBytes: protocol.DefaultMaxFrameBytes,
			Info: protocol.AgentInfo{
				Hostname:      hostname,
				OS:            runtime.GOOS,
				Arch:          runtime.GOARCH,
				User:          u.Username,
				PID:           os.Getpid(),
				ClientVersion: agent.Version,
				Nonce:         nonce,
			},
		})
	}()

	sid := waitForSession(t, ctx, ts.URL)
	t.Logf("session up: %s", sid)

	args, _ := json.Marshal(protocol.ShellArgs{Cmd: "echo rs-e2e-ok"})
	var created struct {
		TID string `json:"tid"`
	}
	postJSON(t, ctx, ts.URL+"/v1/sessions/"+sid+"/tasks", "e2e-token",
		protocol.TaskSpec{Kind: protocol.KindShell, Args: args, Timeout: 10}, &created)
	if created.TID == "" {
		t.Fatal("no tid returned")
	}

	view := waitForTaskDone(t, ctx, ts.URL, created.TID)
	if view.Result == nil || view.Result.Status != protocol.StatusOK {
		t.Fatalf("result = %+v", view.Result)
	}
	if !strings.Contains(view.Result.Stdout, "rs-e2e-ok") {
		t.Fatalf("stdout = %q", view.Result.Stdout)
	}

	audit, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	for _, want := range []string{"listener.start", "session.register", "operator.task", "session.result"} {
		if !strings.Contains(string(audit), want) {
			t.Fatalf("audit log missing %q:\n%s", want, audit)
		}
	}
}

func getJSON(t *testing.T, ctx context.Context, url, token string, out any) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

func postJSON(t *testing.T, ctx context.Context, url, token string, body, out any) {
	t.Helper()
	rd, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(rd)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST %s = %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

func waitForSession(t *testing.T, ctx context.Context, baseURL string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var list []api.SessionView
		getJSON(t, ctx, baseURL+"/v1/sessions", "e2e-token", &list)
		if len(list) > 0 {
			return list[0].SID
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("no session appeared within deadline")
	return ""
}

func waitForTaskDone(t *testing.T, ctx context.Context, baseURL, tid string) api.TaskView {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var view api.TaskView
		getJSON(t, ctx, baseURL+"/v1/tasks/"+tid, "e2e-token", &view)
		if view.Status == "done" {
			return view
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("task did not finish within deadline")
	return api.TaskView{}
}
