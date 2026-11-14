package server_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
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
	"reverseshell/internal/transport"
)

// startStack brings up a teamserver (embedded listener) plus its operator
// API on ephemeral loopback ports with the shared test token. It returns
// the server, the httptest endpoint, and the audit log path.
func startStack(t *testing.T, ctx context.Context, cfg server.Config) (*server.Server, *httptest.Server, string) {
	srv, ts, auditPath, _ := startStackDone(t, ctx, cfg)
	return srv, ts, auditPath
}

// startStackDone additionally returns the server Run's done channel and
// respects a preset ListenerAddr (the F5 restart test reuses the port).
func startStackDone(t *testing.T, ctx context.Context, cfg server.Config) (*server.Server, *httptest.Server, string, <-chan error) {
	t.Helper()
	if cfg.ListenerAddr == "" {
		cfg.ListenerAddr = "127.0.0.1:0"
	}
	if cfg.TransportName == "" {
		cfg.TransportName = "tcp"
	}
	cfg.AuditLogPath = filepath.Join(t.TempDir(), "audit.jsonl")
	srv, err := server.New(cfg)
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
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	return srv, ts, cfg.AuditLogPath, done
}

func testAgentConfig(addr, nonce string) agent.Config {
	return agent.Config{
		Addr:          addr,
		TransportName: "tcp",
		MaxFrameBytes: protocol.DefaultMaxFrameBytes,
		ReconnectBase: 50 * time.Millisecond,
		ReconnectCap:  2 * time.Second,
		Info: protocol.AgentInfo{
			Hostname:      "f2-test",
			OS:            runtime.GOOS,
			Arch:          runtime.GOARCH,
			User:          "testuser",
			PID:           os.Getpid(),
			ClientVersion: agent.Version,
			Nonce:         nonce,
		},
	}
}

// waitNoSessions polls until the session list is empty.
func waitNoSessions(t *testing.T, ctx context.Context, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var list []api.SessionView
		getJSON(t, ctx, baseURL+"/v1/sessions", "e2e-token", &list)
		if len(list) == 0 {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatal("session still listed after drop")
}

// TestSessionResumeByNonce: kill the agent, relaunch it with the same nonce,
// and the session must come back under the same sid (README §4.7, F2
// criterion: "matar el agent y verlo retomar la misma sesión").
func TestSessionResumeByNonce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	srv, ts, auditPath := startStack(t, ctx, server.Config{
		TransportName:   "tcp",
		MaxFrameBytes:   protocol.DefaultMaxFrameBytes,
		StaleMultiplier: 3,
		SessionCfg: protocol.SessionConfig{
			HeartbeatInterval: 15,
			HeartbeatJitter:   0.2,
			MaxFrameBytes:     protocol.DefaultMaxFrameBytes,
		},
	})

	nonce, err := session.NewNonce()
	if err != nil {
		t.Fatal(err)
	}

	// First run: register, then cut the agent off mid-session.
	actx, acancel := context.WithCancel(ctx)
	go func() { _ = agent.Run(actx, testAgentConfig(srv.ListenAddr(), nonce)) }()
	sid := waitForSession(t, ctx, ts.URL)
	acancel()
	waitNoSessions(t, ctx, ts.URL)

	// Second run, same nonce: the session must resume under the same sid.
	go func() { _ = agent.Run(ctx, testAgentConfig(srv.ListenAddr(), nonce)) }()
	sid2 := waitForSession(t, ctx, ts.URL)
	if sid2 != sid {
		t.Fatalf("resume minted a new sid: %q != %q", sid2, sid)
	}

	audit, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), "session.resume") {
		t.Fatalf("audit log missing session.resume:\n%s", audit)
	}
}

// TestStaleReaperSweepsSilentSessions: a registered "agent" that never
// heartbeats must be swept after stale_multiplier × heartbeat_interval.
func TestStaleReaperSweepsSilentSessions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	srv, ts, auditPath := startStack(t, ctx, server.Config{
		TransportName:   "tcp",
		MaxFrameBytes:   protocol.DefaultMaxFrameBytes,
		StaleMultiplier: 3, // stale after 3 × 0.3s = 0.9s
		SessionCfg: protocol.SessionConfig{
			HeartbeatInterval: 0.3,
			HeartbeatJitter:   0,
			MaxFrameBytes:     protocol.DefaultMaxFrameBytes,
		},
	})

	// A silent client: raw REGISTER over the session plane, then nothing.
	conn, err := transport.TCP{}.Dial(ctx, srv.ListenAddr(), transport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	info, _ := json.Marshal(protocol.AgentInfo{
		Hostname: "silent-agent", OS: runtime.GOOS, Nonce: "stale-test-nonce-1",
	})
	reg := protocol.NewEnvelope(protocol.TypeRegister)
	reg.Data = info
	if err := sendRaw(t, ctx, conn, reg); err != nil {
		t.Fatal(err)
	}
	frame, err := conn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	env, err := protocol.Decode(frame)
	if err != nil || env.Type != protocol.TypeRegistered || env.SID == "" {
		t.Fatalf("handshake envelope = %+v (%v)", env, err)
	}
	sid := env.SID

	// The session appears, then goes silent past the threshold and is swept.
	if got := waitForSession(t, ctx, ts.URL); got != sid {
		t.Fatalf("session sid = %q, want %q", got, sid)
	}
	waitNoSessions(t, ctx, ts.URL)

	audit, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), "session.stale") {
		t.Fatalf("audit log missing session.stale:\n%s", audit)
	}
}

// TestAgentExitTaskStopsBeacon: the exit task must produce a final ok
// result and stop the beacon cleanly (no reconnect — proven by a large
// reconnect base and a short test deadline).
func TestAgentExitTaskStopsBeacon(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	srv, ts, _ := startStack(t, ctx, server.Config{
		TransportName:   "tcp",
		MaxFrameBytes:   protocol.DefaultMaxFrameBytes,
		StaleMultiplier: 3,
		SessionCfg: protocol.SessionConfig{
			HeartbeatInterval: 15,
			HeartbeatJitter:   0.2,
			MaxFrameBytes:     protocol.DefaultMaxFrameBytes,
		},
	})

	nonce, err := session.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	cfg := testAgentConfig(srv.ListenAddr(), nonce)
	cfg.ReconnectBase = 30 * time.Second // any drop would blow the deadline

	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Run(ctx, cfg) }()

	sid := waitForSession(t, ctx, ts.URL)

	var created struct {
		TID string `json:"tid"`
	}
	postJSON(t, ctx, ts.URL+"/v1/sessions/"+sid+"/tasks", "e2e-token",
		protocol.TaskSpec{Kind: protocol.KindExit, Timeout: 5}, &created)
	if created.TID == "" {
		t.Fatal("no tid returned")
	}

	select {
	case err := <-agentDone:
		if err != nil {
			t.Fatalf("agent returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not stop on the exit task")
	}

	view := waitForTaskDone(t, ctx, ts.URL, created.TID)
	if view.Result == nil || view.Result.Status != protocol.StatusOK {
		t.Fatalf("exit result = %+v", view.Result)
	}
}

func sendRaw(t *testing.T, ctx context.Context, conn transport.Conn, env *protocol.Envelope) error {
	t.Helper()
	b, err := protocol.Encode(env)
	if err != nil {
		return err
	}
	return conn.Send(ctx, b)
}
