package server_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"reverseshell/internal/agent"
	"reverseshell/internal/api"
	"reverseshell/internal/protocol"
	"reverseshell/internal/server"
	"reverseshell/internal/session"
	"reverseshell/internal/testutil"
)

func f3StackConfig(authToken string) server.Config {
	return server.Config{
		TransportName:   "tcp",
		MaxFrameBytes:   protocol.DefaultMaxFrameBytes,
		StaleMultiplier: 3,
		AuthToken:       authToken,
		SessionCfg: protocol.SessionConfig{
			HeartbeatInterval: 15,
			HeartbeatJitter:   0.2,
			MaxFrameBytes:     protocol.DefaultMaxFrameBytes,
		},
	}
}

// TestImplantAuthRejectsBadToken: with the implant HMAC enabled, an agent
// with the wrong token gets AUTH_FAILED, no session, and an audit line.
func TestImplantAuthRejectsBadToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	srv, ts, auditPath := startStack(t, ctx, f3StackConfig("implant-secret"))

	nonce, err := session.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	cfg := testAgentConfig(srv.ListenAddr(), nonce)
	cfg.AuthToken = "wrong-token"

	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Run(ctx, cfg) }()

	select {
	case err := <-agentDone:
		if err == nil || !strings.Contains(err.Error(), protocol.ErrCodeAuthFailed) {
			t.Fatalf("err = %v, want AUTH_FAILED", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not stop on rejection")
	}

	var list []api.SessionView
	getJSON(t, ctx, ts.URL+"/v1/sessions", "e2e-token", &list)
	if len(list) != 0 {
		t.Fatalf("rejected agent left %d session(s)", len(list))
	}

	audit, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), "session.auth.failed") {
		t.Fatalf("audit log missing session.auth.failed:\n%s", audit)
	}
}

// TestImplantAuthAcceptsGoodToken: the same stack accepts an agent holding
// the right token and a shell task round-trips.
func TestImplantAuthAcceptsGoodToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	srv, ts, _ := startStack(t, ctx, f3StackConfig("implant-secret"))

	nonce, err := session.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	cfg := testAgentConfig(srv.ListenAddr(), nonce)
	cfg.AuthToken = "implant-secret"

	go func() { _ = agent.Run(ctx, cfg) }()
	sid := waitForSession(t, ctx, ts.URL)

	args, _ := json.Marshal(protocol.ShellArgs{Cmd: "echo rs-auth-ok"})
	var created struct {
		TID string `json:"tid"`
	}
	postJSON(t, ctx, ts.URL+"/v1/sessions/"+sid+"/tasks", "e2e-token",
		protocol.TaskSpec{Kind: protocol.KindShell, Args: args, Timeout: 10}, &created)
	view := waitForTaskDone(t, ctx, ts.URL, created.TID)
	if view.Result == nil || view.Result.Status != protocol.StatusOK ||
		!strings.Contains(view.Result.Stdout, "rs-auth-ok") {
		t.Fatalf("result = %+v", view.Result)
	}
}

// TestEndToEndOverTLS: the whole F3 stack — TLS session plane + implant
// HMAC — carries a shell task round-trip.
func TestEndToEndOverTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	certPath, keyPath := testutil.WriteTLSCert(t)
	cfg := f3StackConfig("implant-secret")
	cfg.TransportName = "tls"
	cfg.TLSCertFile = certPath
	cfg.TLSKeyFile = keyPath
	srv, ts, _ := startStack(t, ctx, cfg)

	nonce, err := session.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	acfg := testAgentConfig(srv.ListenAddr(), nonce)
	acfg.TransportName = "tls"
	acfg.AuthToken = "implant-secret"
	acfg.TLSCA = certPath // self-signed cert acts as its own CA (SAN 127.0.0.1)

	go func() { _ = agent.Run(ctx, acfg) }()
	sid := waitForSession(t, ctx, ts.URL)

	args, _ := json.Marshal(protocol.ShellArgs{Cmd: "echo rs-tls-ok"})
	var created struct {
		TID string `json:"tid"`
	}
	postJSON(t, ctx, ts.URL+"/v1/sessions/"+sid+"/tasks", "e2e-token",
		protocol.TaskSpec{Kind: protocol.KindShell, Args: args, Timeout: 10}, &created)
	view := waitForTaskDone(t, ctx, ts.URL, created.TID)
	if view.Result == nil || view.Result.Status != protocol.StatusOK ||
		!strings.Contains(view.Result.Stdout, "rs-tls-ok") {
		t.Fatalf("result = %+v", view.Result)
	}
}
