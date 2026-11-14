package server_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"reverseshell/internal/agent"
	"reverseshell/internal/protocol"
	"reverseshell/internal/relay"
	"reverseshell/internal/server"
	"reverseshell/internal/session"
	"reverseshell/internal/testutil"
	"reverseshell/internal/transport"
)

// TestEndToEndOverHTTP: the agent beacons over HTTP polling through the
// full stack (README §8.2).
func TestEndToEndOverHTTP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	srv, ts, _ := startStack(t, ctx, server.Config{
		TransportName:   "http",
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
	acfg := testAgentConfig(srv.ListenAddr(), nonce)
	acfg.TransportName = "http"

	go func() { _ = agent.Run(ctx, acfg) }()
	sid := waitForSession(t, ctx, ts.URL)

	args, _ := json.Marshal(protocol.ShellArgs{Cmd: "echo rs-http-ok"})
	var created struct {
		TID string `json:"tid"`
	}
	postJSON(t, ctx, ts.URL+"/v1/sessions/"+sid+"/tasks", "e2e-token",
		protocol.TaskSpec{Kind: protocol.KindShell, Args: args, Timeout: 10}, &created)
	view := waitForTaskDone(t, ctx, ts.URL, created.TID)
	if view.Result == nil || view.Result.Status != protocol.StatusOK ||
		!strings.Contains(view.Result.Stdout, "rs-http-ok") {
		t.Fatalf("result = %+v", view.Result)
	}
}

// TestRemoteListenerFeedsTeamserver: the F4 acceptance criterion — a
// standalone listener terminates implant connections and feeds the central
// teamserver over the relay plane (README §6.2).
func TestRemoteListenerFeedsTeamserver(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	certPath, keyPath := testutil.WriteTLSCert(t)
	srv, ts, auditPath := startStack(t, ctx, server.Config{
		TransportName:   "tcp",
		MaxFrameBytes:   protocol.DefaultMaxFrameBytes,
		StaleMultiplier: 3,
		SessionCfg: protocol.SessionConfig{
			HeartbeatInterval: 15,
			HeartbeatJitter:   0.2,
			MaxFrameBytes:     protocol.DefaultMaxFrameBytes,
		},
		RelayAddr:     "127.0.0.1:0",
		RelayToken:    "relay-secret",
		RelayCertFile: certPath,
		RelayKeyFile:  keyPath,
	})

	// The standalone listener: a session listener plus the relay uplink.
	client, err := relay.Dial(ctx, relay.ClientConfig{
		Addr:   srv.RelayAddr(),
		Token:  "relay-secret",
		Name:   "lab-listener-1",
		CAFile: certPath,
	})
	if err != nil {
		t.Fatalf("relay dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	sl, err := (transport.TCP{}).Listen(ctx, "127.0.0.1:0", transport.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sl.Close() })
	go func() {
		for {
			conn, err := sl.Accept(ctx)
			if err != nil {
				return
			}
			go func() { _ = client.Forward(ctx, conn) }()
		}
	}()

	// The agent connects to the REMOTE listener, not to the teamserver.
	nonce, err := session.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	acfg := testAgentConfig(sl.Addr().String(), nonce)
	go func() { _ = agent.Run(ctx, acfg) }()

	sid := waitForSession(t, ctx, ts.URL)
	args, _ := json.Marshal(protocol.ShellArgs{Cmd: "echo rs-relay-ok"})
	var created struct {
		TID string `json:"tid"`
	}
	postJSON(t, ctx, ts.URL+"/v1/sessions/"+sid+"/tasks", "e2e-token",
		protocol.TaskSpec{Kind: protocol.KindShell, Args: args, Timeout: 10}, &created)
	view := waitForTaskDone(t, ctx, ts.URL, created.TID)
	if view.Result == nil || view.Result.Status != protocol.StatusOK ||
		!strings.Contains(view.Result.Stdout, "rs-relay-ok") {
		t.Fatalf("result = %+v", view.Result)
	}

	audit, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"relay.start", "listener.remote.up", "session.register"} {
		if !strings.Contains(string(audit), want) {
			t.Fatalf("audit missing %q:\n%s", want, audit)
		}
	}
}
