package server_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"reverseshell/internal/agent"
	"reverseshell/internal/api"
	"reverseshell/internal/protocol"
	"reverseshell/internal/server"
	"reverseshell/internal/session"
)

func f5StackConfig(storePath string) server.Config {
	return server.Config{
		TransportName:   "tcp",
		MaxFrameBytes:   protocol.DefaultMaxFrameBytes,
		StaleMultiplier: 3,
		TaskStorePath:   storePath,
		SessionCfg: protocol.SessionConfig{
			HeartbeatInterval: 15,
			HeartbeatJitter:   0.2,
			MaxFrameBytes:     protocol.DefaultMaxFrameBytes,
		},
	}
}

// rawRequest performs an authenticated raw HTTP request against the test
// stack (used by file transfers, which are not JSON bodies).
func rawRequest(t *testing.T, method, urlStr, operator string, body []byte) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, urlStr, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer e2e-token")
	req.Header.Set("X-RS-Operator", operator)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, protocol.MaxTransferBytes+1))
	if err != nil {
		t.Fatal(err)
	}
	return resp, b
}

// TestFileTransferRoundTrip pushes a multi-chunk file to the agent and
// pulls it back; both directions verified by sha256 (F5 criterion:
// "archivo íntegro verificado por hash").
func TestFileTransferRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	srv, ts, _ := startStack(t, ctx, f5StackConfig(""))

	nonce, err := session.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	acfg := testAgentConfig(srv.ListenAddr(), nonce)
	go func() { _ = agent.Run(ctx, acfg) }()
	sid := waitForSession(t, ctx, ts.URL)

	// 2.5 MiB deterministic blob → 3 chunks (1 MiB each).
	blob := make([]byte, protocol.TransferChunkBytes*2+11)
	for i := range blob {
		blob[i] = byte(i % 251)
	}
	sum := sha256.Sum256(blob)
	wantSHA := hex.EncodeToString(sum[:])
	remote := filepath.Join(t.TempDir(), "roundtrip.bin")

	// upload → the agent verifies the assembled hash before writing.
	resp, body := rawRequest(t, http.MethodPost,
		ts.URL+"/v1/sessions/"+sid+"/upload?path="+url.QueryEscape(remote), "e2e", blob)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("upload = %d: %s", resp.StatusCode, body)
	}
	var up api.UploadView
	if err := json.Unmarshal(body, &up); err != nil {
		t.Fatal(err)
	}
	if up.Chunks != 3 || up.SHA256 != wantSHA {
		t.Fatalf("upload view = %+v", up)
	}
	upDone := waitForTaskDone(t, ctx, ts.URL, up.FinalTID)
	if upDone.Result == nil || upDone.Result.Status != protocol.StatusOK ||
		!strings.Contains(upDone.Result.Detail, "sha256 verified") {
		t.Fatalf("upload result = %+v", upDone.Result)
	}

	// download back → the dispatcher assembles chunks; the API serves the
	// payload with its complete-file hash.
	args, _ := json.Marshal(protocol.DownloadArgs{Path: remote})
	var created struct {
		TID string `json:"tid"`
	}
	postJSON(t, ctx, ts.URL+"/v1/sessions/"+sid+"/tasks", "e2e-token",
		protocol.TaskSpec{Kind: protocol.KindDownload, Args: args, Timeout: 60}, &created)
	dlDone := waitForTaskDone(t, ctx, ts.URL, created.TID)
	if dlDone.Result == nil || dlDone.Result.Status != protocol.StatusOK {
		t.Fatalf("download result = %+v", dlDone.Result)
	}
	resp, body = rawRequest(t, http.MethodGet, ts.URL+"/v1/tasks/"+created.TID+"/download", "e2e", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download fetch = %d: %s", resp.StatusCode, body)
	}
	if !bytes.Equal(body, blob) {
		t.Fatalf("round trip altered the file: %d bytes back, want %d", len(body), len(blob))
	}
	if resp.Header.Get("X-RS-SHA256") != wantSHA {
		t.Fatalf("X-RS-SHA256 = %q, want %q", resp.Header.Get("X-RS-SHA256"), wantSHA)
	}
}

// TestTaskPersistenceAcrossRestart: the task queue and the nonce→sid resume
// map survive a teamserver restart; the reconnecting agent retakes the same
// session and its pending task completes (F5).
func TestTaskPersistenceAcrossRestart(t *testing.T) {
	actx, acancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer acancel()

	// Pre-allocate the session port so server B can bind the same address.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()

	storePath := filepath.Join(t.TempDir(), "tasks.jsonl")

	// Server A: the agent registers, a task is queued.
	ctxA, cancelA := context.WithTimeout(context.Background(), 30*time.Second)
	cfgA := f5StackConfig(storePath)
	cfgA.ListenerAddr = addr
	srvA, tsA, auditA, doneA := startStackDone(t, ctxA, cfgA)

	nonce, err := session.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	acfg := testAgentConfig(addr, nonce)
	go func() { _ = agent.Run(actx, acfg) }()
	sid := waitForSession(t, ctxA, tsA.URL)

	args, _ := json.Marshal(protocol.ShellArgs{Cmd: "echo rs-persist-ok"})
	var created struct {
		TID string `json:"tid"`
	}
	postJSON(t, ctxA, tsA.URL+"/v1/sessions/"+sid+"/tasks", "e2e-token",
		protocol.TaskSpec{Kind: protocol.KindShell, Args: args, Timeout: 10}, &created)

	// Restart: A dies (persisting queue + nonces); the agent keeps retrying
	// the same address with its backoff loop.
	cancelA()
	<-doneA
	_ = srvA
	_ = auditA

	ctxB, cancelB := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelB()
	cfgB := f5StackConfig(storePath)
	cfgB.ListenerAddr = addr
	_, tsB, _, _ := startStackDone(t, ctxB, cfgB)

	// The agent retakes the SAME session by nonce and the stored task
	// re-delivers (or already completed on A — either way it must be done).
	sid2 := waitForSession(t, ctxB, tsB.URL)
	if sid2 != sid {
		t.Fatalf("resume minted a new sid after restart: %q != %q", sid2, sid)
	}
	view := waitForTaskDone(t, ctxB, tsB.URL, created.TID)
	if view.Result == nil || !strings.Contains(view.Result.Stdout, "rs-persist-ok") {
		t.Fatalf("reloaded task result = %+v", view.Result)
	}
}

// TestTwoOperatorsConcurrent: two operators drive the same session at once;
// results do not interfere and the audit attributes each action (F5).
func TestTwoOperatorsConcurrent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	srv, ts, auditPath := startStack(t, ctx, f5StackConfig(""))

	nonce, err := session.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = agent.Run(ctx, testAgentConfig(srv.ListenAddr(), nonce)) }()
	sid := waitForSession(t, ctx, ts.URL)

	type opResult struct {
		name   string
		stdout string
		err    error
	}
	done := make(chan opResult, 2)
	var wg sync.WaitGroup
	for _, op := range []struct{ name, marker string }{
		{"alice", "rs-alice"}, {"bob", "rs-bob"},
	} {
		wg.Add(1)
		go func(name, marker string) {
			defer wg.Done()
			body := fmt.Sprintf(`{"kind":"shell","args":{"cmd":"echo %s"},"timeout":10}`, marker)
			resp, rbody := rawRequest(t, http.MethodPost,
				ts.URL+"/v1/sessions/"+sid+"/tasks", name, []byte(body))
			if resp.StatusCode != http.StatusAccepted {
				done <- opResult{name: name, err: fmt.Errorf("create = %d: %s", resp.StatusCode, rbody)}
				return
			}
			var created struct {
				TID string `json:"tid"`
			}
			if err := json.Unmarshal(rbody, &created); err != nil {
				done <- opResult{name: name, err: err}
				return
			}
			deadline := time.Now().Add(15 * time.Second)
			for time.Now().Before(deadline) {
				var view api.TaskView
				getJSON(t, ctx, ts.URL+"/v1/tasks/"+created.TID, "e2e-token", &view)
				if view.Status == "done" {
					stdout := ""
					if view.Result != nil {
						stdout = view.Result.Stdout
					}
					done <- opResult{name: name, stdout: stdout}
					return
				}
				select {
				case <-ctx.Done():
					done <- opResult{name: name, err: ctx.Err()}
					return
				case <-time.After(100 * time.Millisecond):
				}
			}
			done <- opResult{name: name, err: fmt.Errorf("task did not finish")}
		}(op.name, op.marker)
	}
	wg.Wait()
	close(done)

	results := map[string]opResult{}
	for r := range done {
		results[r.name] = r
	}
	for _, want := range []struct{ name, marker string }{
		{"alice", "rs-alice"}, {"bob", "rs-bob"},
	} {
		r, ok := results[want.name]
		if !ok || r.err != nil {
			t.Fatalf("operator %s failed: %+v", want.name, r)
		}
		if !strings.Contains(r.stdout, want.marker) {
			t.Fatalf("operator %s got %q (cross-talk?)", want.name, r.stdout)
		}
	}

	audit, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), `"operator":"alice"`) ||
		!strings.Contains(string(audit), `"operator":"bob"`) {
		t.Fatalf("audit does not attribute both operators:\n%s", audit)
	}
}
