package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"reverseshell/internal/protocol"
	"reverseshell/internal/session"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestCreateTaskQueuesEnvelope(t *testing.T) {
	reg := session.NewRegistry()
	d := NewDispatcher(reg, discardLogger(), NewEventBus(), nil, nil)
	sess := &session.Session{SID: "s1", Outbound: make(chan *protocol.Envelope, 1)}
	if err := reg.Add(sess); err != nil {
		t.Fatal(err)
	}
	spec := protocol.TaskSpec{
		Kind:    protocol.KindShell,
		Args:    json.RawMessage(`{"cmd":"whoami"}`),
		Timeout: 5,
	}
	tid, err := d.CreateTask(context.Background(), "s1", spec, "tester")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if tid == "" {
		t.Fatal("empty tid")
	}
	select {
	case env := <-sess.Outbound:
		if env.Type != protocol.TypeTask || env.SID != "s1" || env.TID != tid {
			t.Fatalf("envelope = %+v", env)
		}
		var got protocol.TaskSpec
		if err := json.Unmarshal(env.Data, &got); err != nil || got.Kind != protocol.KindShell {
			t.Fatalf("spec = %+v (%v)", got, err)
		}
	case <-time.After(time.Second):
		t.Fatal("no envelope queued")
	}
}

func TestCreateTaskUnknownSession(t *testing.T) {
	d := NewDispatcher(session.NewRegistry(), discardLogger(), NewEventBus(), nil, nil)
	if _, err := d.CreateTask(context.Background(), "nope",
		protocol.TaskSpec{Kind: protocol.KindSysinfo}, "tester"); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestResumeRequeuesPendingTasks(t *testing.T) {
	reg := session.NewRegistry()
	d := NewDispatcher(reg, discardLogger(), NewEventBus(), nil, nil)

	// First incarnation of s1: the task stays queued and undelivered
	// because nothing drains the channel.
	s1 := &session.Session{SID: "s1", Outbound: make(chan *protocol.Envelope, 1)}
	if err := reg.Add(s1); err != nil {
		t.Fatal(err)
	}
	tid, err := d.CreateTask(context.Background(), "s1",
		protocol.TaskSpec{Kind: protocol.KindShell, Args: json.RawMessage(`{"cmd":"whoami"}`), Timeout: 5}, "tester")
	if err != nil {
		t.Fatal(err)
	}

	// The session drops and comes back with a fresh FIFO under the same sid.
	reg.Remove("s1")
	s2 := &session.Session{SID: "s1", Outbound: make(chan *protocol.Envelope, 4)}
	if err := reg.Add(s2); err != nil {
		t.Fatal(err)
	}

	if n := d.Resume(s2); n != 1 {
		t.Fatalf("requeued = %d, want 1", n)
	}
	select {
	case env := <-s2.Outbound:
		if env.Type != protocol.TypeTask || env.TID != tid || env.SID != "s1" {
			t.Fatalf("envelope = %+v", env)
		}
	case <-time.After(time.Second):
		t.Fatal("no task requeued onto the resumed session")
	}
}

func TestOnResultStoresAndEmits(t *testing.T) {
	reg := session.NewRegistry()
	ev := NewEventBus()
	events, cancel := ev.Subscribe()
	defer cancel()
	d := NewDispatcher(reg, discardLogger(), ev, nil, nil)

	sess := &session.Session{SID: "s1", Outbound: make(chan *protocol.Envelope, 1)}
	if err := reg.Add(sess); err != nil {
		t.Fatal(err)
	}
	tid, err := d.CreateTask(context.Background(), "s1",
		protocol.TaskSpec{Kind: protocol.KindSysinfo}, "tester")
	if err != nil {
		t.Fatal(err)
	}

	res := protocol.TaskResult{Status: protocol.StatusOK, Stdout: "x"}
	rd, _ := json.Marshal(res)
	env := protocol.NewEnvelope(protocol.TypeResult)
	env.SID = "s1"
	env.TID = tid
	env.Data = rd
	d.OnResult(env)

	view, ok := d.Task(tid)
	if !ok || view.Status != taskDone || view.Result == nil || view.Result.Stdout != "x" {
		t.Fatalf("view = %+v ok=%v", view, ok)
	}
	select {
	case e := <-events:
		if e.Type != "task.result" {
			t.Fatalf("event type = %q", e.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("no SSE event emitted")
	}
}

func TestOnResultAssemblesChunkedDownload(t *testing.T) {
	reg := session.NewRegistry()
	ev := NewEventBus()
	events, cancel := ev.Subscribe()
	defer cancel()
	d := NewDispatcher(reg, discardLogger(), ev, nil, nil)

	sess := &session.Session{SID: "s1", Outbound: make(chan *protocol.Envelope, 1)}
	if err := reg.Add(sess); err != nil {
		t.Fatal(err)
	}
	tid, err := d.CreateTask(context.Background(), "s1",
		protocol.TaskSpec{Kind: protocol.KindDownload, Args: json.RawMessage(`{"path":"/lab/flag.txt"}`), Timeout: 30},
		"tester")
	if err != nil {
		t.Fatal(err)
	}

	sendChunk := func(i int, data, sha string, final bool) {
		res := protocol.TaskResult{
			Status: protocol.StatusOK,
			Data:   base64.StdEncoding.EncodeToString([]byte(data)),
			Chunk:  &protocol.ChunkMeta{Index: i, Total: 3, SHA256: sha, Final: final},
		}
		rd, _ := json.Marshal(res)
		env := protocol.NewEnvelope(protocol.TypeResult)
		env.SID = "s1"
		env.TID = tid
		env.Data = rd
		d.OnResult(env)
	}

	sendChunk(0, "aaa", "", false)
	sendChunk(1, "bbb", "", false)
	sendChunk(1, "dup", "", false) // bad index: dropped, assembly unaffected
	view, ok := d.Task(tid)
	if !ok || view.Status != taskQueued {
		t.Fatalf("mid-transfer status = %+v", view)
	}
	select {
	case <-events:
		t.Fatal("intermediate chunk must not emit SSE")
	default:
	}
	sendChunk(2, "ccc", "deadbeef", true)

	view, ok = d.Task(tid)
	if !ok || view.Status != taskDone {
		t.Fatalf("view = %+v ok=%v", view, ok)
	}
	data, sha, ok := d.TaskData(tid)
	if !ok || string(data) != "aaabbbccc" || sha != "deadbeef" {
		t.Fatalf("data = %q sha = %q ok=%v", data, sha, ok)
	}
	select {
	case <-events:
	default:
		t.Fatal("final chunk must emit SSE")
	}
}

func TestTaskStoreReloadAndRequeue(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "tasks.jsonl")

	// First incarnation: a queued, undelivered task gets persisted.
	reg := session.NewRegistry()
	if err := reg.Add(&session.Session{SID: "s1", Outbound: make(chan *protocol.Envelope, 1)}); err != nil {
		t.Fatal(err)
	}
	st, err := openStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	d1 := NewDispatcher(reg, discardLogger(), NewEventBus(), st, nil)
	tid, err := d1.CreateTask(context.Background(), "s1",
		protocol.TaskSpec{Kind: protocol.KindShell, Args: json.RawMessage(`{"cmd":"whoami"}`), Timeout: 5}, "tester")
	if err != nil {
		t.Fatal(err)
	}
	// Session resume records share the same store.
	if err := st.appendLine(storeLine{Type: "session", SID: "s1", Nonce: "nonce-1"}); err != nil {
		t.Fatal(err)
	}
	if err := st.close(); err != nil {
		t.Fatal(err)
	}

	// After a restart the store reloads both the queued task and the
	// nonce→sid map; the resumed session re-delivers it.
	sessions, stored, err := loadStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if sessions["nonce-1"] != "s1" {
		t.Fatalf("sessions = %v", sessions)
	}
	reg2 := session.NewRegistry()
	s2 := &session.Session{SID: "s1", Outbound: make(chan *protocol.Envelope, 4)}
	if err := reg2.Add(s2); err != nil {
		t.Fatal(err)
	}
	d2 := NewDispatcher(reg2, discardLogger(), NewEventBus(), nil, stored)

	view, ok := d2.Task(tid)
	if !ok || view.Status != taskQueued {
		t.Fatalf("reloaded view = %+v ok=%v", view, ok)
	}
	if n := d2.Resume(s2); n != 1 {
		t.Fatalf("requeued = %d, want 1", n)
	}
	select {
	case env := <-s2.Outbound:
		if env.TID != tid || env.Type != protocol.TypeTask {
			t.Fatalf("env = %+v", env)
		}
	case <-time.After(time.Second):
		t.Fatal("stored task was not requeued after reload")
	}
}
