package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
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
	d := NewDispatcher(reg, discardLogger(), NewEventBus())
	sess := &session.Session{SID: "s1", Outbound: make(chan *protocol.Envelope, 1)}
	if err := reg.Add(sess); err != nil {
		t.Fatal(err)
	}
	spec := protocol.TaskSpec{
		Kind:    protocol.KindShell,
		Args:    json.RawMessage(`{"cmd":"whoami"}`),
		Timeout: 5,
	}
	tid, err := d.CreateTask(context.Background(), "s1", spec)
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
	d := NewDispatcher(session.NewRegistry(), discardLogger(), NewEventBus())
	if _, err := d.CreateTask(context.Background(), "nope", protocol.TaskSpec{Kind: protocol.KindSysinfo}); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestOnResultStoresAndEmits(t *testing.T) {
	reg := session.NewRegistry()
	ev := NewEventBus()
	events, cancel := ev.Subscribe()
	defer cancel()
	d := NewDispatcher(reg, discardLogger(), ev)

	sess := &session.Session{SID: "s1", Outbound: make(chan *protocol.Envelope, 1)}
	if err := reg.Add(sess); err != nil {
		t.Fatal(err)
	}
	tid, err := d.CreateTask(context.Background(), "s1", protocol.TaskSpec{Kind: protocol.KindSysinfo})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	res := protocol.TaskResult{Status: protocol.StatusOK, Stdout: "x"}
	rd, _ := json.Marshal(res)
	env := protocol.NewEnvelope(protocol.TypeResult)
	env.SID = "s1"
	env.TID = tid
	env.Data = rd
	d.OnResult(env)

	view, ok := d.Task(tid)
	if !ok || view.Status != "done" || view.Result == nil || view.Result.Stdout != "x" {
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
