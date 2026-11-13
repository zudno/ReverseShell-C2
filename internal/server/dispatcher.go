package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"reverseshell/internal/api"
	"reverseshell/internal/protocol"
	"reverseshell/internal/session"
)

// ErrSessionQueueFull reports the session's outbound FIFO was full (or the
// session went away) while enqueueing a task.
var ErrSessionQueueFull = errors.New("session outbound queue full or session gone")

// taskQueueTimeout bounds how long CreateTask waits to hand the envelope to
// the session writer before declaring the queue full.
const taskQueueTimeout = 5 * time.Second

// Task record statuses.
const (
	taskQueued = "queued"
	taskDone   = "done"
)

// TaskRecord tracks one task from creation to result (in-memory, F1).
type TaskRecord struct {
	TID       string
	SID       string
	Spec      protocol.TaskSpec
	Status    string
	Result    *protocol.TaskResult
	CreatedAt time.Time
}

// Dispatcher correlates operator tasks with agent results.
type Dispatcher struct {
	registry *session.Registry
	audit    *slog.Logger
	events   *EventBus

	mu    sync.Mutex
	tasks map[string]*TaskRecord
}

// NewDispatcher wires the dispatcher to the registry, audit log, and bus.
func NewDispatcher(reg *session.Registry, audit *slog.Logger, ev *EventBus) *Dispatcher {
	return &Dispatcher{
		registry: reg,
		audit:    audit,
		events:   ev,
		tasks:    make(map[string]*TaskRecord),
	}
}

// CreateTask mints a tid, records the task, queues the TASK envelope on the
// session's outbound FIFO, and audits the operator action.
func (d *Dispatcher) CreateTask(ctx context.Context, sid string, spec protocol.TaskSpec) (string, error) {
	sess, err := d.registry.Get(sid)
	if err != nil {
		return "", err
	}
	tid, err := session.NewTID()
	if err != nil {
		return "", fmt.Errorf("mint tid: %w", err)
	}
	env := protocol.NewEnvelope(protocol.TypeTask)
	env.SID = sid
	env.TID = tid
	data, err := json.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("marshal task spec: %w", err)
	}
	env.Data = data

	// Record before enqueue so a poll right after the 202 never 404s.
	d.mu.Lock()
	d.tasks[tid] = &TaskRecord{
		TID:       tid,
		SID:       sid,
		Spec:      spec,
		Status:    taskQueued,
		CreatedAt: time.Now().UTC(),
	}
	d.mu.Unlock()

	qctx, cancel := context.WithTimeout(ctx, taskQueueTimeout)
	defer cancel()
	select {
	case sess.Outbound <- env:
	case <-qctx.Done():
		d.mu.Lock()
		delete(d.tasks, tid)
		d.mu.Unlock()
		d.audit.LogAttrs(context.Background(), slog.LevelWarn, "operator.task.rejected",
			slog.String("sid", sid), slog.String("tid", tid),
			slog.String("kind", spec.Kind), slog.String("reason", "queue full"))
		return "", ErrSessionQueueFull
	}

	d.registry.Touch(sid, session.StateTasked)
	d.audit.LogAttrs(context.Background(), slog.LevelInfo, "operator.task",
		slog.String("sid", sid), slog.String("tid", tid),
		slog.String("kind", spec.Kind), slog.String("args", string(data)))
	return tid, nil
}

// OnResult stores a result, audits its metadata, and emits the SSE event.
// The audit line records what the operator got (status, size), never the
// captured content itself (README §9.3).
func (d *Dispatcher) OnResult(env *protocol.Envelope) {
	var res protocol.TaskResult
	if err := json.Unmarshal(env.Data, &res); err != nil {
		d.audit.LogAttrs(context.Background(), slog.LevelWarn, "session.result.bad",
			slog.String("sid", env.SID), slog.String("tid", env.TID),
			slog.String("error", err.Error()))
		return
	}
	// Audit before flipping the record to done: a poller that sees "done"
	// must be guaranteed the audit line is already on disk.
	d.audit.LogAttrs(context.Background(), slog.LevelInfo, "session.result",
		slog.String("sid", env.SID), slog.String("tid", env.TID),
		slog.String("status", res.Status), slog.Int("exit_code", res.ExitCode),
		slog.Int("result_bytes", len(res.Stdout)+len(res.Stderr)))

	d.mu.Lock()
	if t, ok := d.tasks[env.TID]; ok {
		t.Status = taskDone
		t.Result = &res
	}
	d.mu.Unlock()

	d.registry.Touch(env.SID, session.StateReady)

	d.events.Emit("task.result", map[string]any{
		"sid":       env.SID,
		"tid":       env.TID,
		"status":    res.Status,
		"exit_code": res.ExitCode,
	})
}

// Task returns the task record for the operator API.
func (d *Dispatcher) Task(tid string) (api.TaskView, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	t, ok := d.tasks[tid]
	if !ok {
		return api.TaskView{}, false
	}
	return api.TaskView{
		TID:       t.TID,
		SID:       t.SID,
		Kind:      t.Spec.Kind,
		Status:    t.Status,
		Result:    t.Result,
		CreatedAt: t.CreatedAt,
	}, true
}
