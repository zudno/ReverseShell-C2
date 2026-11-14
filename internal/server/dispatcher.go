package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"reverseshell/internal/api"
	"reverseshell/internal/protocol"
	"reverseshell/internal/session"
)

// ErrSessionQueueFull reports the session's outbound FIFO was full (or the
// session went away) while enqueueing a task.
var ErrSessionQueueFull = errors.New("session outbound queue full or session gone")

// ErrTransferTooLarge reports a transfer above the per-file cap.
var ErrTransferTooLarge = errors.New("transfer exceeds the per-file cap")

// taskQueueTimeout bounds how long CreateTask waits to hand the envelope to
// the session writer before declaring the queue full.
const taskQueueTimeout = 5 * time.Second

// Task record statuses.
const (
	taskQueued = "queued"
	taskDone   = "done"
)

// TaskRecord tracks one task from creation to result. Data holds the
// assembled chunked-download payload (in memory only — never persisted).
type TaskRecord struct {
	TID       string
	SID       string
	Spec      protocol.TaskSpec
	Status    string
	Result    *protocol.TaskResult
	Data      []byte
	chunksGot int
	CreatedAt time.Time
}

// Dispatcher correlates operator tasks with agent results.
type Dispatcher struct {
	registry *session.Registry
	audit    *slog.Logger
	events   *EventBus
	store    *store

	mu    sync.Mutex
	tasks map[string]*TaskRecord
}

// NewDispatcher wires the dispatcher; stored is the reload set from the
// store (pending tasks survive teamserver restarts and re-deliver on the
// session's nonce resume — README §15, F5).
func NewDispatcher(reg *session.Registry, audit *slog.Logger, ev *EventBus, st *store, stored map[string]*storedTask) *Dispatcher {
	d := &Dispatcher{
		registry: reg,
		audit:    audit,
		events:   ev,
		store:    st,
		tasks:    make(map[string]*TaskRecord),
	}
	for _, t := range stored {
		d.tasks[t.TID] = &TaskRecord{
			TID:       t.TID,
			SID:       t.SID,
			Spec:      t.Spec,
			Status:    t.Status,
			Result:    t.Result,
			CreatedAt: t.CreatedAt,
		}
	}
	return d
}

// CreateTask mints a tid, records the task, queues the TASK envelope on the
// session's outbound FIFO, persists it, and audits the operator action.
func (d *Dispatcher) CreateTask(ctx context.Context, sid string, spec protocol.TaskSpec, operator string) (string, error) {
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
			slog.String("operator", operator),
			slog.String("kind", spec.Kind), slog.String("reason", "queue full"))
		return "", ErrSessionQueueFull
	}

	d.registry.Touch(sid, session.StateTasked)
	d.persist(tid, taskQueued, nil)
	d.audit.LogAttrs(context.Background(), slog.LevelInfo, "operator.task",
		slog.String("sid", sid), slog.String("tid", tid),
		slog.String("operator", operator),
		slog.String("kind", spec.Kind), slog.String("args", auditArgs(spec)))
	return tid, nil
}

// CreateUpload chunks an operator file into offset-addressed upload tasks
// and returns the view pointing at the completing task (README §4.5).
func (d *Dispatcher) CreateUpload(ctx context.Context, sid, path string, data []byte, operator string) (api.UploadView, error) {
	if len(data) > protocol.MaxTransferBytes {
		return api.UploadView{}, ErrTransferTooLarge
	}
	if _, err := d.registry.Get(sid); err != nil {
		return api.UploadView{}, err
	}
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	n := (len(data) + protocol.TransferChunkBytes - 1) / protocol.TransferChunkBytes
	if n == 0 {
		n = 1 // empty file: a single final chunk
	}
	var finalTID string
	for i := 0; i < n; i++ {
		off := i * protocol.TransferChunkBytes
		end := min(off+protocol.TransferChunkBytes, len(data))
		args, err := json.Marshal(protocol.UploadArgs{
			Path:       path,
			Offset:     int64(off),
			Index:      int64(i),
			Total:      int64(n),
			TotalBytes: int64(len(data)),
			SHA256:     sha,
			Data:       base64.StdEncoding.EncodeToString(data[off:end]),
			Final:      i == n-1,
		})
		if err != nil {
			return api.UploadView{}, err
		}
		tid, err := d.CreateTask(ctx, sid,
			protocol.TaskSpec{Kind: protocol.KindUpload, Args: args, Timeout: 60}, operator)
		if err != nil {
			return api.UploadView{}, err // partial upload; the audit trail accounts for it
		}
		finalTID = tid
	}
	return api.UploadView{
		FinalTID: finalTID,
		Chunks:   n,
		Bytes:    len(data),
		SHA256:   sha,
	}, nil
}

// OnResult stores a result, audits its metadata, and emits the SSE event.
// Chunked transfers assemble here; intermediate chunks are silent (no
// audit, no SSE) until the final chunk lands (README §9.3).
func (d *Dispatcher) OnResult(env *protocol.Envelope) {
	var res protocol.TaskResult
	if err := json.Unmarshal(env.Data, &res); err != nil {
		d.audit.LogAttrs(context.Background(), slog.LevelWarn, "session.result.bad",
			slog.String("sid", env.SID), slog.String("tid", env.TID),
			slog.String("error", err.Error()))
		return
	}

	d.mu.Lock()
	t, ok := d.tasks[env.TID]
	if ok && res.Chunk != nil {
		if res.Chunk.Index != t.chunksGot {
			d.mu.Unlock()
			d.audit.LogAttrs(context.Background(), slog.LevelWarn, "session.chunk.bad",
				slog.String("sid", env.SID), slog.String("tid", env.TID),
				slog.Int("want", t.chunksGot), slog.Int("got", res.Chunk.Index))
			return
		}
		raw, err := base64.StdEncoding.DecodeString(res.Data)
		if err != nil {
			d.mu.Unlock()
			d.audit.LogAttrs(context.Background(), slog.LevelWarn, "session.chunk.bad",
				slog.String("sid", env.SID), slog.String("tid", env.TID),
				slog.String("error", err.Error()))
			return
		}
		t.Data = append(t.Data, raw...)
		t.chunksGot++
		if !res.Chunk.Final {
			d.mu.Unlock()
			return // intermediate chunk: nothing to audit or emit yet
		}
		res.Data = "" // metadata only from here on
		t.Result = &res
		t.Status = taskDone
		total := len(t.Data)
		d.mu.Unlock()

		d.registry.Touch(env.SID, session.StateReady)
		d.audit.LogAttrs(context.Background(), slog.LevelInfo, "session.result",
			slog.String("sid", env.SID), slog.String("tid", env.TID),
			slog.String("status", res.Status), slog.Int("result_bytes", total))
		d.events.Emit("task.result", map[string]any{
			"sid": env.SID, "tid": env.TID, "status": res.Status, "bytes": total,
		})
		d.persist(env.TID, taskDone, &res)
		return
	}

	// Non-chunk result (the top lock is still held here).
	if ok {
		t.Status = taskDone
		t.Result = &res
	}
	d.mu.Unlock()
	if !ok {
		return
	}

	d.registry.Touch(env.SID, session.StateReady)
	d.audit.LogAttrs(context.Background(), slog.LevelInfo, "session.result",
		slog.String("sid", env.SID), slog.String("tid", env.TID),
		slog.String("status", res.Status), slog.Int("exit_code", res.ExitCode),
		slog.Int("result_bytes", len(res.Stdout)+len(res.Stderr)))
	d.events.Emit("task.result", map[string]any{
		"sid": env.SID, "tid": env.TID, "status": res.Status, "exit_code": res.ExitCode,
	})
	d.persist(env.TID, taskDone, &res)
}

// Resume re-enqueues tasks that never produced a result onto the resumed
// session's fresh outbound FIFO (README §4.7). This is also the restart
// path: tasks reloaded from the store re-deliver once the agent retakes its
// session by nonce. Delivery is at-least-once.
func (d *Dispatcher) Resume(sess *session.Session) int {
	d.mu.Lock()
	pending := make([]*TaskRecord, 0, 4)
	for _, t := range d.tasks {
		if t.SID == sess.SID && t.Status == taskQueued {
			pending = append(pending, t)
		}
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].CreatedAt.Before(pending[j].CreatedAt) })
	d.mu.Unlock()

	n := 0
	for _, t := range pending {
		env := protocol.NewEnvelope(protocol.TypeTask)
		env.SID = t.SID
		env.TID = t.TID
		data, err := json.Marshal(t.Spec)
		if err != nil {
			continue
		}
		env.Data = data
		select {
		case sess.Outbound <- env:
			n++
		default:
			d.audit.LogAttrs(context.Background(), slog.LevelWarn, "task.requeue.dropped",
				slog.String("sid", t.SID), slog.String("tid", t.TID))
		}
	}
	return n
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

// TaskData returns the assembled chunked-download payload and its
// complete-file hash.
func (d *Dispatcher) TaskData(tid string) ([]byte, string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	t, ok := d.tasks[tid]
	if !ok || t.Status != taskDone || t.Result == nil || t.Result.Chunk == nil {
		return nil, "", false
	}
	return t.Data, t.Result.Chunk.SHA256, true
}

// persist appends the task's state to the store, if enabled. Downloaded
// payload bytes are metadata-only by design; upload chunks keep their data
// so pending uploads can be redelivered after a restart.
func (d *Dispatcher) persist(tid, status string, result *protocol.TaskResult) {
	if d.store == nil {
		return
	}
	d.mu.Lock()
	t, ok := d.tasks[tid]
	d.mu.Unlock()
	if !ok {
		return
	}
	rec := &storedTask{
		TID:       t.TID,
		SID:       t.SID,
		Spec:      t.Spec,
		Status:    status,
		Result:    result,
		CreatedAt: t.CreatedAt,
	}
	if err := d.store.appendLine(storeLine{Type: "task", Task: rec}); err != nil {
		d.audit.LogAttrs(context.Background(), slog.LevelWarn, "task.store.error",
			slog.String("tid", tid), slog.String("error", err.Error()))
	}
}

// auditArgs renders a task's args for the audit line without file payloads:
// accountability without captured data (README §9.3).
func auditArgs(spec protocol.TaskSpec) string {
	switch spec.Kind {
	case protocol.KindUpload:
		var a protocol.UploadArgs
		if json.Unmarshal(spec.Args, &a) == nil {
			b, _ := json.Marshal(map[string]any{
				"path": a.Path, "index": a.Index, "total": a.Total, "bytes": len(a.Data),
			})
			return string(b)
		}
	case protocol.KindDownload:
		var a protocol.DownloadArgs
		if json.Unmarshal(spec.Args, &a) == nil {
			b, _ := json.Marshal(map[string]string{"path": a.Path})
			return string(b)
		}
	}
	return string(spec.Args)
}
