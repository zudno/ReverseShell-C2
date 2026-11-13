// Package api implements the operator API: the REST+SSE control plane exposed
// by the teamserver (README §5). Operators authenticate with a bearer token
// and never touch the session plane directly.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"reverseshell/internal/protocol"
)

// SessionView is the operator-facing projection of a session.
type SessionView struct {
	SID         string    `json:"sid"`
	Peer        string    `json:"peer"`
	Hostname    string    `json:"hostname"`
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	User        string    `json:"user"`
	PID         int       `json:"pid"`
	State       string    `json:"state"`
	Transport   string    `json:"transport"`
	ConnectedAt time.Time `json:"connected_at"`
	LastSeen    time.Time `json:"last_seen"`
}

// TaskView is the operator-facing projection of a task and its result.
type TaskView struct {
	TID       string               `json:"tid"`
	SID       string               `json:"sid"`
	Kind      string               `json:"kind"`
	Status    string               `json:"status"`
	Result    *protocol.TaskResult `json:"result,omitempty"`
	CreatedAt time.Time            `json:"created_at"`
}

// Event is one SSE event.
type Event struct {
	Type string
	Data json.RawMessage
}

// Backend is what the API needs from the teamserver core.
type Backend interface {
	Sessions() []SessionView
	CreateTask(ctx context.Context, sid string, spec protocol.TaskSpec) (string, error)
	Task(tid string) (TaskView, bool)
	SubscribeEvents() (<-chan Event, func())
	Shutdown(ctx context.Context) error
}

// Sentinel backend errors, mapped to HTTP statuses by the handlers.
var (
	ErrUnknownSession = errors.New("unknown session")
	ErrSessionBusy    = errors.New("session busy")
)

// Config configures the API server.
type Config struct {
	Addr    string // loopback by default (README §9)
	Token   string // required bearer token
	Backend Backend
	Audit   *slog.Logger // optional: auth failures are audited too
}

// Server serves the operator API.
type Server struct {
	cfg Config
	srv *http.Server
	ln  net.Listener
}

// New validates the config and binds the HTTP listener.
func New(cfg Config) (*Server, error) {
	if cfg.Token == "" {
		return nil, errors.New("api: operator token is required")
	}
	if cfg.Backend == nil {
		return nil, errors.New("api: backend is required")
	}
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:5555"
	}
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("api listen %s: %w", cfg.Addr, err)
	}
	s := &Server{cfg: cfg, ln: ln}
	s.srv = &http.Server{Handler: s.routes()}
	return s, nil
}

// Addr returns the bound API address (useful with port 0).
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Handler returns the routed, authenticated handler (for httptest).
func (s *Server) Handler() http.Handler { return s.srv.Handler }

// Close releases the bound listener.
func (s *Server) Close() error { return s.ln.Close() }

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() { errCh <- s.srv.Serve(s.ln) }()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(sctx)
		return nil
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sessions", s.auth(s.handleSessions))
	mux.HandleFunc("POST /v1/sessions/{sid}/tasks", s.auth(s.handleCreateTask))
	mux.HandleFunc("GET /v1/tasks/{tid}", s.auth(s.handleTask))
	mux.HandleFunc("GET /v1/events", s.auth(s.handleEvents))
	mux.HandleFunc("POST /v1/shutdown", s.auth(s.handleShutdown))
	return mux
}

// auth rejects requests without the exact bearer token (constant-time
// compare) and audits every rejection.
func (s *Server) auth(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.Token)) != 1 {
			if s.cfg.Audit != nil {
				s.cfg.Audit.LogAttrs(r.Context(), slog.LevelWarn, "operator.auth.failed",
					slog.String("remote", r.RemoteAddr), slog.String("path", r.URL.Path))
			}
			writeJSON(w, http.StatusUnauthorized,
				map[string]string{"error": "invalid or missing bearer token"})
			return
		}
		next(w, r)
	}
}

func (s *Server) handleSessions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.cfg.Backend.Sessions())
}

func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request) {
	var spec protocol.TaskSpec
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(&spec); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if err := validateSpec(&spec); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	tid, err := s.cfg.Backend.CreateTask(r.Context(), r.PathValue("sid"), spec)
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, map[string]string{"tid": tid})
	case errors.Is(err, ErrUnknownSession):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.Is(err, ErrSessionBusy):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
}

func validateSpec(spec *protocol.TaskSpec) error {
	switch spec.Kind {
	case protocol.KindShell:
		if len(spec.Args) == 0 {
			return errors.New("shell task requires args.cmd")
		}
		var a protocol.ShellArgs
		if err := json.Unmarshal(spec.Args, &a); err != nil || a.Cmd == "" {
			return errors.New("shell task requires args.cmd")
		}
	case protocol.KindSysinfo:
		// no args
	default:
		return fmt.Errorf("unknown kind %q (supported: shell, sysinfo)", spec.Kind)
	}
	if spec.Timeout < 0 {
		return errors.New("timeout must be >= 0")
	}
	return nil
}

func (s *Server) handleTask(w http.ResponseWriter, r *http.Request) {
	v, ok := s.cfg.Backend.Task(r.PathValue("tid"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown task"})
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming unsupported"})
		return
	}
	events, cancel := s.cfg.Backend.SubscribeEvents()
	defer cancel()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	keep := time.NewTicker(20 * time.Second)
	defer keep.Stop()
	for {
		select {
		case ev := <-events:
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, ev.Data)
			flusher.Flush()
		case <-keep.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) handleShutdown(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "shutting down"})
	_ = s.cfg.Backend.Shutdown(context.Background())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal marshal failure"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}
