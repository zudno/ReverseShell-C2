// Package server implements the teamserver core: the embedded session-plane
// listener, session registry, task dispatch, audit log, and the event feed
// consumed by the operator API (README §3.2).
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"reverseshell/internal/api"
	"reverseshell/internal/protocol"
	"reverseshell/internal/relay"
	"reverseshell/internal/session"
	"reverseshell/internal/transport"
)

// Config configures the teamserver core.
type Config struct {
	TransportName   string
	ListenerAddr    string // "host:port"; the embedded listener bind
	MaxFrameBytes   int
	AuditLogPath    string
	StaleMultiplier float64 // × heartbeat_interval without signal → STALE
	SessionCfg      protocol.SessionConfig

	// Session-plane TLS (transport "tls"): certificate served by the listener.
	TLSCertFile string
	TLSKeyFile  string

	// AuthToken is the shared implant secret: when set, every REGISTER
	// must carry a valid HMAC (README §9.2). Empty = auth disabled.
	AuthToken string

	// Relay plane: when set, the teamserver also accepts connections from
	// standalone remote listeners over TLS (README §6.2).
	RelayAddr     string
	RelayToken    string
	RelayCertFile string
	RelayKeyFile  string

	// TaskStorePath persists task records and session resume nonces as
	// JSONL so pending tasks re-deliver after a restart (README §15, F5).
	// Empty = persistence disabled.
	TaskStorePath string
}

// Server is the teamserver core. It implements api.Backend.
type Server struct {
	cfg        Config
	audit      *slog.Logger
	auditFile  io.Closer
	operLog    *slog.Logger
	registry   *session.Registry
	dispatcher *Dispatcher
	events     *EventBus
	tr         transport.Transport
	listener   transport.Listener
	relay      *relay.Server
	store      *store

	wg     sync.WaitGroup
	mu     sync.Mutex
	conns  map[string]transport.Conn
	nonces map[string]string // agent nonce → sid; survives drops for resume
	cancel context.CancelFunc
}

// New validates the config, opens the audit log, and binds the embedded
// listener. Binding happens here so the address is known before Run starts
// (tests rely on that with port 0).
func New(cfg Config) (*Server, error) {
	if cfg.TransportName == "" {
		cfg.TransportName = "tcp"
	}
	if cfg.ListenerAddr == "" {
		cfg.ListenerAddr = "127.0.0.1:4444"
	}
	if cfg.MaxFrameBytes <= 0 {
		cfg.MaxFrameBytes = protocol.DefaultMaxFrameBytes
	}
	if cfg.AuditLogPath == "" {
		cfg.AuditLogPath = "logs/audit.jsonl"
	}
	if cfg.StaleMultiplier <= 0 {
		cfg.StaleMultiplier = 3
	}
	tr, err := transport.ByName(cfg.TransportName)
	if err != nil {
		return nil, err
	}
	audit, af, err := openAudit(cfg.AuditLogPath)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(cfg.ListenerAddr)
	if err != nil {
		_ = af.Close()
		return nil, fmt.Errorf("listener addr %q: %w", cfg.ListenerAddr, err)
	}
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		audit.LogAttrs(context.Background(), slog.LevelWarn, "listener.nonloopback",
			slog.String("bind", cfg.ListenerAddr))
	}
	l, err := tr.Listen(context.Background(), cfg.ListenerAddr, transport.Options{
		MaxFrameBytes: cfg.MaxFrameBytes,
		CertFile:      cfg.TLSCertFile,
		KeyFile:       cfg.TLSKeyFile,
	})
	if err != nil {
		_ = af.Close()
		return nil, err
	}
	var (
		st           *store
		preloadNonce = make(map[string]string)
		preloadTasks = make(map[string]*storedTask)
	)
	if cfg.TaskStorePath != "" {
		var err error
		st, err = openStore(cfg.TaskStorePath)
		if err != nil {
			_ = af.Close()
			_ = l.Close()
			return nil, err
		}
		preloadNonce, preloadTasks, err = loadStore(cfg.TaskStorePath)
		if err != nil {
			_ = st.close()
			_ = af.Close()
			_ = l.Close()
			return nil, fmt.Errorf("load task store: %w", err)
		}
	}
	s := &Server{
		cfg:       cfg,
		audit:     audit,
		auditFile: af,
		operLog:   slog.New(slog.NewTextHandler(os.Stderr, nil)),
		registry:  session.NewRegistry(),
		events:    NewEventBus(),
		tr:        tr,
		listener:  l,
		conns:     make(map[string]transport.Conn),
		nonces:    make(map[string]string),
		store:     st,
	}
	s.dispatcher = NewDispatcher(s.registry, audit, s.events, st, preloadTasks)
	for n, sid := range preloadNonce {
		s.nonces[n] = sid
	}
	if cfg.RelayAddr != "" {
		if cfg.RelayToken == "" || cfg.RelayCertFile == "" || cfg.RelayKeyFile == "" {
			_ = af.Close()
			_ = l.Close()
			return nil, fmt.Errorf("relay plane requires a token and TLS cert/key")
		}
		rs, err := relay.NewServer(relay.ServerConfig{
			Addr:     cfg.RelayAddr,
			Token:    cfg.RelayToken,
			CertFile: cfg.RelayCertFile,
			KeyFile:  cfg.RelayKeyFile,
		}, audit)
		if err != nil {
			_ = af.Close()
			_ = l.Close()
			return nil, err
		}
		s.relay = rs
		audit.LogAttrs(context.Background(), slog.LevelInfo, "relay.start",
			slog.String("bind", rs.Addr().String()))
	}
	audit.LogAttrs(context.Background(), slog.LevelInfo, "listener.start",
		slog.String("bind", l.Addr().String()),
		slog.String("transport", tr.Name()))
	return s, nil
}

// ListenAddr returns the bound session listener address (useful with port 0).
func (s *Server) ListenAddr() string { return s.listener.Addr().String() }

// RelayAddr returns the bound relay endpoint address ("" when disabled).
func (s *Server) RelayAddr() string {
	if s.relay == nil {
		return ""
	}
	return s.relay.Addr().String()
}

// Audit exposes the audit logger so the operator API audits auth failures on
// the same choke point.
func (s *Server) Audit() *slog.Logger { return s.audit }

// Run accepts agent connections until ctx is cancelled (or Shutdown is
// called), then tears every session down and waits for handlers to finish.
func (s *Server) Run(ctx context.Context) error {
	rctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()
	defer func() {
		cancel()
		_ = s.listener.Close()
		if s.relay != nil {
			_ = s.relay.Close()
		}
	}()

	if s.cfg.SessionCfg.HeartbeatInterval > 0 {
		go s.reapLoop(rctx)
	}

	go s.acceptLoop(rctx, s.listener)
	if s.relay != nil {
		go func() { _ = s.relay.Run(rctx) }()
		go s.acceptLoop(rctx, s.relay)
	}

	<-rctx.Done()

	// Closing every conn is what unblocks each handler's Recv.
	s.mu.Lock()
	conns := make([]transport.Conn, 0, len(s.conns))
	for _, c := range s.conns {
		conns = append(conns, c)
	}
	s.conns = make(map[string]transport.Conn)
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	s.wg.Wait()

	if s.store != nil {
		_ = s.store.close()
	}
	s.audit.LogAttrs(context.Background(), slog.LevelInfo, "server.stop")
	_ = s.auditFile.Close()
	return nil
}

// acceptLoop feeds session handlers from one session-plane listener — the
// embedded listener or the relay endpoint (remote sessions are treated
// exactly like local ones).
func (s *Server) acceptLoop(ctx context.Context, l transport.Listener) {
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.operLog.Error("accept failed", "error", err)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(ctx, conn)
		}()
	}
}

// Sessions implements api.Backend.
func (s *Server) Sessions() []api.SessionView {
	list := s.registry.List()
	out := make([]api.SessionView, 0, len(list))
	for _, sess := range list {
		out = append(out, api.SessionView{
			SID:         sess.SID,
			Peer:        sess.Peer,
			Hostname:    sess.Agent.Hostname,
			OS:          sess.Agent.OS,
			Arch:        sess.Agent.Arch,
			User:        sess.Agent.User,
			PID:         sess.Agent.PID,
			State:       string(sess.State),
			Transport:   sess.Transport,
			ConnectedAt: sess.ConnectedAt,
			LastSeen:    sess.LastSeen,
		})
	}
	return out
}

// CreateTask implements api.Backend.
func (s *Server) CreateTask(ctx context.Context, sid string, spec protocol.TaskSpec, operator string) (string, error) {
	tid, err := s.dispatcher.CreateTask(ctx, sid, spec, operator)
	switch {
	case err == nil:
		return tid, nil
	case errors.Is(err, session.ErrNotFound):
		return "", fmt.Errorf("%w: %s", api.ErrUnknownSession, sid)
	case errors.Is(err, ErrSessionQueueFull):
		return "", api.ErrSessionBusy
	default:
		return "", err
	}
}

// CreateUpload implements api.Backend: chunked operator→agent file push.
func (s *Server) CreateUpload(ctx context.Context, sid, path string, data []byte, operator string) (api.UploadView, error) {
	view, err := s.dispatcher.CreateUpload(ctx, sid, path, data, operator)
	switch {
	case err == nil:
		return view, nil
	case errors.Is(err, session.ErrNotFound):
		return view, fmt.Errorf("%w: %s", api.ErrUnknownSession, sid)
	case errors.Is(err, ErrSessionQueueFull):
		return view, api.ErrSessionBusy
	case errors.Is(err, ErrTransferTooLarge):
		return view, api.ErrTransferTooLarge
	default:
		return view, err
	}
}

// TaskData implements api.Backend.
func (s *Server) TaskData(tid string) ([]byte, string, bool) {
	return s.dispatcher.TaskData(tid)
}

// Task implements api.Backend.
func (s *Server) Task(tid string) (api.TaskView, bool) {
	return s.dispatcher.Task(tid)
}

// SubscribeEvents implements api.Backend.
func (s *Server) SubscribeEvents() (<-chan api.Event, func()) {
	return s.events.Subscribe()
}

// Shutdown implements api.Backend: it cancels Run's context, which unblocks
// the accept loop and tears every session down.
func (s *Server) Shutdown(_ context.Context) error {
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel == nil {
		return errors.New("server is not running")
	}
	cancel()
	return nil
}

// reapLoop marks sessions STALE when no signal arrived for
// stale_multiplier × heartbeat_interval (README §7): it sweeps them from
// the registry, closes their connections, and audits the event.
func (s *Server) reapLoop(ctx context.Context) {
	interval := time.Duration(s.cfg.SessionCfg.HeartbeatInterval * float64(time.Second))
	threshold := time.Duration(float64(interval) * s.cfg.StaleMultiplier)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().UTC().Add(-threshold)
			for _, sess := range s.registry.Sweep(cutoff) {
				s.closeConn(sess.SID)
				s.audit.LogAttrs(context.Background(), slog.LevelInfo, "session.stale",
					slog.String("sid", sess.SID))
				s.events.Emit("session.stale", map[string]string{"sid": sess.SID})
			}
		}
	}
}

// storeConn records the conn serving a sid.
func (s *Server) storeConn(sid string, c transport.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns[sid] = c
}

// dropConnIf removes the sid's conn only if it is still c: a resumed
// session's new conn must not be deleted by the old handler's cleanup.
func (s *Server) dropConnIf(sid string, c transport.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns[sid] == c {
		delete(s.conns, sid)
	}
}

// closeConn closes the conn serving a sid, if any (STALE sweep, resume).
func (s *Server) closeConn(sid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.conns[sid]; ok {
		_ = c.Close()
	}
}
