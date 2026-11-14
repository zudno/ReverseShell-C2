package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"reverseshell/internal/protocol"
)

func init() { Register(HTTP{}) }

const (
	defaultPollWait = 25 * time.Second
	beaconPath      = "/beacon"
	cidHeader       = "X-RS-Cid"
)

// HTTP carries the session plane over HTTP(S) polling (README §8.2): the
// agent POSTs agent→server frames to /beacon and long-polls GET /beacon
// for the next server→agent frame. The framing is untouched — HTTP is only
// the carriage. HTTPS applies when TLS options are set on either side.
type HTTP struct{}

// Name implements Transport.
func (HTTP) Name() string { return "http" }

// Dial implements Transport.
func (HTTP) Dial(_ context.Context, addr string, opt Options) (Conn, error) {
	scheme := "http"
	hc := &http.Client{}
	if opt.CAFile != "" || opt.InsecureSkipVerify {
		scheme = "https"
		roots, err := loadCAPool(opt.CAFile)
		if err != nil {
			return nil, err
		}
		hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:            roots,
			ServerName:         opt.ServerName,
			InsecureSkipVerify: opt.InsecureSkipVerify, // explicit lab opt-in
			MinVersion:         tls.VersionTLS12,
		}}
	}
	return &httpClientConn{
		hc:     hc,
		base:   scheme + "://" + addr,
		opt:    opt,
		remote: addr,
	}, nil
}

// Listen implements Transport.
func (HTTP) Listen(_ context.Context, addr string, opt Options) (Listener, error) {
	if opt.CertFile != "" || opt.KeyFile != "" {
		if opt.CertFile == "" || opt.KeyFile == "" {
			return nil, fmt.Errorf("http transport requires both cert and key")
		}
		if _, err := tls.LoadX509KeyPair(opt.CertFile, opt.KeyFile); err != nil {
			return nil, fmt.Errorf("http load keypair: %w", err)
		}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("http listen %s: %w", addr, err)
	}
	l := &httpListener{
		opt:      opt,
		ln:       ln,
		conns:    make(map[string]*MemConn),
		acceptCh: make(chan *MemConn, 64),
		closed:   make(chan struct{}),
	}
	mux := http.NewServeMux()
	mux.HandleFunc(beaconPath, l.handleBeacon)
	l.srv = &http.Server{Handler: mux}
	go func() {
		if opt.CertFile != "" {
			_ = l.srv.ServeTLS(ln, opt.CertFile, opt.KeyFile)
		} else {
			_ = l.srv.Serve(ln)
		}
	}()
	return l, nil
}

// httpListener adapts HTTP beacon requests into session Conns.
type httpListener struct {
	opt      Options
	srv      *http.Server
	ln       net.Listener
	mu       sync.Mutex
	conns    map[string]*MemConn
	acceptCh chan *MemConn
	closed   chan struct{}
	once     sync.Once
}

// Accept yields one MemConn per beaconing agent.
func (l *httpListener) Accept(ctx context.Context) (Conn, error) {
	select {
	case c := <-l.acceptCh:
		return c, nil
	case <-ctx.Done():
		_ = l.Close()
		return nil, ctx.Err()
	}
}

func (l *httpListener) Addr() net.Addr { return l.ln.Addr() }

func (l *httpListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		_ = l.srv.Close()
		_ = l.ln.Close()
	})
	return nil
}

func (l *httpListener) handleBeacon(w http.ResponseWriter, r *http.Request) {
	maxFrame := l.opt.MaxFrameBytes
	if maxFrame <= 0 {
		maxFrame = protocol.DefaultMaxFrameBytes
	}
	cid := r.URL.Query().Get("cid")

	switch r.Method {
	case http.MethodPost:
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(maxFrame)))
		if err != nil {
			http.Error(w, "oversized or unreadable frame", http.StatusRequestEntityTooLarge)
			return
		}
		conn, effCid, ok := l.connFor(w, r, cid)
		if !ok {
			return
		}
		select {
		case conn.Inbound <- body:
		case <-conn.Done():
			l.dropConn(effCid)
			http.Error(w, "session gone", http.StatusGone)
			return
		case <-l.closed:
			http.Error(w, "listener closed", http.StatusServiceUnavailable)
			return
		case <-time.After(10 * time.Second):
			http.Error(w, "session reader stalled", http.StatusServiceUnavailable)
			return
		}
		l.reply(w, r, conn, effCid, 0)
	case http.MethodGet:
		conn, ok := l.lookup(w, cid)
		if !ok {
			return
		}
		pollWait := l.opt.PollWait
		if pollWait <= 0 {
			pollWait = defaultPollWait
		}
		l.reply(w, r, conn, cid, pollWait)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// reply returns one queued frame, waiting up to wait (long-poll for GET).
func (l *httpListener) reply(w http.ResponseWriter, r *http.Request, conn *MemConn, cid string, wait time.Duration) {
	w.Header().Set(cidHeader, cid)
	var frame []byte
	if wait > 0 {
		select {
		case frame = <-conn.Outbound:
		case <-time.After(wait):
		case <-conn.Done():
			l.dropConn(cid)
			http.Error(w, "session gone", http.StatusGone)
			return
		case <-r.Context().Done():
			return
		}
	} else {
		select {
		case frame = <-conn.Outbound:
		default:
		}
	}
	if frame == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(frame)
}

// connFor resolves the session for a POST: new beacons mint a cid and are
// pushed to Accept; known beacons look their conn up. It returns the
// effective cid (the agent learns it from the response header).
func (l *httpListener) connFor(w http.ResponseWriter, r *http.Request, cid string) (*MemConn, string, bool) {
	if cid == "" {
		newCid, err := randID()
		if err != nil {
			http.Error(w, "cannot mint cid", http.StatusInternalServerError)
			return nil, "", false
		}
		conn := NewMemConn(r.RemoteAddr, 16)
		l.mu.Lock()
		l.conns[newCid] = conn
		l.mu.Unlock()
		select {
		case l.acceptCh <- conn:
		case <-l.closed:
			l.dropConn(newCid)
			http.Error(w, "listener closed", http.StatusServiceUnavailable)
			return nil, "", false
		case <-time.After(5 * time.Second):
			l.dropConn(newCid)
			http.Error(w, "accept queue stalled", http.StatusServiceUnavailable)
			return nil, "", false
		}
		return conn, newCid, true
	}
	conn, ok := l.lookup(w, cid)
	return conn, cid, ok
}

func (l *httpListener) lookup(w http.ResponseWriter, cid string) (*MemConn, bool) {
	l.mu.Lock()
	conn := l.conns[cid]
	l.mu.Unlock()
	if conn == nil {
		http.Error(w, "unknown cid", http.StatusNotFound)
		return nil, false
	}
	return conn, true
}

func (l *httpListener) dropConn(cid string) {
	l.mu.Lock()
	delete(l.conns, cid)
	l.mu.Unlock()
}

func randID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// httpClientConn is the agent-side beacon: POST pushes frames, GET
// long-polls for replies. The first response's cid header pins the session.
type httpClientConn struct {
	mu      sync.Mutex
	cid     string
	pending []byte
	hc      *http.Client
	base    string
	opt     Options
	remote  string
}

func (c *httpClientConn) maxFrame() int {
	if c.opt.MaxFrameBytes > 0 {
		return c.opt.MaxFrameBytes
	}
	return protocol.DefaultMaxFrameBytes
}

func (c *httpClientConn) Send(ctx context.Context, frame []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+beaconPath+"?cid="+c.cidLocked(), bytes.NewReader(frame))
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("http beacon post: %w", err)
	}
	defer resp.Body.Close()
	c.rememberCID(resp.Header.Get(cidHeader))
	switch resp.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, int64(c.maxFrame())))
		if err != nil {
			return err
		}
		if len(body) > 0 {
			c.stash(body)
		}
		return nil
	case http.StatusNoContent:
		return nil
	case http.StatusNotFound, http.StatusGone:
		return fmt.Errorf("http session gone (status %d)", resp.StatusCode)
	default:
		return fmt.Errorf("http beacon post: status %d", resp.StatusCode)
	}
}

func (c *httpClientConn) Recv(ctx context.Context) ([]byte, error) {
	if frame := c.take(); frame != nil {
		return frame, nil
	}
	for {
		frame, ok, err := c.pollOnce(ctx)
		if err != nil {
			return nil, err
		}
		if ok {
			return frame, nil
		}
	}
}

func (c *httpClientConn) pollOnce(ctx context.Context) (frame []byte, ok bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.base+beaconPath+"?cid="+c.cidLocked(), nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("http beacon poll: %w", err)
	}
	defer resp.Body.Close()
	c.rememberCID(resp.Header.Get(cidHeader))
	switch resp.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, int64(c.maxFrame())))
		if err != nil {
			return nil, false, err
		}
		if len(body) == 0 {
			return nil, false, nil
		}
		return body, true, nil
	case http.StatusNoContent:
		return nil, false, nil
	case http.StatusNotFound, http.StatusGone:
		return nil, false, fmt.Errorf("http session gone (status %d)", resp.StatusCode)
	default:
		return nil, false, fmt.Errorf("http beacon poll: status %d", resp.StatusCode)
	}
}

func (c *httpClientConn) cidLocked() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cid
}

func (c *httpClientConn) rememberCID(cid string) {
	if cid == "" {
		return
	}
	c.mu.Lock()
	c.cid = cid
	c.mu.Unlock()
}

// stash holds a frame received in a POST reply for the next Recv.
func (c *httpClientConn) stash(frame []byte) {
	c.mu.Lock()
	c.pending = frame
	c.mu.Unlock()
}

func (c *httpClientConn) take() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == nil {
		return nil
	}
	frame := c.pending
	c.pending = nil
	return frame
}

func (c *httpClientConn) RemoteAddr() string { return c.remote }

func (c *httpClientConn) Close() error { return nil }
