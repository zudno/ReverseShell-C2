// Package transport provides pluggable, message-oriented session transports.
// Each Send/Recv moves exactly one framed message; framing lives in
// internal/protocol and is never reimplemented here (README §8).
package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
)

// Conn delivers whole framed messages over one session connection.
type Conn interface {
	Send(ctx context.Context, frame []byte) error
	Recv(ctx context.Context) ([]byte, error)
	RemoteAddr() string
	Close() error
}

// Listener yields accepted Conns on the teamserver side.
type Listener interface {
	Accept(ctx context.Context) (Conn, error)
	Addr() net.Addr
	Close() error
}

// Options carries transport tuning shared by every implementation.
type Options struct {
	MaxFrameBytes int
	// TLS session-plane settings (transport "tls").
	CertFile           string // listener side: server certificate
	KeyFile            string // listener side: server key
	CAFile             string // agent side: CA bundle to verify the listener
	ServerName         string // agent side: SNI / verification name (default: addr host)
	InsecureSkipVerify bool   // agent side, lab only: skip verification (explicit opt-in)
}

// Transport is the factory interface implemented by each transport module and
// selected by name on both sides.
type Transport interface {
	Name() string
	Dial(ctx context.Context, addr string, opt Options) (Conn, error)
	Listen(ctx context.Context, addr string, opt Options) (Listener, error)
}

var (
	mu       sync.RWMutex
	registry = map[string]Transport{}
)

// Register makes a transport selectable by name (called from init).
func Register(t Transport) {
	mu.Lock()
	defer mu.Unlock()
	registry[t.Name()] = t
}

// ByName resolves "tcp", "tls", "http", … to a registered transport.
func ByName(name string) (Transport, error) {
	mu.RLock()
	defer mu.RUnlock()
	t, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown transport %q", name)
	}
	return t, nil
}
