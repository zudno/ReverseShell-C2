package transport

import (
	"context"
	"errors"
	"sync"
)

// ErrClosed is returned by a closed MemConn's Send and Recv.
var ErrClosed = errors.New("connection closed")

// MemConn is a channel-backed, message-oriented Conn. Wire pumps push frames
// the peer sent into Inbound (the session reader consumes them via Recv) and
// drain Outbound into the wire (the session writer feeds it via Send). It
// backs transports where the physical wire does not carry our framing
// directly: HTTP polling and the relay plane.
type MemConn struct {
	remote   string
	Inbound  chan []byte
	Outbound chan []byte
	done     chan struct{}
	once     sync.Once
}

// NewMemConn returns a MemConn with the given queue depth.
func NewMemConn(remote string, depth int) *MemConn {
	if depth <= 0 {
		depth = 16
	}
	return &MemConn{
		remote:   remote,
		Inbound:  make(chan []byte, depth),
		Outbound: make(chan []byte, depth),
		done:     make(chan struct{}),
	}
}

// Send queues one frame for the wire pump.
func (c *MemConn) Send(ctx context.Context, frame []byte) error {
	// A closed conn never accepts frames, even with buffer space left:
	// without this check a ready-buffer send could win the select race.
	select {
	case <-c.done:
		return ErrClosed
	default:
	}
	select {
	case c.Outbound <- frame:
		return nil
	case <-c.done:
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Recv returns the next frame the wire pump delivered.
func (c *MemConn) Recv(ctx context.Context) ([]byte, error) {
	select {
	case <-c.done:
		return nil, ErrClosed
	default:
	}
	select {
	case frame := <-c.Inbound:
		return frame, nil
	case <-c.done:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// RemoteAddr identifies the peer this conn stands for.
func (c *MemConn) RemoteAddr() string { return c.remote }

// Done closes when Close is called; wire pumps select on it.
func (c *MemConn) Done() <-chan struct{} { return c.done }

// Close unblocks every pending Send/Recv and wire pump.
func (c *MemConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}
