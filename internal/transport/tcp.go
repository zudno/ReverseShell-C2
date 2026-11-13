package transport

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"

	"reverseshell/internal/protocol"
)

func init() { Register(TCP{}) }

// TCP is the baseline stream transport: a persistent socket carrying the
// shared length-prefix framing (README §8.2).
type TCP struct{}

// Name implements Transport.
func (TCP) Name() string { return "tcp" }

// Dial implements Transport.
func (TCP) Dial(ctx context.Context, addr string, opt Options) (Conn, error) {
	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s: %w", addr, err)
	}
	return newTCPConn(nc, opt), nil
}

// Listen implements Transport.
func (TCP) Listen(_ context.Context, addr string, opt Options) (Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp listen %s: %w", addr, err)
	}
	return &tcpListener{l: l, opt: opt}, nil
}

type tcpListener struct {
	l   net.Listener
	opt Options
}

// Accept blocks until a connection arrives or ctx is cancelled. Cancelling
// ctx closes the listener: that is what unblocks the helper goroutine.
func (t *tcpListener) Accept(ctx context.Context) (Conn, error) {
	type acceptResult struct {
		c   net.Conn
		err error
	}
	ch := make(chan acceptResult, 1)
	go func() {
		c, err := t.l.Accept()
		ch <- acceptResult{c: c, err: err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("tcp accept: %w", r.err)
		}
		return newTCPConn(r.c, t.opt), nil
	case <-ctx.Done():
		_ = t.l.Close()
		return nil, ctx.Err()
	}
}

func (t *tcpListener) Addr() net.Addr { return t.l.Addr() }

func (t *tcpListener) Close() error { return t.l.Close() }

type tcpConn struct {
	nc       net.Conn
	br       *bufio.Reader
	maxFrame int
}

func newTCPConn(nc net.Conn, opt Options) *tcpConn {
	max := opt.MaxFrameBytes
	if max <= 0 {
		max = protocol.DefaultMaxFrameBytes
	}
	return &tcpConn{
		nc:       nc,
		br:       bufio.NewReader(nc),
		maxFrame: max,
	}
}

// Send writes one frame, applying any write deadline carried by ctx.
func (c *tcpConn) Send(ctx context.Context, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.nc.SetWriteDeadline(dl)
	} else {
		_ = c.nc.SetWriteDeadline(time.Time{})
	}
	if err := protocol.WriteFrame(c.nc, frame); err != nil {
		return fmt.Errorf("tcp send: %w", err)
	}
	return nil
}

// Recv reads one whole frame, applying any read deadline carried by ctx. A
// cancelled context alone does not interrupt a blocked read; the owner must
// also Close the conn (shutdown does exactly that).
func (c *tcpConn) Recv(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.nc.SetReadDeadline(dl)
	} else {
		_ = c.nc.SetReadDeadline(time.Time{})
	}
	frame, err := protocol.ReadFrame(c.br, c.maxFrame)
	if err != nil {
		return nil, fmt.Errorf("tcp recv: %w", err)
	}
	return frame, nil
}

func (c *tcpConn) RemoteAddr() string {
	if c.nc.RemoteAddr() == nil {
		return ""
	}
	return c.nc.RemoteAddr().String()
}

func (c *tcpConn) Close() error { return c.nc.Close() }
