package transport

import (
	"context"
	"testing"
	"time"
)

func TestMemConnRoundTrip(t *testing.T) {
	ctx := context.Background()
	c := NewMemConn("test-peer", 4)
	if c.RemoteAddr() != "test-peer" {
		t.Fatalf("remote = %q", c.RemoteAddr())
	}
	if err := c.Send(ctx, []byte("to-wire")); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case got := <-c.Outbound:
		if string(got) != "to-wire" {
			t.Fatalf("pump got %q", got)
		}
	default:
		t.Fatal("nothing drained from Outbound")
	}
	c.Inbound <- []byte("from-wire")
	got, err := c.Recv(ctx)
	if err != nil || string(got) != "from-wire" {
		t.Fatalf("recv = %q (%v)", got, err)
	}
}

func TestMemConnClosedUnblocks(t *testing.T) {
	ctx := context.Background()
	c := NewMemConn("x", 4)
	c.Close()
	if err := c.Send(ctx, []byte("f")); err == nil {
		t.Fatal("send on closed conn must fail")
	}
	if _, err := c.Recv(ctx); err == nil {
		t.Fatal("recv on closed conn must fail")
	}
	select {
	case <-c.Done():
	default:
		t.Fatal("Done not closed")
	}

	full := NewMemConn("x", 1)
	done := make(chan error, 1)
	go func() {
		_, err := full.Recv(ctx) // blocks: Inbound is empty, nothing sends
		done <- err
	}()
	full.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked recv must fail after close")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not unblock a waiting recv")
	}
}
