package transport

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestTCPFrameRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	l, err := TCP{}.Listen(ctx, "127.0.0.1:0", Options{})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	addr := l.Addr().String()
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("listener bound non-loopback: %s", addr)
	}

	srvErr := make(chan error, 1)
	go func() {
		c, err := l.Accept(ctx)
		if err != nil {
			srvErr <- err
			return
		}
		frame, err := c.Recv(ctx)
		if err != nil {
			srvErr <- err
			return
		}
		srvErr <- c.Send(ctx, frame)
	}()

	cli, err := TCP{}.Dial(ctx, addr, Options{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	if err := cli.Send(ctx, []byte("ping-123")); err != nil {
		t.Fatalf("send: %v", err)
	}
	got, err := cli.Recv(ctx)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if string(got) != "ping-123" {
		t.Fatalf("echo = %q", got)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server side: %v", err)
	}
}
