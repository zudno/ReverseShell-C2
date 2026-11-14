package transport

import (
	"context"
	"fmt"
	"testing"
	"time"

	"reverseshell/internal/testutil"
)

func httpRoundTrip(t *testing.T, listenOpt, dialOpt Options) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	l, err := (HTTP{}).Listen(ctx, "127.0.0.1:0", listenOpt)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	addr := l.Addr().String()

	srvErr := make(chan error, 1)
	go func() {
		c, err := l.Accept(ctx)
		if err != nil {
			srvErr <- err
			return
		}
		frame, err := c.Recv(ctx) // the agent's beacon
		if err != nil {
			srvErr <- err
			return
		}
		if string(frame) != "hello-beacon" {
			srvErr <- fmt.Errorf("frame = %q", frame)
			return
		}
		srvErr <- c.Send(ctx, []byte("server-reply"))
	}()

	cli, err := (HTTP{}).Dial(ctx, addr, dialOpt)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	if err := cli.Send(ctx, []byte("hello-beacon")); err != nil {
		t.Fatalf("send: %v", err)
	}
	got, err := cli.Recv(ctx)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if string(got) != "server-reply" {
		t.Fatalf("reply = %q", got)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server side: %v", err)
	}
}

func TestHTTPFrameRoundTrip(t *testing.T) {
	httpRoundTrip(t, Options{PollWait: 300 * time.Millisecond}, Options{})
}

func TestHTTPSFrameRoundTrip(t *testing.T) {
	certPath, keyPath := testutil.WriteTLSCert(t)
	httpRoundTrip(t,
		Options{PollWait: 300 * time.Millisecond, CertFile: certPath, KeyFile: keyPath},
		Options{CAFile: certPath},
	)
}

func TestHTTPSessionGoneAfterClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	l, err := (HTTP{}).Listen(ctx, "127.0.0.1:0", Options{PollWait: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		c, err := l.Accept(ctx)
		if err == nil {
			_ = c.Close() // session torn down server-side
		}
	}()

	cli, err := (HTTP{}).Dial(ctx, l.Addr().String(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	if _, err := cli.Recv(ctx); err == nil {
		t.Fatal("recv must fail once the server closed the session")
	}
}
