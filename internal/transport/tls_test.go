package transport

import (
	"context"
	"strings"
	"testing"
	"time"

	"reverseshell/internal/testutil"
)

func TestTLSListenRequiresCert(t *testing.T) {
	if _, err := (TLS{}).Listen(context.Background(), "127.0.0.1:0", Options{}); err == nil {
		t.Fatal("expected error when cert/key are missing")
	}
}

func TestTLSFrameRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	certPath, keyPath := testutil.WriteTLSCert(t)
	l, err := TLS{}.Listen(ctx, "127.0.0.1:0", Options{CertFile: certPath, KeyFile: keyPath})
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
		frame, err := c.Recv(ctx)
		if err != nil {
			srvErr <- err
			return
		}
		srvErr <- c.Send(ctx, frame)
	}()

	cli, err := TLS{}.Dial(ctx, addr, Options{CAFile: certPath})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	if err := cli.Send(ctx, []byte("ping-over-tls")); err != nil {
		t.Fatalf("send: %v", err)
	}
	got, err := cli.Recv(ctx)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if string(got) != "ping-over-tls" {
		t.Fatalf("echo = %q", got)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server side: %v", err)
	}
}

func TestTLSDialRejectsUnknownCA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	certPath, keyPath := testutil.WriteTLSCert(t)
	l, err := TLS{}.Listen(ctx, "127.0.0.1:0", Options{CertFile: certPath, KeyFile: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	// A second, unrelated certificate must not verify the listener.
	otherCA, _ := testutil.WriteTLSCert(t)
	_, err = TLS{}.Dial(ctx, l.Addr().String(), Options{CAFile: otherCA})
	if err == nil {
		t.Fatal("dial with unknown CA must fail")
	}
	if !strings.Contains(err.Error(), "handshake") {
		t.Fatalf("err = %v, want handshake failure", err)
	}
}
