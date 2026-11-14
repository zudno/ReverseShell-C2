package relay_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"testing"
	"time"

	"reverseshell/internal/relay"
	"reverseshell/internal/testutil"
	"reverseshell/internal/transport"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestMessageRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	m := &relay.Message{Type: relay.TypeFrameRelay, SID: "s1", Data: []byte("payload")}
	if err := relay.Write(&buf, m); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := relay.Read(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Type != relay.TypeFrameRelay || got.SID != "s1" || string(got.Data) != "payload" {
		t.Fatalf("message = %+v", got)
	}
}

func newRelayServer(t *testing.T, ctx context.Context, token string) *relay.Server {
	t.Helper()
	certPath, keyPath := testutil.WriteTLSCert(t)
	srv, err := relay.NewServer(relay.ServerConfig{
		Addr:     "127.0.0.1:0",
		Token:    token,
		CertFile: certPath,
		KeyFile:  keyPath,
	}, discardLogger())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	go func() { _ = srv.Run(ctx) }()
	return srv
}

func TestServerRejectsBadToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv := newRelayServer(t, ctx, "relay-secret")

	raw, err := tls.Dial("tcp", srv.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, // test-only: we are checking the token layer
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()

	if err := relay.Write(raw, &relay.Message{Type: relay.TypeListenerHello, Name: "bad", Token: "wrong"}); err != nil {
		t.Fatal(err)
	}
	reply, err := relay.Read(raw)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply.Type != relay.TypeListenerError {
		t.Fatalf("reply type = %q, want LISTENER_ERROR", reply.Type)
	}
}

func TestRelaySessionRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv := newRelayServer(t, ctx, "relay-secret")

	client, err := relay.Dial(ctx, relay.ClientConfig{
		Addr:     srv.Addr().String(),
		Token:    "relay-secret",
		Name:     "lab-listener",
		Insecure: true, // test: the self-signed cert is its own CA
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	// A MemConn stands in for the terminated implant connection.
	agent := transport.NewMemConn("fake-agent", 16)
	forwardDone := make(chan error, 1)
	go func() { forwardDone <- client.Forward(ctx, agent) }()

	// The teamserver side accepts the remote session.
	sconn, err := srv.Accept(ctx)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	t.Cleanup(func() { _ = sconn.Close() })

	// agent → teamserver
	agent.Inbound <- []byte("frame-from-agent")
	got, err := sconn.Recv(ctx)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if string(got) != "frame-from-agent" {
		t.Fatalf("frame = %q", got)
	}

	// teamserver → agent
	if err := sconn.Send(ctx, []byte("frame-to-agent")); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case frame := <-agent.Outbound:
		if string(frame) != "frame-to-agent" {
			t.Fatalf("agent got %q", frame)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no frame pumped back to the agent")
	}

	// Tearing the session down on the teamserver side must close the agent.
	if err := sconn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-forwardDone:
		if err == nil {
			t.Fatal("forward must end when the session goes down")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("forward did not end on session down")
	}
}
