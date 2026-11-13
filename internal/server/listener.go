package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"reverseshell/internal/protocol"
	"reverseshell/internal/session"
	"reverseshell/internal/transport"
)

// handleConn runs one agent connection: the REGISTER handshake, then a
// reader loop paired with a writer goroutine that drains the session's
// outbound FIFO (README §4.6).
func (s *Server) handleConn(ctx context.Context, conn transport.Conn) {
	defer conn.Close()

	info, ok := s.expectRegister(ctx, conn)
	if !ok {
		return
	}
	sid, err := session.NewSID()
	if err != nil {
		s.reject(ctx, conn, protocol.ErrCodeInternal, "cannot mint session id")
		return
	}
	sess := &session.Session{
		SID:         sid,
		Peer:        conn.RemoteAddr(),
		Transport:   s.tr.Name(),
		Agent:       info,
		State:       session.StateRegistered,
		ConnectedAt: time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Outbound:    make(chan *protocol.Envelope, 16),
	}
	if err := s.registry.Add(sess); err != nil {
		s.reject(ctx, conn, protocol.ErrCodeInternal, "session registration failed")
		return
	}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()

	s.mu.Lock()
	s.conns[sid] = conn
	s.mu.Unlock()

	defer func() {
		s.registry.Remove(sid)
		s.mu.Lock()
		delete(s.conns, sid)
		s.mu.Unlock()
		s.audit.LogAttrs(context.Background(), slog.LevelInfo, "session.down",
			slog.String("sid", sid))
		s.events.Emit("session.down", map[string]string{"sid": sid})
	}()

	if !s.sendRegistered(ctx, conn, sid) {
		return
	}

	s.audit.LogAttrs(context.Background(), slog.LevelInfo, "session.register",
		slog.String("sid", sid), slog.String("src", sess.Peer),
		slog.String("os", info.OS), slog.String("user", info.User),
		slog.String("hostname", info.Hostname))
	s.events.Emit("session.register", map[string]string{
		"sid":      sid,
		"os":       info.OS,
		"user":     info.User,
		"hostname": info.Hostname,
	})

	go s.writeLoop(sctx, conn, sess.Outbound)

	for {
		frame, err := conn.Recv(sctx)
		if err != nil {
			return
		}
		env, err := protocol.Decode(frame)
		if err != nil {
			s.reject(sctx, conn, protocol.ErrCodeBadEnvelope, err.Error())
			return
		}
		s.registry.Touch(sid, session.StateReady)
		switch env.Type {
		case protocol.TypeResult:
			if env.SID != sid || env.TID == "" {
				s.operLog.Warn("result with bad correlation", "sid", sid,
					"envelope_sid", env.SID, "envelope_tid", env.TID)
				continue
			}
			s.dispatcher.OnResult(env)
		case protocol.TypeHeartbeat:
			ack := protocol.NewEnvelope(protocol.TypeAck)
			ack.SID = sid
			select {
			case sess.Outbound <- ack:
			case <-sctx.Done():
				return
			}
		case protocol.TypeBye:
			s.audit.LogAttrs(context.Background(), slog.LevelInfo, "session.bye",
				slog.String("sid", sid))
			return
		case protocol.TypeError:
			var ep protocol.ErrorPayload
			if err := json.Unmarshal(env.Data, &ep); err == nil {
				s.operLog.Warn("agent reported error", "sid", sid,
					"code", ep.Code, "detail", ep.Message)
			}
		default:
			s.reject(sctx, conn, protocol.ErrCodeUnknownType, "unexpected "+string(env.Type))
			return
		}
	}
}

// expectRegister consumes the first frame and validates it as a REGISTER.
func (s *Server) expectRegister(ctx context.Context, conn transport.Conn) (protocol.AgentInfo, bool) {
	frame, err := conn.Recv(ctx)
	if err != nil {
		return protocol.AgentInfo{}, false
	}
	env, err := protocol.Decode(frame)
	if err != nil || env.Type != protocol.TypeRegister {
		s.reject(ctx, conn, protocol.ErrCodeBadEnvelope, "expected REGISTER")
		return protocol.AgentInfo{}, false
	}
	var info protocol.AgentInfo
	if err := json.Unmarshal(env.Data, &info); err != nil || info.Nonce == "" {
		s.reject(ctx, conn, protocol.ErrCodeBadEnvelope, "malformed agent_info")
		return protocol.AgentInfo{}, false
	}
	return info, true
}

// sendRegistered confirms the session and hands the agent its parameters.
func (s *Server) sendRegistered(ctx context.Context, conn transport.Conn, sid string) bool {
	cfg := s.cfg.SessionCfg
	if cfg.MaxFrameBytes == 0 {
		cfg.MaxFrameBytes = s.cfg.MaxFrameBytes
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return false
	}
	env := protocol.NewEnvelope(protocol.TypeRegistered)
	env.SID = sid
	env.Data = data
	return sendEnvelope(ctx, conn, env) == nil
}

// writeLoop drains the outbound FIFO into the connection. It exits on
// context cancellation or a send failure; the channel is never closed here
// because the dispatcher may hold concurrent send references.
func (s *Server) writeLoop(ctx context.Context, conn transport.Conn, outbound <-chan *protocol.Envelope) {
	for {
		select {
		case env := <-outbound:
			if err := sendEnvelope(ctx, conn, env); err != nil {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// reject sends a non-recoverable protocol error and lets the caller close.
func (s *Server) reject(ctx context.Context, conn transport.Conn, code, msg string) {
	env := protocol.NewEnvelope(protocol.TypeError)
	data, _ := json.Marshal(protocol.ErrorPayload{Code: code, Message: msg, Recoverable: false})
	env.Data = data
	_ = sendEnvelope(ctx, conn, env)
}

func sendEnvelope(ctx context.Context, conn transport.Conn, e *protocol.Envelope) error {
	b, err := protocol.Encode(e)
	if err != nil {
		return err
	}
	return conn.Send(ctx, b)
}
