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

// handleConn runs one agent connection: the REGISTER handshake (resuming
// the session when the nonce is known), then a reader loop paired with a
// writer goroutine that drains the session's outbound FIFO (README §4.6).
func (s *Server) handleConn(ctx context.Context, conn transport.Conn) {
	defer conn.Close()

	info, ts, ok := s.expectRegister(ctx, conn)
	if !ok {
		return
	}
	if s.cfg.AuthToken != "" && !protocol.ValidRegisterMAC(s.cfg.AuthToken, info, ts, info.Auth) {
		s.audit.LogAttrs(context.Background(), slog.LevelWarn, "session.auth.failed",
			slog.String("src", conn.RemoteAddr()),
			slog.String("hostname", info.Hostname))
		s.reject(ctx, conn, protocol.ErrCodeAuthFailed, "invalid registration mac")
		return
	}
	sid, resumed, err := s.resolveSession(info.Nonce)
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
	// The previous record (if any) is superseded; only our own cleanup may
	// remove the fresh one.
	s.registry.Remove(sid)
	if err := s.registry.Add(sess); err != nil {
		s.reject(ctx, conn, protocol.ErrCodeInternal, "session registration failed")
		return
	}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()

	s.storeConn(sid, conn)

	defer func() {
		s.registry.RemoveSession(sess)
		s.dropConnIf(sid, conn)
		s.audit.LogAttrs(context.Background(), slog.LevelInfo, "session.down",
			slog.String("sid", sid))
		s.events.Emit("session.down", map[string]string{"sid": sid})
	}()

	if !s.sendRegistered(ctx, conn, sid) {
		return
	}

	if resumed {
		n := s.dispatcher.Resume(sess)
		s.audit.LogAttrs(context.Background(), slog.LevelInfo, "session.resume",
			slog.String("sid", sid), slog.String("src", sess.Peer),
			slog.Int("requeued", n))
		s.events.Emit("session.resume", map[string]any{"sid": sid, "requeued": n})
	} else {
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
	}

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

// resolveSession maps the agent nonce to its sid. A known nonce resumes the
// same session (kicking any leftover connection); a fresh nonce mints a
// new sid and is remembered for future resumes (README §4.7).
func (s *Server) resolveSession(nonce string) (sid string, resumed bool, err error) {
	fresh, err := session.NewSID()
	if err != nil {
		return "", false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if known, ok := s.nonces[nonce]; ok {
		if old, ok := s.conns[known]; ok {
			_ = old.Close() // unblock the superseded handler; its cleanup no-ops
		}
		delete(s.conns, known)
		return known, true, nil
	}
	s.nonces[nonce] = fresh
	if s.store != nil {
		// Survive restarts: a reconnecting agent retakes its session and
		// its pending tasks (README §4.7, F5).
		if err := s.store.appendLine(storeLine{Type: "session", SID: fresh, Nonce: nonce}); err != nil {
			s.audit.LogAttrs(context.Background(), slog.LevelWarn, "task.store.error",
				slog.String("error", err.Error()))
		}
	}
	return fresh, false, nil
}

// expectRegister consumes the first frame and validates it as a REGISTER.
// It returns the agent identity and the envelope timestamp (the HMAC input).
func (s *Server) expectRegister(ctx context.Context, conn transport.Conn) (protocol.AgentInfo, float64, bool) {
	frame, err := conn.Recv(ctx)
	if err != nil {
		return protocol.AgentInfo{}, 0, false
	}
	env, err := protocol.Decode(frame)
	if err != nil || env.Type != protocol.TypeRegister {
		s.reject(ctx, conn, protocol.ErrCodeBadEnvelope, "expected REGISTER")
		return protocol.AgentInfo{}, 0, false
	}
	var info protocol.AgentInfo
	if err := json.Unmarshal(env.Data, &info); err != nil || info.Nonce == "" {
		s.reject(ctx, conn, protocol.ErrCodeBadEnvelope, "malformed agent_info")
		return protocol.AgentInfo{}, 0, false
	}
	return info, env.TS, true
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
