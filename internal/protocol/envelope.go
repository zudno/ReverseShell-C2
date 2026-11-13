package protocol

import (
	"encoding/json"
	"fmt"
	"time"
)

// Version is the session-plane protocol version (envelope field "v").
const Version = 1

// MsgType enumerates the eight session-plane message types (README §4.3).
type MsgType string

const (
	TypeRegister   MsgType = "REGISTER"
	TypeRegistered MsgType = "REGISTERED"
	TypeTask       MsgType = "TASK"
	TypeResult     MsgType = "RESULT"
	TypeHeartbeat  MsgType = "HEARTBEAT"
	TypeAck        MsgType = "ACK"
	TypeError      MsgType = "ERROR"
	TypeBye        MsgType = "BYE"
)

var validTypes = map[MsgType]bool{
	TypeRegister:   true,
	TypeRegistered: true,
	TypeTask:       true,
	TypeResult:     true,
	TypeHeartbeat:  true,
	TypeAck:        true,
	TypeError:      true,
	TypeBye:        true,
}

// Envelope is the single message shape of the session plane. Data is decoded
// lazily, only under the schema of Type (README §3.6).
type Envelope struct {
	V    int             `json:"v"`
	Type MsgType         `json:"type"`
	SID  string          `json:"sid,omitempty"`
	TID  string          `json:"tid,omitempty"`
	TS   float64         `json:"ts"`
	Data json.RawMessage `json:"data,omitempty"`
}

// NewEnvelope returns an envelope of the given type, stamped with the current
// protocol version and time.
func NewEnvelope(t MsgType) *Envelope {
	return &Envelope{
		V:    Version,
		Type: t,
		TS:   float64(time.Now().UnixMilli()) / 1000,
	}
}

// Encode serializes the envelope into the bytes carried inside a frame.
func Encode(e *Envelope) ([]byte, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	return b, nil
}

// Decode parses and validates a frame payload. The peer is untrusted: unknown
// versions and unknown message types are rejected.
func Decode(b []byte) (*Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}
	if e.V != Version {
		return nil, fmt.Errorf("unsupported protocol version %d (want %d)", e.V, Version)
	}
	if !validTypes[e.Type] {
		return nil, fmt.Errorf("unknown message type %q", e.Type)
	}
	return &e, nil
}
