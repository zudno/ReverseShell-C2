// Package protocol implements the session-plane wire protocol shared by the
// agent and the teamserver: length-prefixed JSON envelopes (README §4).
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// DefaultMaxFrameBytes bounds a single framed message (4 MiB, README §4.1).
const DefaultMaxFrameBytes = 4 << 20

// ErrFrameTooLarge reports a frame header announcing more bytes than allowed.
// The connection must be treated as broken.
var ErrFrameTooLarge = errors.New("frame exceeds maximum size")

// WriteFrame writes payload as one length-prefixed frame: [u32 BE][payload].
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > math.MaxUint32 {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(payload))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write frame payload: %w", err)
	}
	return nil
}

// ReadFrame reads exactly one frame. It never assumes one underlying read
// equals one message: io.ReadFull accumulates until the frame is whole.
func ReadFrame(r io.Reader, maxFrame int) ([]byte, error) {
	if maxFrame <= 0 {
		maxFrame = DefaultMaxFrameBytes
	}
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read frame header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if int(n) > maxFrame {
		return nil, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, n, maxFrame)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read frame payload: %w", err)
	}
	return buf, nil
}
