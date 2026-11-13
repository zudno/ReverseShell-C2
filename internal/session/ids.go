// Package session holds the session model, opaque IDs, and the concurrency-
// safe registry used by the teamserver core (README §7).
package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// NewSID returns a new opaque session id (6 random bytes, hex-encoded).
func NewSID() (string, error) { return randHex(6) }

// NewTID returns a new opaque task id (4 random bytes, hex-encoded).
func NewTID() (string, error) { return randHex(4) }

// NewNonce returns a random agent nonce used to resume sessions across
// reconnects (README §4.7).
func NewNonce() (string, error) { return randHex(8) }

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}
