package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
)

// RegisterMAC returns the hex HMAC-SHA256 over nonce|hostname|ts keyed by
// the shared implant token (README §9.2). The token itself never travels
// on the wire.
func RegisterMAC(token string, info AgentInfo, ts float64) string {
	mac := hmac.New(sha256.New, []byte(token))
	fmt.Fprintf(mac, "%s|%s|%s", info.Nonce, info.Hostname, strconv.FormatFloat(ts, 'f', -1, 64))
	return hex.EncodeToString(mac.Sum(nil))
}

// ValidRegisterMAC verifies a REGISTER's auth field in constant time.
func ValidRegisterMAC(token string, info AgentInfo, ts float64, got string) bool {
	if got == "" {
		return false
	}
	want := RegisterMAC(token, info, ts)
	return hmac.Equal([]byte(want), []byte(got))
}
