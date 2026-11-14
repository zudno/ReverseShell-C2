package protocol

import (
	"strings"
	"testing"
)

func TestRegisterMACIsDeterministic(t *testing.T) {
	info := AgentInfo{Nonce: "n1", Hostname: "lab-01"}
	m1 := RegisterMAC("secret", info, 1762940000.123)
	m2 := RegisterMAC("secret", info, 1762940000.123)
	if m1 == "" || m1 != m2 {
		t.Fatalf("mac not deterministic: %q vs %q", m1, m2)
	}
	if RegisterMAC("other-token", info, 1762940000.123) == m1 {
		t.Fatal("token must change the mac")
	}
	if RegisterMAC("secret", AgentInfo{Nonce: "n2", Hostname: "lab-01"}, 1762940000.123) == m1 {
		t.Fatal("nonce must change the mac")
	}
	if RegisterMAC("secret", info, 1762940000.124) == m1 {
		t.Fatal("ts must change the mac")
	}
}

func TestValidRegisterMAC(t *testing.T) {
	ts := 1762940000.123
	info := AgentInfo{Nonce: "n1", Hostname: "lab-01"}
	info.Auth = RegisterMAC("secret", info, ts)

	if !ValidRegisterMAC("secret", info, ts, info.Auth) {
		t.Fatal("valid mac rejected")
	}
	if ValidRegisterMAC("wrong-token", info, ts, info.Auth) {
		t.Fatal("wrong token accepted")
	}
	tampered := info
	tampered.Auth = strings.Repeat("0", len(info.Auth))
	if ValidRegisterMAC("secret", tampered, ts, tampered.Auth) {
		t.Fatal("tampered mac accepted")
	}
	if ValidRegisterMAC("secret", AgentInfo{Nonce: "n1", Hostname: "lab-01"}, ts, "") {
		t.Fatal("empty mac accepted")
	}
}
