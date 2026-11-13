package protocol

import (
	"encoding/json"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	env := NewEnvelope(TypeTask)
	env.SID = "b3f1"
	env.TID = "77c2"
	env.Data = json.RawMessage(`{"kind":"shell","args":{"cmd":"whoami"}}`)

	b, err := Encode(env)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.V != Version || got.Type != TypeTask || got.SID != env.SID || got.TID != env.TID {
		t.Fatalf("decoded = %+v", got)
	}
	var spec TaskSpec
	if err := json.Unmarshal(got.Data, &spec); err != nil {
		t.Fatalf("data decode: %v", err)
	}
	if spec.Kind != KindShell {
		t.Fatalf("kind = %q", spec.Kind)
	}
}

func TestDecodeRejectsUnknownType(t *testing.T) {
	if _, err := Decode([]byte(`{"v":1,"type":"NOPE","ts":1}`)); err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestDecodeRejectsWrongVersion(t *testing.T) {
	if _, err := Decode([]byte(`{"v":99,"type":"TASK","ts":1}`)); err == nil {
		t.Fatal("expected error for wrong version")
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	if _, err := Decode([]byte(`not-json`)); err == nil {
		t.Fatal("expected error for garbage payload")
	}
}
