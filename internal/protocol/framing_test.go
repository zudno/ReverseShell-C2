package protocol

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte(`{"hello":"world"}`)
	if err := WriteFrame(&buf, payload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := ReadFrame(&buf, 0)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round trip = %q, want %q", got, payload)
	}
}

func TestReadFrameReassemblesPartialReads(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(&buf, []byte("defgh")); err != nil {
		t.Fatal(err)
	}
	r := &oneByteReader{data: buf.Bytes()}
	for _, want := range []string{"abc", "defgh"} {
		got, err := ReadFrame(r, 0)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if string(got) != want {
			t.Fatalf("frame = %q, want %q", got, want)
		}
	}
}

func TestReadFrameRejectsOversized(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, make([]byte, 1024)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(bytes.NewReader(buf.Bytes()), 16); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("err = %v, want ErrFrameTooLarge", err)
	}
}

func TestReadFrameRejectsTruncated(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	if _, err := ReadFrame(bytes.NewReader(data[:2]), 0); err == nil {
		t.Fatal("truncated header: expected error")
	}
	if _, err := ReadFrame(bytes.NewReader(data[:8]), 0); err == nil {
		t.Fatal("truncated payload: expected error")
	}
}

// oneByteReader returns at most one byte per Read to force reassembly.
type oneByteReader struct {
	data []byte
	off  int
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	p[0] = r.data[r.off]
	r.off++
	return 1, nil
}
