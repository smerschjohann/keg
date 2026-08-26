package frame

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		payload []byte
	}{
		{"empty payload", []byte{}},
		{"single byte", []byte{0x42}},
		{"typical dns query", bytes.Repeat([]byte{0xAB}, 512)},
		{"max size", bytes.Repeat([]byte{0x7F}, 65535)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			if err := WriteFrame(&buf, tt.payload); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}
			got, err := ReadFrame(&buf)
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if !bytes.Equal(got, tt.payload) {
				t.Errorf("roundtrip mismatch: got %d bytes, want %d", len(got), len(tt.payload))
			}
		})
	}
}

func TestWriteFrame_TooLarge(t *testing.T) {
	t.Parallel()
	err := WriteFrame(&bytes.Buffer{}, make([]byte, 65536))
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("65535")) {
		t.Fatalf("WriteFrame(>64KiB) = %v, want error naming the 65535 limit", err)
	}
}

func TestReadFrame_TruncatedStream(t *testing.T) {
	t.Parallel()
	// Header announces 100 bytes, payload cut short.
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint16(100))
	buf.WriteByte(1)
	if _, err := ReadFrame(&buf); err == nil {
		t.Fatal("ReadFrame(truncated payload) = nil, want error")
	}
}

func TestReadFrame_HeaderOnlyEOF(t *testing.T) {
	t.Parallel()
	if _, err := ReadFrame(bytes.NewReader(nil)); err == nil {
		t.Fatal("ReadFrame(empty) = nil, want EOF error")
	}
}

// Two frames written sequentially are read back independently (stream
// framing, no cross-talk).
func TestSequentialFrames(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	a := []byte("first")
	b := []byte("second-frame-with-different-length")
	if err := WriteFrame(&buf, a); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(&buf, b); err != nil {
		t.Fatal(err)
	}
	for _, want := range [][]byte{a, b} {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}
