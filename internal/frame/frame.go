// Package frame implements the 2-byte length-prefix wire framing used by
// the egress and delegation channels (DNS per RFC 1035 §4.2.2, runner
// protocol). One frame = one message; frames are read/written sequentially
// from a byte stream.
package frame

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MaxSize is the largest frame payload: the 2-byte length prefix caps it
// at 65535 bytes (RFC 1035 DNS message limit).
const MaxSize = 65535

// WriteFrame writes len(b) as a 2-byte big-endian prefix followed by b in a
// single Write call. One call keeps a frame atomic for callers that serialize
// concurrent writers only per Write: a split header/payload write can be
// interleaved by another goroutine and corrupt the stream.
func WriteFrame(w io.Writer, b []byte) error {
	if len(b) > MaxSize {
		return fmt.Errorf("frame: payload %d bytes exceeds %d limit", len(b), MaxSize)
	}
	buf := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(b))) // #nosec G115 -- bounded by MaxSize check above
	copy(buf[2:], b)
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("frame: write: %w", err)
	}
	return nil
}

// ReadFrame reads one complete frame. io.EOF at a frame boundary propagates
// as *error wrapped EOF; a short header or payload yields a descriptive
// truncation error.
func ReadFrame(r io.Reader) ([]byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, fmt.Errorf("frame: read header: %w", err)
	}
	n := binary.BigEndian.Uint16(head[:])
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("frame: read payload (%d bytes announced): %w", n, err)
	}
	return payload, nil
}
