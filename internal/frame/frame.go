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

// WriteFrame writes len(b) as a 2-byte big-endian prefix followed by b.
func WriteFrame(w io.Writer, b []byte) error {
	if len(b) > MaxSize {
		return fmt.Errorf("frame: payload %d bytes exceeds %d limit", len(b), MaxSize)
	}
	var head [2]byte
	binary.BigEndian.PutUint16(head[:], uint16(len(b))) // #nosec G115 -- bounded by MaxSize check above
	if _, err := w.Write(head[:]); err != nil {
		return fmt.Errorf("frame: write header: %w", err)
	}
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("frame: write payload: %w", err)
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
