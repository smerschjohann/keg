package orchestrator

import (
	"encoding/binary"
)

// ParseSNI extracts the server_name extension from a TLS ClientHello
// contained in the peeked bytes. It returns ok=false for anything that is
// not a parseable ClientHello with an SNI hostname — callers treat that as
// deny-by-default (fail-closed, including future ECH handshakes).
//
// Bounds-checked throughout; never panics on attacker-controlled input.
func ParseSNI(data []byte) (hostname string, ok bool) {
	// TLS record header
	if len(data) < 5 || data[0] != 0x16 { // handshake content type
		return "", false
	}
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	if recLen < 4 || len(data) < 5+recLen {
		return "", false
	}
	hs := data[5 : 5+recLen]
	if hs[0] != 0x01 { // client_hello
		return "", false
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if hsLen+4 > len(hs) {
		return "", false
	}
	body := hs[4 : 4+hsLen]

	// version(2) + random(32)
	p := 34
	if len(body) < p {
		return "", false
	}
	// session id
	if p+1 > len(body) {
		return "", false
	}
	p += 1 + int(body[p])
	// cipher suites
	if p+2 > len(body) {
		return "", false
	}
	p += 2 + int(binary.BigEndian.Uint16(body[p:p+2]))
	// compression methods
	if p+1 > len(body) {
		return "", false
	}
	p += 1 + int(body[p])
	// extensions
	if p+2 > len(body) {
		return "", false
	}
	extTotal := int(binary.BigEndian.Uint16(body[p : p+2]))
	p += 2
	if extTotal > len(body)-p {
		extTotal = len(body) - p
	}
	end := p + extTotal

	for p+4 <= end {
		extType := binary.BigEndian.Uint16(body[p : p+2])
		extLen := int(binary.BigEndian.Uint16(body[p+2 : p+4]))
		p += 4
		if p+extLen > end {
			return "", false
		}
		if extType == 0x0000 && extLen >= 5 {
			listLen := int(binary.BigEndian.Uint16(body[p : p+2]))
			q := p + 2
			if listLen > extLen-2 || q+listLen > end {
				return "", false
			}
			for q+3 <= p+2+listLen {
				nameType := body[q]
				nameLen := int(binary.BigEndian.Uint16(body[q+1 : q+3]))
				q += 3
				if nameType != 0 || q+nameLen > p+2+listLen {
					break
				}
				return string(body[q : q+nameLen]), true
			}
		}
		p += extLen
	}
	return "", false
}
