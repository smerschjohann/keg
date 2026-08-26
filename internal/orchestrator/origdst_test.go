package orchestrator

import (
	"net"
	"testing"
)

// sockaddr_in layout (linux): family u16, port u16 BE, addr 4 bytes.
func TestParseOriginalDest(t *testing.T) {
	t.Parallel()
	valid := []byte{
		0x02, 0x00, // AF_INET, native-endian (kernel returns host byte order)
		0x1F, 0x91, // port 8081 big-endian
		192, 0, 2, 7, // 192.0.2.7
		0x00, 0x00, 0x00, 0x00, // sin_zero padding
	}
	cases := []struct {
		name     string
		in       []byte
		wantIP   string
		wantPort int
		wantOK   bool
	}{
		{"valid sockaddr_in", valid, "192.0.2.7", 8081, true},
		{"minimal length without padding", valid[:8], "192.0.2.7", 8081, true},
		{"wrong family (AF_INET6)", append([]byte{0x0a, 0x00}, valid[2:]...), "", 0, false},
		{"family zero", append([]byte{0x00, 0x00}, valid[2:]...), "", 0, false},
		{"truncated header", valid[:3], "", 0, false},
		{"empty", nil, "", 0, false},
		{"port zero is rejected", func() []byte {
			b := append([]byte{}, valid...)
			b[2], b[3] = 0, 0
			return b
		}(), "", 0, false},
		{"zero address is rejected", func() []byte {
			b := append([]byte{}, valid...)
			b[4], b[5], b[6], b[7] = 0, 0, 0, 0
			return b
		}(), "", 0, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ip, port, ok := parseOriginalDest(tt.in)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if ip.String() != tt.wantIP || port != tt.wantPort {
				t.Fatalf("got %s:%d, want %s:%d", ip, port, tt.wantIP, tt.wantPort)
			}
		})
	}
}

func TestOriginalDestNonTCPConnFails(t *testing.T) {
	t.Parallel()
	// A non-TCP conn must yield ok=false, never panic.
	c, _ := net.Pipe()
	defer func() { _ = c.Close() }()
	if _, _, ok := originalDest(c); ok {
		t.Fatal("originalDest(net.Pipe) must fail cleanly")
	}
}
