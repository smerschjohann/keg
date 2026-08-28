// Package portsfw implements the port back-channel (channel E,
// CONCEPT.md §4.9): declared sandbox ports are exposed on the HOST loopback
// only. Host clients connect to 127.0.0.1:<host>; every accepted connection
// is carried as one muxado stream to the guest forwarder, which dials the
// target on the sandbox loopback.
//
// Security model (THREAT_MODEL §5.8): traffic direction is inbound — the
// sandbox can only accept what the forwarder brings in, answers return
// exclusively to the connecting host client. The guest refuses targets
// outside its declared list (deny-by-default); host-side binding is
// 127.0.0.1 only.
package portsfw

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/smerschjohann/keg/internal/config"
)

// ResolvedPort is one port back-channel entry with its final host port
// (dynamic entries carry the allocated value). Listener holds the
// pre-bound host listener for dynamic entries — the binding IS the port
// reservation, so no second process can steal the port between resolve
// and serve; tests may leave it nil (static entries bind at start).
type ResolvedPort struct {
	Name     string // optional; enables KEG_PORT_<NAME>
	HostIP   string // IP to bind on host (defaults to 127.0.0.1)
	Guest    int    // port inside the sandbox
	HostPort int    // port on the host
	Listener net.Listener
}

// Resolve turns parsed specs into concrete port entries. alloc supplies a
// pre-bound listener for each dynamic spec (binding :0 up front makes the
// allocation collision-free: the listener IS the reservation).
func Resolve(specs []config.PortSpec, alloc func(hostIP string) (*net.Listener, error)) ([]ResolvedPort, error) {
	out := make([]ResolvedPort, 0, len(specs))
	for _, s := range specs {
		hostIP := s.HostIP
		if hostIP == "" {
			hostIP = "127.0.0.1"
		}
		if !s.Dynamic {
			out = append(out, ResolvedPort{Name: s.Name, HostIP: hostIP, Guest: s.Guest, HostPort: s.Host})
			continue
		}
		if alloc == nil {
			return nil, fmt.Errorf("allocate dynamic port %q: no allocator provided", s.Name)
		}
		ln, err := alloc(hostIP)
		if err != nil {
			return nil, fmt.Errorf("allocate dynamic port %q: %w", s.Name, err)
		}
		addr, ok := (*ln).Addr().(*net.TCPAddr)
		if !ok {
			return nil, fmt.Errorf("allocate dynamic port %q: listener address %T is not TCP", s.Name, (*ln).Addr())
		}
		out = append(out, ResolvedPort{Name: s.Name, HostIP: hostIP, Guest: s.Guest, HostPort: addr.Port, Listener: *ln})
	}
	return out, nil
}

// PortEnv returns the sandbox environment entries exporting allocated host
// ports: KEG_PORT_<NAME> for every named entry (names sanitized to
// [A-Z0-9_] so shells can reference them; CONCEPT.md §4.9 uses a dash in
// its example, which would be unparseable as $VAR). Unnamed entries export
// nothing.
func PortEnv(ports []ResolvedPort) map[string]string {
	env := make(map[string]string)
	for _, p := range ports {
		if p.Name == "" {
			continue
		}
		env["KEG_PORT_"+sanitize(p.Name)] = strconv.Itoa(p.HostPort)
	}
	return env
}

// sanitize maps arbitrary names onto shell-safe variable characters:
// uppercase, non-alphanumerics become underscores.
func sanitize(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 32)
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// EncodeTarget writes the guest target port as a 2-byte big-endian header
// (the per-stream framing of channel E). Ports outside 1..65535 are
// rejected so the guest side can never be talked into dialing port 0 or
// oversized values.
func EncodeTarget(buf []byte, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d out of range 1..65535", port)
	}
	buf[0] = byte(port >> 8)   //nolint:gosec // G115: validated 1..65535 above, high bits fit
	buf[1] = byte(port & 0xff) //nolint:gosec // G115: masked to one byte
	return nil
}

// DecodeTarget reads one EncodeTarget header.
func DecodeTarget(r io.Reader) (int, error) {
	var buf [2]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, fmt.Errorf("read target port header: %w", err)
	}
	port := int(buf[0])<<8 | int(buf[1])
	if port == 0 {
		return 0, fmt.Errorf("target port header: zero port")
	}
	return port, nil
}

// FormatAllowed renders the guest-side allowlist marker ("3000,5432").
func FormatAllowed(ports []ResolvedPort) string {
	ps := make([]string, len(ports))
	for i, p := range ports {
		ps[i] = strconv.Itoa(p.Guest)
	}
	return strings.Join(ps, ",")
}

// ParseAllowed parses the allowlist marker into a set. Any malformed part
// fails closed (empty result + error), never a partial allowlist.
func ParseAllowed(marker string) (map[int]bool, error) {
	allowed := make(map[int]bool)
	if marker == "" {
		return allowed, nil
	}
	for _, part := range strings.Split(marker, ",") {
		port, err := strconv.Atoi(part)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid KEG_PORTS marker %q", marker)
		}
		allowed[port] = true
	}
	return allowed, nil
}
