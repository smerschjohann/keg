package orchestrator

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// soOriginalDst asks the kernel for the pre-NAT destination of a socket
// redirected by iptables/nftables REDIRECT or DNAT (SOL_IP level).
const soOriginalDst = 80 // SO_ORIGINAL_DST

// originalDest recovers the original "ip:port" a redirected TCP connection
// was sent to. It returns ok=false for anything that is not a TCP conn
// with conntrack NAT information — callers treat that as fail-closed.
func originalDest(conn net.Conn) (net.IP, int, bool) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, 0, false
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return nil, 0, false
	}
	var sa [16]byte // sizeof(struct sockaddr_in)
	var serr error
	if cerr := raw.Control(func(fd uintptr) {
		saLen := uint32(len(sa))
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
			fd, syscall.SOL_IP, soOriginalDst,
			uintptr(unsafe.Pointer(&sa[0])), uintptr(unsafe.Pointer(&saLen)), 0)
		if errno != 0 {
			serr = fmt.Errorf("getsockopt(SO_ORIGINAL_DST): %w", errno)
		}
	}); cerr != nil {
		return nil, 0, false
	}
	if serr != nil {
		return nil, 0, false
	}
	return parseOriginalDest(sa[:])
}

// parseOriginalDest decodes a struct sockaddr_in as returned by
// SO_ORIGINAL_DST: family u16 native-endian, port u16 big-endian,
// IPv4 address 4 bytes. Zero addresses/ports and non-AF_INET families are
// rejected so garbage can never become an implicit allow.
func parseOriginalDest(sa []byte) (net.IP, int, bool) {
	if len(sa) < 8 {
		return nil, 0, false
	}
	family := binary.NativeEndian.Uint16(sa[0:2])
	if family != syscall.AF_INET {
		return nil, 0, false
	}
	port := int(binary.BigEndian.Uint16(sa[2:4]))
	ip := net.IP(append([]byte(nil), sa[4:8]...))
	if port == 0 || ip.IsUnspecified() {
		return nil, 0, false
	}
	return ip, port, true
}
