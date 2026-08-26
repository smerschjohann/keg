package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// parsePortString accepts "3000" (guest=host) and "src:dst".
func parsePortString(s string) (guest, host int, err error) {
	parts := strings.Split(s, ":")
	switch len(parts) {
	case 1:
		guest, err = strconv.Atoi(parts[0])
		if err != nil {
			return 0, 0, fmt.Errorf("port spec %q: invalid port number", s)
		}
		return guest, guest, nil
	case 2:
		guest, err = strconv.Atoi(parts[0])
		if err != nil {
			return 0, 0, fmt.Errorf("port spec %q: invalid sandbox port", s)
		}
		host, err = strconv.Atoi(parts[1])
		if err != nil {
			return 0, 0, fmt.Errorf("port spec %q: invalid host port", s)
		}
		return guest, host, nil
	default:
		return 0, 0, fmt.Errorf("port spec %q: want \"<port>\" or \"<sandbox>:<host>\"", s)
	}
}

// ParsePublishFlag parses a Docker/Podman compatible port publishing specification
// (e.g. "8080", "8080:80", ":8080:8080", "127.0.0.1:8080:80", ":8080", "127.0.0.1::8080",
// "8080/tcp", "[::1]:8080:80"). Host binding is restricted to loopback interfaces
// (127.0.0.1, localhost, ::1, 0.0.0.0 per THREAT_MODEL §5.8).
func ParsePublishFlag(s string) (PortSpec, error) {
	if s == "" {
		return PortSpec{}, fmt.Errorf("empty port spec")
	}

	// Strip and validate protocol suffix (e.g. "/tcp")
	raw := s
	if idx := strings.LastIndex(raw, "/"); idx != -1 {
		proto := strings.ToLower(raw[idx+1:])
		if proto != "tcp" {
			return PortSpec{}, fmt.Errorf("port spec %q: only tcp is supported", s)
		}
		raw = raw[:idx]
	}

	if raw == "" {
		return PortSpec{}, fmt.Errorf("port spec %q: empty port after protocol", s)
	}

	var hostIP string
	portPart := raw

	// Handle bracketed IPv6: [::1]:8080:80 or [::1]::80 or [::1]:80
	if strings.HasPrefix(raw, "[") {
		closeIdx := strings.Index(raw, "]")
		if closeIdx == -1 {
			return PortSpec{}, fmt.Errorf("port spec %q: missing closing bracket in IPv6 address", s)
		}
		hostIP = raw[1:closeIdx]
		rest := raw[closeIdx+1:]
		if rest != "" && !strings.HasPrefix(rest, ":") {
			return PortSpec{}, fmt.Errorf("port spec %q: invalid port spec after IPv6 address", s)
		}
		portPart = strings.TrimPrefix(rest, ":")
	}

	// Validate hostIP if present
	if hostIP != "" {
		if !isAllowedHostIP(hostIP) {
			return PortSpec{}, fmt.Errorf("port spec %q: invalid host IP %q: keg only binds on loopback (127.0.0.1)", s, hostIP)
		}
	}

	parts := strings.Split(portPart, ":")
	var guestPort, hostPort int
	var isDynamic bool

	if hostIP != "" {
		switch len(parts) {
		case 1:
			g, err := parsePortNum(parts[0], s, "sandbox")
			if err != nil {
				return PortSpec{}, err
			}
			guestPort = g
			isDynamic = true
		case 2:
			if parts[0] == "" || parts[0] == "0" {
				isDynamic = true
			} else {
				h, err := parsePortNum(parts[0], s, "host")
				if err != nil {
					return PortSpec{}, err
				}
				hostPort = h
			}
			g, err := parsePortNum(parts[1], s, "sandbox")
			if err != nil {
				return PortSpec{}, err
			}
			guestPort = g
		default:
			return PortSpec{}, fmt.Errorf("port spec %q: invalid port spec", s)
		}
	} else {
		switch len(parts) {
		case 1:
			g, err := parsePortNum(parts[0], s, "sandbox")
			if err != nil {
				return PortSpec{}, err
			}
			guestPort = g
			hostPort = g
		case 2:
			if parts[0] == "" || parts[0] == "0" {
				g, err := parsePortNum(parts[1], s, "sandbox")
				if err != nil {
					return PortSpec{}, err
				}
				guestPort = g
				isDynamic = true
			} else if isIPOrHost(parts[0]) {
				if !isAllowedHostIP(parts[0]) {
					return PortSpec{}, fmt.Errorf("port spec %q: invalid host IP %q: keg only binds on loopback (127.0.0.1)", s, parts[0])
				}
				g, err := parsePortNum(parts[1], s, "sandbox")
				if err != nil {
					return PortSpec{}, err
				}
				guestPort = g
				isDynamic = true
			} else {
				h, err := parsePortNum(parts[0], s, "host")
				if err != nil {
					return PortSpec{}, err
				}
				g, err := parsePortNum(parts[1], s, "sandbox")
				if err != nil {
					return PortSpec{}, err
				}
				hostPort = h
				guestPort = g
			}
		case 3:
			ip := parts[0]
			if ip != "" && !isAllowedHostIP(ip) {
				return PortSpec{}, fmt.Errorf("port spec %q: invalid host IP %q: keg only binds on loopback (127.0.0.1)", s, ip)
			}
			if parts[1] == "" || parts[1] == "0" {
				isDynamic = true
			} else {
				h, err := parsePortNum(parts[1], s, "host")
				if err != nil {
					return PortSpec{}, err
				}
				hostPort = h
			}
			g, err := parsePortNum(parts[2], s, "sandbox")
			if err != nil {
				return PortSpec{}, err
			}
			guestPort = g
		default:
			return PortSpec{}, fmt.Errorf("port spec %q: invalid port spec", s)
		}
	}

	return PortSpec{
		Guest:   guestPort,
		Host:    hostPort,
		Dynamic: isDynamic,
	}, nil
}

func parsePortNum(p, orig, kind string) (int, error) {
	n, err := strconv.Atoi(p)
	if err != nil {
		return 0, fmt.Errorf("port spec %q: invalid %s port %q", orig, kind, p)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port spec %q: %s port %d out of range 1..65535", orig, kind, n)
	}
	return n, nil
}

func isAllowedHostIP(ipStr string) bool {
	if ipStr == "" || ipStr == "localhost" {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

func isIPOrHost(s string) bool {
	if s == "localhost" {
		return true
	}
	return net.ParseIP(s) != nil
}

// ExpandPath resolves a leading ~ and $VAR/${VAR} references against the
// environment. Unset variables are a hard error — silent empty expansion
// would hide misconfiguration.
func ExpandPath(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand %q: %w", path, err)
		}
		path = home + strings.TrimPrefix(path, "~")
	}

	var out strings.Builder
	for i := 0; i < len(path); {
		c := path[i]
		if c != '$' {
			out.WriteByte(c)
			i++
			continue
		}
		rest := path[i+1:]
		var name string
		switch {
		case strings.HasPrefix(rest, "{"):
			end := strings.IndexByte(rest, '}')
			if end < 0 {
				return "", fmt.Errorf("expand %q: unclosed ${", path)
			}
			name = rest[1:end]
			i += 1 + end + 1
		default:
			j := 0
			for j < len(rest) && isNameChar(rest[j]) {
				j++
			}
			if j == 0 {
				// literal '$'
				out.WriteByte('$')
				i++
				continue
			}
			name = rest[:j]
			i += 1 + j
		}
		val, ok := os.LookupEnv(name)
		if !ok {
			return "", fmt.Errorf("expand %q: environment variable %s is not set", path, name)
		}
		out.WriteString(val)
	}
	return out.String(), nil
}

func isNameChar(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}
