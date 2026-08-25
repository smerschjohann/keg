package config

import (
	"fmt"
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
