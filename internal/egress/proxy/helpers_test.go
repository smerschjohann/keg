package proxy

import (
	"net"
	"runtime"
	"strconv"
)

// runtimeNumGoroutine indirection keeps the leak check testable.
func runtimeNumGoroutine() int { return runtime.NumGoroutine() }

// portOf extracts the numeric port from a "host:port" address (test helper).
func portOf(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if _, err := strconv.Atoi(port); err != nil {
		return addr
	}
	return port
}
