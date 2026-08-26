package orchestrator

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/smerschjohann/keg/internal/config"
)

// rawEndpoints correlates resolved IPs back to allowed tcp_endpoints
// (name + pinned ports). Populated by the DNS forwarding path; consulted
// by the proxy for IP-literal CONNECT targets.
type rawEndpoints struct {
	mu   sync.Mutex
	byIP map[string]rawEntry
}

type rawEntry struct {
	host  string
	ports []int
}

func (r *rawEndpoints) allow(host string, ips []net.IP, ports []int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, ip := range ips {
		r.byIP[ip.String()] = rawEntry{host: h, ports: ports}
	}
}

func (r *rawEndpoints) check(ipPort string) bool {
	ip, port, err := net.SplitHostPort(ipPort)
	if err != nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.byIP[ip]
	if !ok {
		return false
	}
	for _, p := range entry.ports {
		if fmt.Sprint(p) == port {
			return true
		}
	}
	return false
}

// rawCfg bundles the DNS policy with the raw-TCP endpoint allowlist.
type rawCfg struct {
	DNSConfig
	Endpoints []config.TCPEndpoint
}
