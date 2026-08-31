package orchestrator

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/smerschjohann/keg/internal/config"
)

// DefaultRawCorrelationTTL bounds how long a resolved IP may act for the
// name it came from. Deliberately short: a reused IP must not inherit an
// old name's raw-TCP permission.
const DefaultRawCorrelationTTL = 30 * time.Second

// rawEndpoints correlates resolved IPs back to allowed tcp_endpoints
// (name + pinned ports). Populated by the DNS forwarding path; consulted
// by the proxy for IP-literal CONNECT targets. Entries expire after their
// TTL (checked lazily) so stale correlations cannot accumulate.
type rawEndpoints struct {
	mu   sync.Mutex
	byIP map[string]rawEntry
	// now is injectable so tests can advance time deterministically.
	now func() time.Time
}

type rawEntry struct {
	host      string
	ports     []int
	expiresAt time.Time
}

func newRawEndpoints() *rawEndpoints {
	return &rawEndpoints{byIP: map[string]rawEntry{}, now: time.Now}
}

// allow records ip→(host, ports) for ttl. A non-positive ttl rejects the
// entry outright — an unbounded correlation would outlive its DNS basis.
func (r *rawEndpoints) allow(host string, ips []net.IP, ports []int, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	expires := r.now().Add(ttl)
	for _, ip := range ips {
		r.byIP[ip.String()] = rawEntry{host: h, ports: ports, expiresAt: expires}
	}
}

// check reports whether "ip:port" matches a live correlation. Expired
// entries are evicted on sight.
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
	if !r.now().Before(entry.expiresAt) {
		delete(r.byIP, ip)
		return false
	}
	for _, p := range entry.ports {
		if fmt.Sprint(p) == port {
			return true
		}
	}
	return false
}

// resolveHost returns the correlated hostname for ip, if a live correlation exists.
func (r *rawEndpoints) resolveHost(ip string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.byIP[ip]
	if !ok {
		return ""
	}
	if !r.now().Before(entry.expiresAt) {
		delete(r.byIP, ip)
		return ""
	}
	return entry.host
}

// rawCfg bundles the DNS policy with the raw-TCP endpoint allowlist.
type rawCfg struct {
	DNSConfig
	Endpoints []config.TCPEndpoint
}
