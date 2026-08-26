package dns

import (
	"net"
	"strings"
	"testing"
	"time"

	miek "github.com/miekg/dns"
)

// mustQuery packs a wire-format A query for name.
func mustQuery(t *testing.T, name string) []byte {
	t.Helper()
	m := new(miek.Msg)
	m.SetQuestion(miek.Fqdn(name), miek.TypeA)
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	return wire
}

// answerFields unpacks a wire response into the interesting fields.
func answerFields(t *testing.T, wire []byte) (rcode int, answers []string, authoritative bool) {
	t.Helper()
	m := new(miek.Msg)
	if err := m.Unpack(wire); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	for _, rr := range m.Answer {
		if a, ok := rr.(*miek.A); ok {
			answers = append(answers, a.A.String())
		}
	}
	return m.Rcode, answers, m.Authoritative
}

func TestResolver_HostsExact(t *testing.T) {
	t.Parallel()
	r := Resolver{
		Hosts:     map[string]string{"db.local.test": "127.0.0.1"},
		Whitelist: nil,
	}
	resp := r.HandleQuery(mustQuery(t, "db.local.test"))
	rcode, answers, auth := answerFields(t, resp)
	if rcode != miek.RcodeSuccess || len(answers) != 1 || answers[0] != "127.0.0.1" || !auth {
		t.Fatalf("hosts exact: rcode=%d answers=%v auth=%v", rcode, answers, auth)
	}
}

func TestResolver_HostsWildcardSingleLevel(t *testing.T) {
	t.Parallel()
	r := Resolver{Hosts: map[string]string{"*.svc.local.test": "10.0.0.7"}}
	resp := r.HandleQuery(mustQuery(t, "api.svc.local.test"))
	rcode, answers, _ := answerFields(t, resp)
	if rcode != miek.RcodeSuccess || len(answers) != 1 {
		t.Fatalf("wildcard match failed: %d %v", rcode, answers)
	}
	// Multi-level splat must NOT match.
	resp = r.HandleQuery(mustQuery(t, "a.b.svc.local.test"))
	if rc, _, _ := answerFields(t, resp); rc != miek.RcodeNameError {
		t.Fatalf("multi-level wildcard matched, rcode=%d", rc)
	}
}

// Hosts mappings win over the whitelist and are authoritative even when
// redirecting a well-known domain.
func TestResolver_HostsOverridesWhitelist(t *testing.T) {
	t.Parallel()
	r := Resolver{
		Hosts:     map[string]string{"proxy.golang.org": "10.9.9.9"},
		Whitelist: []string{"proxy.golang.org"},
		Upstream:  unreachableUpstream(t), // would fail loudly if contacted
	}
	resp := r.HandleQuery(mustQuery(t, "proxy.golang.org"))
	rcode, answers, _ := answerFields(t, resp)
	if rcode != miek.RcodeSuccess || len(answers) != 1 || answers[0] != "10.9.9.9" {
		t.Fatalf("hosts override broken: %d %v", rcode, answers)
	}
}

func TestResolver_WhitelistForwardsToUpstream(t *testing.T) {
	t.Parallel()
	upstream := fakeUpstream(t, map[string]string{"proxy.golang.org": "93.184.216.34"})
	r := Resolver{Whitelist: []string{"*.golang.org"}, Upstream: upstream}

	resp := r.HandleQuery(mustQuery(t, "proxy.golang.org"))
	rcode, answers, _ := answerFields(t, resp)
	if rcode != miek.RcodeSuccess || len(answers) != 1 || answers[0] != "93.184.216.34" {
		t.Fatalf("forwarded answer wrong: %d %v", rcode, answers)
	}
}

func TestResolver_DenyIsNXDOMAIN(t *testing.T) {
	t.Parallel()
	r := Resolver{Whitelist: []string{"*.golang.org"}, Upstream: unreachableUpstream(t)}
	resp := r.HandleQuery(mustQuery(t, "evil.example.com"))
	if rc, answers, _ := answerFields(t, resp); rc != miek.RcodeNameError || answers != nil {
		t.Fatalf("deny: rcode=%d answers=%v, want NXDOMAIN without answers", rc, answers)
	}
}

func TestResolver_EmptyWhitelistDeniesEverything(t *testing.T) {
	t.Parallel()
	r := Resolver{}
	resp := r.HandleQuery(mustQuery(t, "anything.org"))
	if rc, _, _ := answerFields(t, resp); rc != miek.RcodeNameError {
		t.Fatalf("empty resolver allowed a name: %d", rc)
	}
}

func TestResolver_UpstreamFailureIsServFail(t *testing.T) {
	t.Parallel()
	r := Resolver{
		Whitelist: []string{"*.golang.org"},
		Upstream:  unreachableUpstream(t),
		Timeout:   shortTimeout(),
	}
	resp := r.HandleQuery(mustQuery(t, "proxy.golang.org"))
	if rc, _, _ := answerFields(t, resp); rc != miek.RcodeServerFailure {
		t.Fatalf("upstream failure rcode=%d, want SERVFAIL", rc)
	}
}

// TestResolver_ResponseIDMatchesQuery pins RFC correctness: the response
// ID must echo the query ID (Go DNS client does this for forwarding; hosts
// and NXDOMAIN paths build responses themselves).
func TestResolver_ResponseIDMatchesQuery(t *testing.T) {
	t.Parallel()
	query := mustQuery(t, "db.local.test")
	r := Resolver{Hosts: map[string]string{"db.local.test": "127.0.0.1"}}
	resp := r.HandleQuery(query)
	qid := uint16(query[0])<<8 | uint16(query[1])
	rid := uint16(resp[0])<<8 | uint16(resp[1])
	if qid != rid {
		t.Fatalf("response id %d != query id %d", rid, qid)
	}
}

// fakeUpstream starts a UDP DNS server answering A queries from the given
// name->ip map; returns its "host:port" address.
func fakeUpstream(t *testing.T, answers map[string]string) string {
	t.Helper()
	handler := func(w miek.ResponseWriter, req *miek.Msg) {
		m := new(miek.Msg)
		m.SetReply(req)
		if len(req.Question) == 1 {
			name := strings.TrimSuffix(req.Question[0].Name, ".")
			if ip, ok := answers[name]; ok {
				rr, err := miek.NewRR(miek.Fqdn(name) + " 5 IN A " + ip)
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
		_ = w.WriteMsg(m)
	}
	server := &miek.Server{Handler: miek.HandlerFunc(handler)}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake upstream listen: %v", err)
	}
	server.PacketConn = pc // serve exactly this socket; port is ours
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = pc.Close()
		_ = server.Shutdown()
	})
	return pc.LocalAddr().String()
}

// unreachableUpstream is a closed loopback port.
func unreachableUpstream(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func shortTimeout() time.Duration { return 300 * time.Millisecond }
