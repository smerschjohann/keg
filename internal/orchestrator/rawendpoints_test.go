package orchestrator

import (
	"net"
	"testing"
	"time"
)

func TestRawEndpoints_AllowAndCheck(t *testing.T) {
	t.Parallel()
	re := newRawEndpoints()
	re.allow("Echo.Example.Test.", []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")}, []int{9000}, time.Minute)

	cases := []struct {
		name string
		addr string
		want bool
	}{
		{"first ip allowed port", "10.0.0.1:9000", true},
		{"second ip allowed port", "10.0.0.2:9000", true},
		{"wrong port pinned out", "10.0.0.1:1234", false},
		{"unknown ip", "10.9.9.9:9000", false},
		{"missing port", "10.0.0.1", false},
		{"garbage", "", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := re.check(tt.addr); got != tt.want {
				t.Fatalf("check(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

func TestRawEndpoints_TTLExpiry(t *testing.T) {
	t.Parallel()
	current := time.Unix(1700000000, 0)
	re := newRawEndpoints()
	re.now = func() time.Time { return current }

	re.allow("echo.test", []net.IP{net.ParseIP("10.0.0.7")}, []int{443}, 30*time.Second)
	if !re.check("10.0.0.7:443") {
		t.Fatal("fresh entry must pass")
	}

	current = current.Add(31 * time.Second)
	if re.check("10.0.0.7:443") {
		t.Fatal("expired entry must fail")
	}

	// Lazy eviction: the expired entry is gone, re-allowing the same IP
	// starts a fresh lifetime instead of resurrecting the stale one.
	re.allow("echo.test", []net.IP{net.ParseIP("10.0.0.7")}, []int{443}, 30*time.Second)
	current = current.Add(10 * time.Second)
	if !re.check("10.0.0.7:443") {
		t.Fatal("re-allowed entry must pass with fresh lifetime")
	}
}

func TestRawEndpoints_ExpiryIsPerEntry(t *testing.T) {
	t.Parallel()
	current := time.Unix(1700000000, 0)
	re := newRawEndpoints()
	re.now = func() time.Time { return current }

	re.allow("short.test", []net.IP{net.ParseIP("10.0.0.1")}, []int{1}, 10*time.Second)
	current = current.Add(5 * time.Second)
	re.allow("long.test", []net.IP{net.ParseIP("10.0.0.2")}, []int{2}, time.Hour)
	current = current.Add(6 * time.Second)

	if re.check("10.0.0.1:1") {
		t.Fatal("short entry must expire")
	}
	if !re.check("10.0.0.2:2") {
		t.Fatal("long entry must survive")
	}
}

func TestRawEndpoints_ZeroTTLRejected(t *testing.T) {
	t.Parallel()
	re := newRawEndpoints()
	re.allow("x.test", []net.IP{net.ParseIP("10.0.0.1")}, []int{1}, 0)
	if re.check("10.0.0.1:1") {
		t.Fatal("entry without positive TTL must never be stored live")
	}
}
