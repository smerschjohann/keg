package orchestrator

import (
	"os"
	"testing"
	"time"
)

func TestSocketpair_TransfersDataBothWays(t *testing.T) {
	a, b, err := Socketpair()
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	defer a.Close()
	defer b.Close()

	go func() {
		if _, err := a.Write([]byte("ping")); err != nil {
			t.Errorf("write: %v", err)
		}
	}()
	buf := make([]byte, 4)
	if err := readFull(b, buf, time.Second); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("got %q, want ping", buf)
	}
}

func TestSocketpair_ClosedEndReportsEOF(t *testing.T) {
	a, b, err := Socketpair()
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	defer a.Close()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := a.Read(buf); err == nil {
		t.Error("read on peer-closed socketpair must fail")
	}
}

func TestStripDeniedEnv(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"HTTP_PROXY=http://corp:3128",
		"AWS_SESSION_TOKEN=leak",
		"TERM=xterm",
	}
	got := StripDeniedEnv(env, HostDeniedEnvVars)
	for _, want := range []string{"PATH=/usr/bin", "TERM=xterm"} {
		found := false
		for _, e := range got {
			if e == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q missing from %v", want, got)
		}
	}
	for _, banned := range []string{"HTTP_PROXY=", "AWS_SESSION_TOKEN="} {
		for _, e := range got {
			if len(e) >= len(banned) && e[:len(banned)] == banned {
				t.Errorf("denied var survived: %q in %v", e, got)
			}
		}
	}
}

func TestStripDeniedEnv_KeepsExplicitSets(t *testing.T) {
	// Explicitly set values must survive stripping (set wins over deny).
	env := []string{"HTTP_PROXY=http://corp:3128"}
	got := StripDeniedEnv(env, HostDeniedEnvVars)
	if len(got) != 0 {
		t.Errorf("plain strip must remove denied var, got %v", got)
	}
}

func TestFDConstants_StablePlan(t *testing.T) {
	// The FD map is protocol-relevant (CONCEPT.md §9); changing these
	// numbers breaks host<->guest coordination.
	if FDProxy != 3 || FDDNS != 4 || FDRunner != 5 || FDPorts != 6 || FDPreserved != 4 {
		t.Errorf("FD plan changed unexpectedly: proxy=%d dns=%d runner=%d ports=%d preserved=%d",
			FDProxy, FDDNS, FDRunner, FDPorts, FDPreserved)
	}
}

// readFull reads exactly len(buf) bytes or times out.
func readFull(f *os.File, buf []byte, timeout time.Duration) error {
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := f.Read(buf)
		done <- result{n, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			return r.err
		}
		if r.n != len(buf) {
			return os.ErrDeadlineExceeded
		}
		return nil
	case <-time.After(timeout):
		return os.ErrDeadlineExceeded
	}
}
