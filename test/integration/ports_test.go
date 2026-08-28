//go:build integration

package integration

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/orchestrator"
	"github.com/smerschjohann/keg/internal/portsfw"

	"golang.ngrok.com/muxado"
)

// TestSandboxPortBackChannel is the WP-M4 §6.4 DoD test ("Playwright-
// Workflow"): dev servers run inside the sandbox, the host reaches them on
// 127.0.0.1 through channel E. The dynamic entry proves collision-free
// allocation plus KEG_PORT_<NAME> export; the static entry proves the
// src:dst mapping.
func TestSandboxPortBackChannel(t *testing.T) {
	dir := t.TempDir()

	// Reserve the dynamic host port up front (same mechanism as
	// buildRunPlan): binding :0 IS the reservation.
	resolved, err := portsfw.Resolve(
		[]config.PortSpec{
			{Name: "dev-server", Guest: 8080, Dynamic: true},
			{Guest: 3000, Host: 3000},
		},
		func(hostIP string) (*net.Listener, error) {
			var lc net.ListenConfig
			if hostIP == "" {
				hostIP = "127.0.0.1"
			}
			ln, err := lc.Listen(context.Background(), "tcp", net.JoinHostPort(hostIP, "0"))
			if err != nil {
				return nil, err
			}
			return &ln, nil
		},
	)
	if err != nil {
		t.Fatalf("resolve ports: %v", err)
	}
	dyn := resolved[0]

	script := `
socat -T2 TCP-LISTEN:8080,reuseaddr EXEC:cat &
socat -T2 TCP-LISTEN:3000,reuseaddr EXEC:cat &
echo "DYN:$KEG_PORT_DEV_SERVER"
wait
`
	var out strings.Builder
	plan, err := planFor(dir, t.TempDir(), orchestrator.OverlayPlain,
		[]string{"/bin/sh", "-c", script})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	plan.Stdout = &out
	plan.Stderr = &out

	// Mirror buildRunPlan's env wiring (the harness builds plans directly).
	for k, v := range portsfw.PortEnv(resolved) {
		plan.EnvSet[k] = v
	}
	plan.EnvSet[orchestrator.EnvPortsForward] = portsfw.FormatAllowed(resolved)

	sb, err := orchestrator.Launch(t.Context(), plan)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer sb.Close()
	if err := sb.StartPortsForward(resolved); err != nil {
		t.Fatalf("start ports forward: %v", err)
	}

	// Host clients hit the loopback listeners; each connection lands on the
	// corresponding sandbox loopback service.
	echoRoundtrip(t, dyn.Listener.Addr().String(), []byte("via-dynamic-entry"))
	echoRoundtrip(t, "127.0.0.1:3000", []byte("via-static-entry"))

	code, err := sb.Wait()
	if err != nil {
		t.Fatalf("wait: %v\noutput:\n%s", err, out.String())
	}
	if code != 0 {
		t.Fatalf("sandbox exited %d:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "DYN:"+strconv.Itoa(dyn.HostPort)) {
		t.Errorf("sandbox did not see exported port var:\n%s", out.String())
	}
}

// TestInvariant_PortChannelGuestDenyList pins THREAT_MODEL §5.8 end-to-end:
// a host-side stream naming an UNdeclared target is closed by the guest
// forwarder without any dial — even though the channel itself is live.
func TestInvariant_PortChannelGuestDenyList(t *testing.T) {
	dir := t.TempDir()

	resolved, err := portsfw.Resolve(
		[]config.PortSpec{{Guest: 3000, Host: 3000}},
		nil,
	)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// The sandbox just idles long enough for the probe; the guest
	// forwarder runs because the marker names only port 3000.
	script := `sleep 8`
	plan, err := planFor(dir, t.TempDir(), orchestrator.OverlayPlain,
		[]string{"/bin/sh", "-c", script})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	plan.EnvSet[orchestrator.EnvPortsForward] = portsfw.FormatAllowed(resolved)

	sb, err := orchestrator.Launch(t.Context(), plan)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer sb.Close()
	if err := sb.StartPortsForward(resolved); err != nil {
		t.Fatalf("start ports forward: %v", err)
	}

	// Raw host-side session on channel E: request undeclared target 9999.
	file := sb.Channel(orchestrator.FDPorts)
	if file == nil {
		t.Fatal("channel E not available")
	}
	sess := muxado.Server(file, nil)
	defer sess.Close() // #nosec G307 -- test cleanup
	stream, err := sess.Open()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close() // #nosec G307 -- test cleanup
	var hdr [2]byte
	if err := portsfw.EncodeTarget(hdr[:], 9999); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := stream.Write(hdr[:]); err != nil {
		t.Fatalf("write header: %v", err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	n, err := stream.Read(buf)
	if err == nil && n > 0 {
		t.Errorf("undeclared target got served %d bytes: %q", n, buf[:n])
	}
	// EOF (or timeout-with-zero-bytes) means the guest closed the stream
	// without dialing — deny-by-default held.
}

// TestHostPortForwarding_SSHStyle verifies channel F (SSH -L style host forwarding):
// a service runs on the host, the sandbox connects to 127.0.0.1:<guest_port>, and
// the host forwarder tunnels the connection to the host target.
func TestHostPortForwarding_SSHStyle(t *testing.T) {
	dir := t.TempDir()

	// 1. Start a host-side TCP echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("host echo listen: %v", err)
	}
	defer echoLn.Close()

	hostPort := echoLn.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	forwardSpecs := []config.ForwardHostSpec{
		{GuestPort: 4567, TargetHost: "127.0.0.1", TargetPort: hostPort},
	}

	// 2. Sandbox connects to 127.0.0.1:4567 and expects echo
	script := `
sleep 1
python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', 4567))
s.sendall(b'test-payload-via-channel-f')
data = s.recv(1024).decode()
print('GOT:' + data)
s.close()
"
`
	var out strings.Builder
	plan, err := planFor(dir, t.TempDir(), orchestrator.OverlayPlain,
		[]string{"/bin/sh", "-c", script})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	plan.Stdout = &out
	plan.Stderr = &out
	plan.ForwardHosts = forwardSpecs
	plan.EnvSet[orchestrator.EnvForwardHosts] = portsfw.FormatForwardHosts(forwardSpecs)

	sb, err := orchestrator.Launch(t.Context(), plan)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer sb.Close()

	if err := sb.StartHostForward(forwardSpecs); err != nil {
		t.Fatalf("start host forward: %v", err)
	}

	code, err := sb.Wait()
	if err != nil {
		t.Fatalf("wait: %v\noutput:\n%s", err, out.String())
	}
	if code != 0 {
		t.Fatalf("sandbox exited %d:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "test-payload-via-channel-f") {
		t.Errorf("sandbox output did not contain echo:\n%s", out.String())
	}
}

// TestInvariant_HostForwardDenyList pins THREAT_MODEL §5.8:
// host forwarder rejects any stream requesting an undeclared guest port target.
func TestInvariant_HostForwardDenyList(t *testing.T) {
	dir := t.TempDir()

	forwardSpecs := []config.ForwardHostSpec{
		{GuestPort: 4567, TargetHost: "127.0.0.1", TargetPort: 1234},
	}

	script := `sleep 8`
	plan, err := planFor(dir, t.TempDir(), orchestrator.OverlayPlain,
		[]string{"/bin/sh", "-c", script})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	plan.ForwardHosts = forwardSpecs
	plan.EnvSet[orchestrator.EnvForwardHosts] = portsfw.FormatForwardHosts(forwardSpecs)

	sb, err := orchestrator.Launch(t.Context(), plan)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer sb.Close()

	if err := sb.StartHostForward(forwardSpecs); err != nil {
		t.Fatalf("start host forward: %v", err)
	}

	file := sb.Channel(orchestrator.FDHostForward)
	if file == nil {
		t.Fatal("channel F not available")
	}
	sess := muxado.Client(file, nil)
	defer sess.Close()

	stream, err := sess.Open()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer stream.Close()

	// Request undeclared port 9999
	var hdr [2]byte
	if err := portsfw.EncodeTarget(hdr[:], 9999); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := stream.Write(hdr[:]); err != nil {
		t.Fatalf("write: %v", err)
	}

	_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	n, err := stream.Read(buf)
	if err == nil && n > 0 {
		t.Errorf("undeclared target got served %d bytes: %q", n, buf[:n])
	}
}

func echoRoundtrip(t *testing.T, addr string, payload []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("host dial %s: %v", addr, err)
	}
	defer conn.Close() // #nosec G307 -- test cleanup
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write %s: %v", addr, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo from %s: %v", addr, err)
	}
	if string(got) != string(payload) {
		t.Errorf("echo from %s = %q, want %q", addr, got, payload)
	}
}
