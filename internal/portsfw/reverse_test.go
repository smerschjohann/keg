package portsfw

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/smerschjohann/keg/internal/config"

	"golang.ngrok.com/muxado"
)

// TestChannelF_EndToEnd tunnels a guest-side TCP connection through a real
// muxado session and the host forwarder into an upstream echo server (e.g. host-side service).
func TestChannelF_EndToEnd(t *testing.T) {
	hostEnd, guestEnd := socketpairTCP(t)
	echoAddr := echoServer(t)
	targetTCP := echoAddr.(*net.TCPAddr)

	specs := []config.ForwardHostSpec{
		{
			GuestPort:  2345,
			TargetHost: targetTCP.IP.String(),
			TargetPort: targetTCP.Port,
		},
	}

	// Host side: serves channel F, accepts streams, checks allowed specs, dials target
	hctx, hcancel := context.WithCancel(context.Background())
	defer hcancel()
	hDone := make(chan struct{})
	go func() {
		defer close(hDone)
		_ = ServeHostForwarder(hctx, muxado.Server(hostEnd, nil), specs, nil)
	}()

	// Guest side: listens on local port (simulating sandbox loopback), forwards to host session
	sess := muxado.Client(guestEnd, nil)
	defer func() { _ = sess.Close() }()

	guestLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("guest listen: %v", err)
	}
	defer func() { _ = guestLn.Close() }()

	go func() { _ = ForwardGuest(sess, guestLn, 2345) }()

	// Client inside sandbox connects to guest listener
	client, err := net.Dial("tcp", guestLn.Addr().String())
	if err != nil {
		t.Fatalf("client dial guest listener: %v", err)
	}
	defer func() { _ = client.Close() }()

	payload := []byte("hello from sandbox to host")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}

	got := readWithTimeout(t, client, len(payload))
	if string(got) != string(payload) {
		t.Errorf("echo roundtrip = %q, want %q", got, payload)
	}
}

// TestChannelF_DenyList verifies that streams requesting undeclared ports are closed
// without dialing (deny-by-default on the host forwarder).
func TestChannelF_DenyList(t *testing.T) {
	hostEnd, guestEnd := socketpairTCP(t)

	specs := []config.ForwardHostSpec{
		{
			GuestPort:  2345,
			TargetHost: "127.0.0.1",
			TargetPort: 1234,
		},
	}

	hctx, hcancel := context.WithCancel(context.Background())
	defer hcancel()
	go func() {
		_ = ServeHostForwarder(hctx, muxado.Server(hostEnd, nil), specs, nil)
	}()

	sess := muxado.Client(guestEnd, nil)
	defer func() { _ = sess.Close() }()

	stream, err := sess.Open()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer func() { _ = stream.Close() }()

	// Request undeclared guest port 9999
	var hdr [2]byte
	if err := EncodeTarget(hdr[:], 9999); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := stream.Write(hdr[:]); err != nil {
		t.Fatalf("write header: %v", err)
	}

	_ = stream.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 16)
	n, err := stream.Read(buf)
	if err == nil && n > 0 {
		t.Errorf("undeclared target got served %d bytes: %q", n, buf[:n])
	}
}

func TestFormatAndParseForwardHosts(t *testing.T) {
	specs := []config.ForwardHostSpec{
		{GuestPort: 2345, TargetHost: "127.0.0.1", TargetPort: 1234},
		{GuestPort: 5432, TargetHost: "db.internal", TargetPort: 5432},
	}

	formatted := FormatForwardHosts(specs)
	parsed, err := ParseForwardHostsEnv(formatted)
	if err != nil {
		t.Fatalf("ParseForwardHostsEnv failed: %v", err)
	}

	if len(parsed) != 2 {
		t.Fatalf("len(parsed) = %d, want 2", len(parsed))
	}
	if parsed[0] != specs[0] || parsed[1] != specs[1] {
		t.Errorf("parsed = %+v, want %+v", parsed, specs)
	}
}
