package runner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"

	"github.com/smerschjohann/keg/internal/frame"
)

// SocketPath is the filesystem location of the delegation socket inside
// the sandbox (CONCEPT.md §3). The guest bridge binds it; the delegate
// client connects to it. Package-level var so in-process tests can point
// it at a temporary location.
var SocketPath = "/run/keg/runner.sock"

// Exec runs one whitelisted job over conn and streams its output to the
// given writers. The returned int is always a valid process exit code:
// the job's own code verbatim, CodeRejected (126) for whitelist denials
// and CodeProtocolError (125) for transport/protocol problems. Diagnostics
// go to stderr, never stdout.
func Exec(conn io.ReadWriteCloser, argv []string, dir string, stdout, stderr io.Writer) int {
	defer func() { _ = conn.Close() }()

	req := JobRequest{ArgvB64: EncodeStrings(argv), Dir: dir}
	if err := frame.WriteFrame(conn, EncodeRequest(req)); err != nil {
		return fail(stderr, "keg delegate: send request: %v", err)
	}
	for {
		payload, err := frame.ReadFrame(conn)
		if err != nil {
			return fail(stderr, "keg delegate: %v", err)
		}
		var ev Event
		if jsonErr := json.Unmarshal(payload, &ev); jsonErr != nil {
			return fail(stderr, "keg delegate: malformed event: %v", jsonErr)
		}
		switch ev.Type {
		case EventStdout, EventStderr:
			data, decErr := base64.StdEncoding.DecodeString(ev.Data)
			if decErr != nil {
				return fail(stderr, "keg delegate: corrupt %s chunk", ev.Type)
			}
			target := stderr
			if ev.Type == EventStdout {
				target = stdout
			}
			if _, werr := target.Write(data); werr != nil {
				return fail(stderr, "keg delegate: write output: %v", werr)
			}
		case EventExit:
			return ev.Code
		case EventDenied:
			_, _ = fmt.Fprintf(stderr, "keg delegate: declined: %s\n", ev.Message)
			return CodeRejected
		case EventError:
			_, _ = fmt.Fprintf(stderr, "keg delegate: error: %s\n", ev.Message)
			return CodeProtocolError
		default:
			return fail(stderr, "keg delegate: unknown event type %q", ev.Type)
		}
	}
}

func fail(stderr io.Writer, format string, args ...any) int {
	_, _ = fmt.Fprintf(stderr, format+"\n", args...)
	return CodeProtocolError
}

// Dial connects to the guest-side runner socket; CodeNoRunner results when
// the socket is missing (no delegated_tasks configured).
func Dial() (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(context.Background(), "unix", SocketPath)
	if err != nil {
		return nil, fmt.Errorf("runner socket %s: %w", SocketPath, err)
	}
	return conn, nil
}
