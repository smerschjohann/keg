package runner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"

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

// List queries the host runner over conn for the effective whitelisted tasks
// and their descriptions.
func List(conn io.ReadWriteCloser) ([]TaskInfo, error) {
	defer func() { _ = conn.Close() }()

	if err := frame.WriteFrame(conn, EncodeRequest(JobRequest{List: true})); err != nil {
		return nil, fmt.Errorf("send list request: %w", err)
	}
	payload, err := frame.ReadFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("read list response: %w", err)
	}
	var ev Event
	if err := json.Unmarshal(payload, &ev); err != nil {
		return nil, fmt.Errorf("decode list response: %w", err)
	}
	switch ev.Type {
	case EventList:
		return ev.Tasks, nil
	case EventError:
		return nil, fmt.Errorf("%s", ev.Message)
	default:
		return nil, fmt.Errorf("unexpected event type %q", ev.Type)
	}
}

// FormatTaskList renders whitelisted tasks and raw rules in a readable table
// for humans and AI agents.
func FormatTaskList(tasks []TaskInfo) string {
	if len(tasks) == 0 {
		return "No delegated tasks configured.\n"
	}

	type row struct {
		usage string
		kind  string
		info  TaskInfo
	}
	rows := make([]row, 0, len(tasks))
	maxUsage := 0
	maxKind := 0
	for _, t := range tasks {
		var usage string
		switch t.Kind {
		case "prefix":
			usage = t.Name + " [args…]"
		case "raw":
			usage = t.Name + " <subcommand> [args…]"
		default:
			usage = t.Name
		}
		kindTag := "[" + t.Kind + "]"
		if len(usage) > maxUsage {
			maxUsage = len(usage)
		}
		if len(kindTag) > maxKind {
			maxKind = len(kindTag)
		}
		rows = append(rows, row{usage: usage, kind: kindTag, info: t})
	}

	var b strings.Builder
	b.WriteString("Allowed delegated tasks (run via 'keg delegate <task> [args...]' or 'just delegate <task> [args...]'):\n\n")
	for _, r := range rows {
		if r.info.Description != "" {
			fmt.Fprintf(&b, "  %-*s  %-*s  %s\n", maxUsage, r.usage, maxKind, r.kind, r.info.Description)
		} else {
			fmt.Fprintf(&b, "  %-*s  %s\n", maxUsage, r.usage, r.kind)
		}
		if r.info.Kind == "raw" {
			if len(r.info.Subcommands) > 0 {
				fmt.Fprintf(&b, "    subcommands: %s\n", strings.Join(r.info.Subcommands, ", "))
			}
			var opts []string
			for _, o := range r.info.OptsWithValue {
				opts = append(opts, o+" <val>")
			}
			opts = append(opts, r.info.Flags...)
			if len(opts) > 0 {
				suffix := ""
				if r.info.AllowOptValueForm {
					suffix = " (--opt=val allowed)"
				}
				fmt.Fprintf(&b, "    options:     %s%s\n", strings.Join(opts, ", "), suffix)
			}
			if len(r.info.ForbiddenArgsMatching) > 0 {
				fmt.Fprintf(&b, "    forbidden:   %s\n", strings.Join(r.info.ForbiddenArgsMatching, ", "))
			}
		}
	}
	return b.String()
}
