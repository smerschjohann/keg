package runner

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/smerschjohann/keg/internal/frame"
)

// speakEvents sends the given events as framed JSON from the "host" side
// of a socketpair and closes the connection afterwards.
func speakEvents(t *testing.T, hostEnd io.ReadWriteCloser, events []Event) {
	t.Helper()
	go func() {
		_, _ = frame.ReadFrame(hostEnd)
		for _, ev := range events {
			b, err := json.Marshal(ev)
			if err != nil {
				return
			}
			if err := frame.WriteFrame(hostEnd, b); err != nil {
				return
			}
		}
		_ = hostEnd.Close()
	}()
}

func TestExec_MapsServerOutcomesToExitCodes(t *testing.T) {
	tests := []struct {
		name       string
		events     []Event
		argv       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{
			name:       "job exit code is returned verbatim",
			events:     []Event{{Type: EventExit, Code: 3}},
			wantCode:   3,
			wantStderr: "",
		},
		{
			name: "output chunks stream before the exit marker",
			events: []Event{
				{Type: EventStdout, Data: base64.StdEncoding.EncodeToString([]byte("line one\n"))},
				{Type: EventStderr, Data: base64.StdEncoding.EncodeToString([]byte("warn\n"))},
				{Type: EventStdout, Data: base64.StdEncoding.EncodeToString([]byte("line two\n"))},
				{Type: EventExit, Code: 0},
			},
			wantCode:   0,
			wantStdout: "line one\nline two\n",
			wantStderr: "warn\n",
		},
		{
			name:       "denial yields 126 with visible reason",
			events:     []Event{{Type: EventDenied, Message: `"git push" is not a whitelisted "git" subcommand`}},
			wantCode:   CodeRejected,
			wantStderr: `is not a whitelisted`,
		},
		{
			name:       "server error yields 125 with message",
			events:     []Event{{Type: EventError, Message: "job dir escapes the repository root"}},
			wantCode:   CodeProtocolError,
			wantStderr: "escapes the repository root",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guestEnd, hostEnd := socketpairTCP(t)
			speakEvents(t, hostEnd, tt.events)
			var out, errBuf strings.Builder
			code := Exec(guestEnd, tt.argv, "", &out, &errBuf)
			if code != tt.wantCode {
				t.Fatalf("Exec() = %d, want %d (stderr: %q)", code, tt.wantCode, errBuf.String())
			}
			if out.String() != tt.wantStdout {
				t.Errorf("stdout = %q, want %q", out.String(), tt.wantStdout)
			}
			if tt.wantStderr != "" && !strings.Contains(errBuf.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want containing %q", errBuf.String(), tt.wantStderr)
			}
		})
	}
}

func TestExec_TruncatedResponseIsAProtocolError(t *testing.T) {
	guestEnd, hostEnd := socketpairTCP(t)
	// Send an unparseable frame, then hang up without any final marker.
	go func() {
		_ = frame.WriteFrame(hostEnd, []byte("this is not json"))
		_ = hostEnd.Close()
	}()
	var out, errBuf strings.Builder
	if code := Exec(guestEnd, []string{"whatever"}, "", &out, &errBuf); code != CodeProtocolError {
		t.Fatalf("Exec() = %d, want %d (stderr %q)", code, CodeProtocolError, errBuf.String())
	}
}

func TestSocketPath_ConstantMatchesGuestBridge(t *testing.T) {
	if !filepath.IsAbs(SocketPath) {
		t.Errorf("SocketPath = %q, must be absolute inside the sandbox", SocketPath)
	}
}
