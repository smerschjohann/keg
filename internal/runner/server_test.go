package runner

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/smerschjohann/keg/internal/config"
	"github.com/smerschjohann/keg/internal/frame"
)

// --- helpers ---------------------------------------------------------------

func baseEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := NewEngine(config.DelegatedTasks{
		Prefixes: []string{"test-playwright"},
		Raw:      []config.RawRule{gitRule()},
	}, config.RunnerCfg{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

// fakeJustBin builds an executable standing in for `just`: it echoes its
// argv to stdout/stderr and exits with the code from $FAKE_EXIT.
func fakeJustBin(t *testing.T) string {
	t.Helper()
	return writeScript(t, "just", `
echo "just-stdout:" "$@"
echo "just-stderr" >&2
exit ${FAKE_EXIT:-0}
`)
}

func writeScript(t *testing.T, name, body string) string {
	t.Helper()
	return writeFile(t, filepath.Join(t.TempDir(), name), body)
}

// writeFile creates an executable shell script at path.
func writeFile(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o750); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chmod(path, 0o750); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
	return path
}

func mustFrame(b []byte) []byte {
	var buf bytes.Buffer
	if err := frame.WriteFrame(&buf, b); err != nil {
		panic(err) // unreachable: test payloads stay far below the limit
	}
	return buf.Bytes()
}

func encodeReq(argv []string, dir string) []byte {
	return EncodeRequest(JobRequest{ArgvB64: EncodeStrings(argv), Dir: dir})
}

// readEvents drains one stream until EOF and returns all events plus the
// final exit/denied/error classification.
func readEvents(t *testing.T, conn io.Reader) []Event {
	t.Helper()
	var events []Event
	for {
		payload, err := frame.ReadFrame(conn)
		if err != nil {
			break
		}
		var ev Event
		if err := json.Unmarshal(payload, &ev); err != nil {
			t.Fatalf("event unmarshal: %v", err)
		}
		events = append(events, ev)
	}
	if len(events) == 0 {
		t.Fatal("no events received")
	}
	return events
}

type evResult struct {
	code    int
	denied  string
	errMsg  string
	stdout  string
	stderr  string
	sawExit bool
}

func classify(events []Event) evResult {
	var r evResult
	for _, ev := range events {
		data, _ := base64.StdEncoding.DecodeString(ev.Data)
		switch ev.Type {
		case EventStdout:
			r.stdout += string(data)
		case EventStderr:
			r.stderr += string(data)
		case EventDenied:
			r.denied = ev.Message
			r.code = CodeRejected
		case EventError:
			r.errMsg = ev.Message
			r.code = CodeProtocolError
		case EventExit:
			r.code = ev.Code
			r.sawExit = true
		}
	}
	return r
}

// --- tests -----------------------------------------------------------------

func TestEncodeRequest_RoundTripsHostileArguments(t *testing.T) {
	argv := []string{"git", "commit", "-m", "mehrzeilig\nmit \"quotes\" und ümläuten\tund $dollar"}
	req := JobRequest{ArgvB64: EncodeStrings(argv), Dir: "sub/dir"}
	raw := EncodeRequest(req)
	got, err := DecodeRequest(raw)
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	if decoded := DecodeStrings(got.ArgvB64); strings.Join(decoded, "|") != strings.Join(argv, "|") {
		t.Errorf("argv roundtrip mismatch:\n got %q\nwant %q", decoded, argv)
	}
	if got.Dir != "sub/dir" {
		t.Errorf("dir roundtrip: got %q", got.Dir)
	}
}

func TestServer_ExecutesWhitelistedJobs(t *testing.T) {
	tests := []struct {
		name      string
		argv      []string
		dir       string
		path      string // placeholder replaced by the stub dir below
		fakeExit  string
		wantCode  int
		wantStdou string
	}{
		{
			name:      "prefix task with arguments",
			argv:      []string{"test-playwright", "login.spec.ts"},
			wantCode:  0,
			wantStdou: "just-stdout: test-playwright login.spec.ts\n",
		},
		{
			name:      "raw git commit passes arguments verbatim",
			argv:      []string{"git", "commit", "-m", "msg"},
			path:      "RAWBIN",
			wantCode:  0,
			wantStdou: "raw-git: commit -m msg\n",
		},
		{
			name:      "exit code is mirrored verbatim",
			argv:      []string{"test-playwright"},
			fakeExit:  "42", // set via t.Setenv below (server inherits it)
			wantCode:  42,
			wantStdou: "just-stdout: test-playwright\n",
		},
		{
			name:     "job inside repo subdir stays in the jail",
			argv:     []string{"test-playwright", "x"},
			dir:      "pkg/sub",
			wantCode: 0,
		},
	}
	rawBinDir := t.TempDir()
	writeFile(t, filepath.Join(rawBinDir, "git"), `echo "raw-git:" "$@"
exit ${FAKE_EXIT:-0}
`)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := pipeSessions(t)
			if tt.path == "RAWBIN" {
				t.Setenv("PATH", rawBinDir+":"+os.Getenv("PATH"))
			}
			if tt.fakeExit != "" {
				t.Setenv("FAKE_EXIT", tt.fakeExit)
			}
			repo := t.TempDir()
			if tt.dir != "" {
				if err := os.MkdirAll(filepath.Join(repo, tt.dir), 0o750); err != nil {
					t.Fatalf("mkdir repo subdir: %v", err)
				}
			}
			cfg := ServerConfig{
				Engine:   baseEngine(t),
				JustBin:  fakeJustBin(t),
				RepoRoot: repo,
			}
			go func() { _ = ServeSession(server, cfg) }()

			stream := openStream(t, client)
			if _, err := stream.Write(mustFrame(encodeReq(tt.argv, tt.dir))); err != nil {
				t.Fatalf("send request: %v", err)
			}
			res := classify(readEvents(t, stream))
			if res.code != tt.wantCode {
				t.Fatalf("exit code = %d (denied=%q err=%q), want %d",
					res.code, res.denied, res.errMsg, tt.wantCode)
			}
			if !res.sawExit {
				t.Error("no exit marker event received")
			}
			if tt.wantStdou != "" && !strings.Contains(res.stdout, tt.wantStdou) {
				t.Errorf("stdout = %q, want containing %q", res.stdout, tt.wantStdou)
			}
			if tt.path == "" && !strings.Contains(res.stderr, "just-stderr") {
				t.Errorf("stderr = %q, want live stderr streaming", res.stderr)
			}
		})
	}
}

func TestServer_DeniesWithoutExecuting(t *testing.T) {
	client, server := pipeSessions(t)
	repo := t.TempDir()
	marker := filepath.Join(repo, "marker")
	cfg := ServerConfig{
		Engine:   baseEngine(t),
		JustBin:  writeScript(t, "just", "touch "+marker+"\nexit 0\n"),
		RepoRoot: repo,
	}
	go func() { _ = ServeSession(server, cfg) }()

	stream := openStream(t, client)
	_, err := stream.Write(mustFrame(encodeReq([]string{"git", "push", "origin", "main"}, "")))
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	res := classify(readEvents(t, stream))
	if res.denied == "" {
		t.Fatalf("denied event missing; result %+v", res)
	}
	if !strings.Contains(res.denied, "push") {
		t.Errorf("denial reason %q does not name the offending argument", res.denied)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Error("denied job was executed anyway — must never run")
	}
}

func TestServer_PathJailBlocksEscapes(t *testing.T) {
	tests := []struct {
		name string
		dir  string
	}{
		{"parent traversal", "../outside"},
		{"absolute path", "/tmp"},
		{"sneaky traversal", "sub/../../outside"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := pipeSessions(t)
			repo := t.TempDir()
			marker := filepath.Join(repo, "marker")
			cfg := ServerConfig{
				Engine:   baseEngine(t),
				JustBin:  writeScript(t, "just", "touch "+marker+"\n"),
				RepoRoot: repo,
			}
			go func() { _ = ServeSession(server, cfg) }()

			stream := openStream(t, client)
			if _, err := stream.Write(mustFrame(encodeReq([]string{"test-playwright"}, tt.dir))); err != nil {
				t.Fatalf("send request: %v", err)
			}
			res := classify(readEvents(t, stream))
			if res.errMsg == "" {
				t.Fatalf("expected protocol error event, got %+v", res)
			}
			time.Sleep(50 * time.Millisecond)
			if _, err := os.Stat(marker); err == nil {
				t.Errorf("job ran outside the path jail (%s)", tt.dir)
			}
		})
	}
}

func TestServer_SuppressesGitHooksForRawGitJobs(t *testing.T) {
	client, server := pipeSessions(t)
	seenArgs := filepath.Join(t.TempDir(), "args")
	gitStub := writeScript(t, "git", `printf '%s\n' "$@" > `+seenArgs+"\nexit 0\n")
	cfg := ServerConfig{
		Engine:   baseEngine(t),
		JustBin:  fakeJustBin(t),
		RepoRoot: t.TempDir(),
		HooksDir: t.TempDir(), // empty dir owned by keg
	}
	_ = gitStub
	// Put the stub on PATH so exec("git") finds it.
	t.Setenv("PATH", filepath.Dir(gitStub)+":"+os.Getenv("PATH"))
	go func() { _ = ServeSession(server, cfg) }()

	stream := openStream(t, client)
	if _, err := stream.Write(mustFrame(encodeReq([]string{"git", "commit", "-m", "x"}, ""))); err != nil {
		t.Fatalf("send request: %v", err)
	}
	res := classify(readEvents(t, stream))
	if res.code != 0 {
		t.Fatalf("job failed: %+v", res)
	}
	raw, err := os.ReadFile(seenArgs)
	if err != nil {
		t.Fatalf("git stub did not run: %v", err)
	}
	args := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(args) < 4 || args[0] != "-c" || !strings.HasPrefix(args[1], "core.hooksPath=") || args[2] != "commit" {
		t.Errorf("git invoked without hook suppression: %q", args)
	}
}

func TestServer_ContextCancelKillsRunningJob(t *testing.T) {
	client, server := pipeSessions(t)
	sleep := writeScript(t, "sleep-job", `#!/bin/sh
echo started
exec sleep 30
`)
	engine, err := NewEngine(config.DelegatedTasks{}, config.RunnerCfg{
		ExtraPrefixes: []string{"test-sleep"},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	cfg := ServerConfig{Engine: engine, JustBin: sleep, RepoRoot: t.TempDir()}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = ServeSessionCtx(ctx, server, cfg) }()

	stream := openStream(t, client)
	if _, err := stream.Write(mustFrame(encodeReq([]string{"test-sleep"}, ""))); err != nil {
		t.Fatalf("send request: %v", err)
	}
	waitForEvent(t, stream, "started")
	cancel()
	// The job must die promptly; if it survived, cleanup would block ~30 s.
	done := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, stream); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream still alive 5 s after context cancel — job not killed")
	}
}

func TestServer_ConcurrentJobsDoNotInterleave(t *testing.T) {
	client, server := pipeSessions(t)
	slow := writeScript(t, "slow", `#!/bin/sh
echo "A:$1"; sleep 0.2; echo "B:$1"; echo "E:$1" >&2; exit 7
`)
	engine, err := NewEngine(config.DelegatedTasks{}, config.RunnerCfg{
		ExtraPrefixes: []string{"job-a", "job-b"},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	cfg := ServerConfig{Engine: engine, JustBin: slow, RepoRoot: t.TempDir()}
	go func() { _ = ServeSession(server, cfg) }()

	run := func(name string) evResult {
		stream := openStream(t, client)
		if _, err := stream.Write(mustFrame(encodeReq([]string{name, name}, ""))); err != nil {
			t.Fatalf("send request: %v", err)
		}
		defer stream.Close() //nolint:errcheck -- test stream
		return classify(readEvents(t, stream))
	}
	var wg sync.WaitGroup
	results := make([]evResult, 2)
	for i, name := range []string{"job-a", "job-b"} {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			results[i] = run(name)
		}(i, name)
	}
	wg.Wait()
	for i, want := range []string{"A:job-a", "A:job-b"} {
		if !strings.Contains(results[i].stdout, want) {
			t.Errorf("job %d stdout missing %q: %q", i, want, results[i].stdout)
		}
		if results[i].code != 7 {
			t.Errorf("job %d exit code = %d, want 7", i, results[i].code)
		}
	}
}

func TestServeSession_StopsAndLeaksNothingOnClose(t *testing.T) {
	before := runtime.NumGoroutine()
	_, server := pipeSessions(t)
	cfg := ServerConfig{Engine: baseEngine(t), JustBin: fakeJustBin(t), RepoRoot: t.TempDir()}
	done := make(chan error, 1)
	go func() { done <- ServeSession(server, cfg) }()
	_ = server.Close() // muxado Accept wakes on OWN session close (M4 note 3)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ServeSession did not stop after session close")
	}
	deadline := time.Now().Add(3 * time.Second)
	for numGoroutine() > before+5 && time.Now().Before(deadline) {
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}
	if n := numGoroutine(); n > before+5 {
		t.Errorf("goroutines leaked: before=%d after=%d", before, n)
	}
}

// numGoroutine indirection keeps the leak check testable.
var numGoroutine = runtime.NumGoroutine

func TestRequest_MapsOutcomesToExitCodes(t *testing.T) {
	// The client maps outcomes onto conventional codes without running
	// anything: denial ⇒ 126, protocol error ⇒ 125, success ⇒ job code.
	if CodeRejected != 126 {
		t.Errorf("CodeRejected = %d, want 126", CodeRejected)
	}
	if CodeProtocolError != 125 {
		t.Errorf("CodeProtocolError = %d, want 125", CodeProtocolError)
	}
}

// waitForEvent reads framed events until one carries the given text (in a
// message or a decoded stdout/stderr chunk), with an overall timeout.
func waitForEvent(t *testing.T, conn io.Reader, needle string) Event {
	t.Helper()
	type result struct {
		ev  Event
		eof bool
	}
	found := make(chan result, 1)
	go func() {
		for {
			payload, err := frame.ReadFrame(conn)
			if err != nil {
				found <- result{eof: true}
				return
			}
			var ev Event
			if json.Unmarshal(payload, &ev) != nil {
				continue
			}
			data, _ := base64.StdEncoding.DecodeString(ev.Data)
			if strings.Contains(ev.Message, needle) ||
				strings.Contains(ev.Data, base64.StdEncoding.EncodeToString([]byte(needle))) ||
				strings.Contains(string(data), needle) {
				found <- result{ev: ev}
				return
			}
		}
	}()
	select {
	case r := <-found:
		if r.eof {
			t.Fatalf("stream ended while waiting for %q", needle)
		}
		return r.ev
	case <-time.After(10 * time.Second):
		t.Fatalf("%q never appeared in stream", needle)
		return Event{}
	}
}
