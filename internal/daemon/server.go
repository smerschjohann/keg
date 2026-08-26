// Package daemon implements the keg background daemon server and RPC protocol (CONCEPT.md §8.3).
package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/smerschjohann/keg/internal/frame"
	"github.com/smerschjohann/keg/pkg/keg"
)

// Config holds daemon server configuration.
type Config struct {
	ListenAddr   string // "unix:///path/to/sock" or "127.0.0.1:7777"
	Auth         string // "token" | "none"
	Token        string // auth token
	MaxSandboxes int    // concurrent limit (default 10)
}

// Server is the keg daemon server.
type Server struct {
	mu           sync.Mutex
	cfg          Config
	listener     net.Listener
	sandboxes    map[string]*managedSandbox
	closed       bool
	closeHandler func()
}

type managedSandbox struct {
	id       string
	repoRoot string
	sb       *keg.Sandbox
}

// NewServer creates and initializes a daemon server with the given configuration.
func NewServer(cfg Config) (*Server, error) {
	if cfg.MaxSandboxes <= 0 {
		cfg.MaxSandboxes = 10
	}
	if cfg.ListenAddr == "" {
		runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
		if runtimeDir == "" {
			runtimeDir = "/tmp"
		}
		cfg.ListenAddr = "unix://" + filepath.Join(runtimeDir, "keg", "api.sock")
	}

	isUnix := strings.HasPrefix(cfg.ListenAddr, "unix://")
	isLoopback := strings.HasPrefix(cfg.ListenAddr, "127.0.0.1:") || strings.HasPrefix(cfg.ListenAddr, "localhost:")

	if !isUnix && !isLoopback && cfg.Auth != "token" {
		return nil, fmt.Errorf("token auth is required when listening on network %s", cfg.ListenAddr)
	}
	if cfg.Auth == "token" && cfg.Token == "" {
		return nil, fmt.Errorf("token is required when auth mode is token")
	}

	var (
		ln           net.Listener
		closeHandler func()
	)

	var lc net.ListenConfig
	if isUnix {
		sockPath := strings.TrimPrefix(cfg.ListenAddr, "unix://")
		if err := os.MkdirAll(filepath.Dir(sockPath), 0o770); err != nil { // #nosec G301,G703 -- socket directory permissions per CONCEPT.md §8.3
			return nil, fmt.Errorf("create socket dir: %w", err)
		}
		_ = os.Remove(sockPath) // #nosec G703 -- trusted local path
		l, err := lc.Listen(context.Background(), "unix", sockPath)
		if err != nil {
			return nil, fmt.Errorf("listen unix: %w", err)
		}
		_ = os.Chmod(sockPath, 0o660)                     // #nosec G302,G703 -- socket permissions per CONCEPT.md §8.3
		closeHandler = func() { _ = os.Remove(sockPath) } // #nosec G703 -- trusted local path
		ln = l
	} else {
		l, err := lc.Listen(context.Background(), "tcp", cfg.ListenAddr)
		if err != nil {
			return nil, fmt.Errorf("listen tcp: %w", err)
		}
		ln = l
	}

	return &Server{
		cfg:          cfg,
		listener:     ln,
		sandboxes:    make(map[string]*managedSandbox),
		closeHandler: closeHandler,
	}, nil
}

// Close stops the server and terminates all active sandboxes.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	sbs := make([]*managedSandbox, 0, len(s.sandboxes))
	for _, m := range s.sandboxes {
		sbs = append(sbs, m)
	}
	s.sandboxes = make(map[string]*managedSandbox)
	s.mu.Unlock()

	for _, m := range sbs {
		_ = m.sb.Close()
	}

	err := s.listener.Close()
	if s.closeHandler != nil {
		s.closeHandler()
	}
	return err
}

// Serve accepts client connections and handles daemon requests until ctx is canceled.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Audit client UID on Unix sockets via SO_PEERCRED
	if uconn, ok := conn.(*net.UnixConn); ok {
		if raw, err := uconn.SyscallConn(); err == nil {
			_ = raw.Control(func(fd uintptr) {
				if cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED); err == nil {
					slog.Info("daemon client connected", "uid", cred.Uid, "gid", cred.Gid, "pid", cred.Pid)
				}
			})
		}
	}

	for {
		payload, err := frame.ReadFrame(conn)
		if err != nil {
			return
		}

		var req Request
		if err := json.Unmarshal(payload, &req); err != nil {
			_ = sendJSONResponse(conn, Response{
				Action:  "unknown",
				Success: false,
				Error:   fmt.Sprintf("malformed request: %v", err),
			})
			continue
		}

		if s.cfg.Auth == "token" && req.Token != s.cfg.Token {
			_ = sendJSONResponse(conn, Response{
				Action:  req.Action,
				Success: false,
				Error:   "unauthorized: invalid auth token",
			})
			continue
		}

		switch req.Action {
		case ActionCreate:
			s.handleCreate(ctx, conn, req)
		case ActionStatus:
			s.handleStatus(conn, req)
		case ActionList:
			s.handleList(conn)
		case ActionStop:
			s.handleStop(conn, req)
		case ActionExec:
			s.handleExec(ctx, conn, req)
		default:
			_ = sendJSONResponse(conn, Response{
				Action:  req.Action,
				Success: false,
				Error:   fmt.Sprintf("unknown action %q", req.Action),
			})
		}
	}
}

func (s *Server) handleCreate(ctx context.Context, conn net.Conn, req Request) {
	s.mu.Lock()
	if len(s.sandboxes) >= s.cfg.MaxSandboxes {
		s.mu.Unlock()
		_ = sendJSONResponse(conn, Response{
			Action:  ActionCreate,
			Success: false,
			Error:   fmt.Sprintf("maximum sandbox limit of %d reached", s.cfg.MaxSandboxes),
		})
		return
	}
	s.mu.Unlock()

	var opts []keg.Option
	if req.Options.RepoConfig != "" {
		opts = append(opts, keg.WithRepoConfig(req.Options.RepoConfig))
	}
	if req.Options.UserConfig != "" {
		opts = append(opts, keg.WithUserConfig(req.Options.UserConfig))
	}
	if req.Options.Ephemeral {
		opts = append(opts, keg.WithEphemeral())
	}
	if req.Options.DiskOverlay != "" {
		opts = append(opts, keg.WithDiskOverlay(req.Options.DiskOverlay))
	}
	if req.Options.IsolateCaches {
		opts = append(opts, keg.WithIsolateCaches())
	}
	if req.Options.IsolatedCacheName != "" {
		opts = append(opts, keg.WithIsolatedCacheName(req.Options.IsolatedCacheName))
	}
	if req.Options.InstanceName != "" {
		opts = append(opts, keg.WithName(req.Options.InstanceName))
	}
	if req.Options.AuditFile != "" {
		opts = append(opts, keg.WithAuditFile(req.Options.AuditFile))
	}
	if len(req.Options.Command) > 0 {
		opts = append(opts, keg.WithCommand(req.Options.Command...))
	}

	sb, err := keg.Launch(ctx, req.RepoRoot, opts...)
	if err != nil {
		_ = sendJSONResponse(conn, Response{
			Action:  ActionCreate,
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	id := generateID()
	managed := &managedSandbox{
		id:       id,
		repoRoot: req.RepoRoot,
		sb:       sb,
	}

	s.mu.Lock()
	s.sandboxes[id] = managed
	s.mu.Unlock()

	slog.Info("daemon sandbox created", "id", id, "repo", req.RepoRoot, "pid", sb.Pid())

	_ = sendJSONResponse(conn, Response{
		Action:    ActionCreate,
		Success:   true,
		SandboxID: id,
		Status:    "running",
		Pid:       sb.Pid(),
	})
}

func (s *Server) handleStatus(conn net.Conn, req Request) {
	s.mu.Lock()
	m, ok := s.sandboxes[req.SandboxID]
	s.mu.Unlock()

	if !ok {
		_ = sendJSONResponse(conn, Response{
			Action:    ActionStatus,
			Success:   false,
			Error:     fmt.Sprintf("sandbox %q not found", req.SandboxID),
			SandboxID: req.SandboxID,
		})
		return
	}

	_ = sendJSONResponse(conn, Response{
		Action:    ActionStatus,
		Success:   true,
		SandboxID: m.id,
		Status:    "running",
		Pid:       m.sb.Pid(),
	})
}

func (s *Server) handleList(conn net.Conn) {
	s.mu.Lock()
	list := make([]SandboxStatus, 0, len(s.sandboxes))
	for _, m := range s.sandboxes {
		list = append(list, SandboxStatus{
			SandboxID: m.id,
			RepoRoot:  m.repoRoot,
			Status:    "running",
			Pid:       m.sb.Pid(),
		})
	}
	s.mu.Unlock()

	_ = sendJSONResponse(conn, Response{
		Action:    ActionList,
		Success:   true,
		Sandboxes: list,
	})
}

func (s *Server) handleStop(conn net.Conn, req Request) {
	s.mu.Lock()
	m, ok := s.sandboxes[req.SandboxID]
	if ok {
		delete(s.sandboxes, req.SandboxID)
	}
	s.mu.Unlock()

	if !ok {
		_ = sendJSONResponse(conn, Response{
			Action:    ActionStop,
			Success:   false,
			Error:     fmt.Sprintf("sandbox %q not found", req.SandboxID),
			SandboxID: req.SandboxID,
		})
		return
	}

	_ = m.sb.Close()
	slog.Info("daemon sandbox stopped", "id", m.id)

	_ = sendJSONResponse(conn, Response{
		Action:    ActionStop,
		Success:   true,
		SandboxID: m.id,
		Status:    "stopped",
	})
}

func (s *Server) handleExec(ctx context.Context, conn net.Conn, req Request) {
	s.mu.Lock()
	m, ok := s.sandboxes[req.SandboxID]
	s.mu.Unlock()

	if !ok {
		_ = sendEvent(conn, ExecEvent{
			Type:    "error",
			Message: fmt.Sprintf("sandbox %q not found", req.SandboxID),
		})
		return
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	subSb, err := keg.Launch(ctx, m.repoRoot,
		keg.WithEphemeral(),
		keg.WithStdout(&stdoutBuf),
		keg.WithStderr(&stderrBuf),
		keg.WithCommand(req.Argv...),
	)
	if err != nil {
		_ = sendEvent(conn, ExecEvent{
			Type:    "error",
			Message: err.Error(),
		})
		return
	}
	defer func() { _ = subSb.Close() }()

	code, waitErr := subSb.Wait()
	if stdoutBuf.Len() > 0 {
		_ = sendEvent(conn, ExecEvent{
			Type: "stdout",
			Data: base64.StdEncoding.EncodeToString(stdoutBuf.Bytes()),
		})
	}
	if stderrBuf.Len() > 0 {
		_ = sendEvent(conn, ExecEvent{
			Type: "stderr",
			Data: base64.StdEncoding.EncodeToString(stderrBuf.Bytes()),
		})
	}
	if waitErr != nil {
		_ = sendEvent(conn, ExecEvent{
			Type:    "error",
			Message: waitErr.Error(),
		})
	}
	_ = sendEvent(conn, ExecEvent{
		Type: "exit",
		Code: code,
	})
}

func sendEvent(w io.Writer, ev ExecEvent) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return frame.WriteFrame(w, data)
}

func sendJSONResponse(w io.Writer, res Response) error {
	data, err := json.Marshal(res)
	if err != nil {
		return err
	}
	return frame.WriteFrame(w, data)
}

func generateID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
