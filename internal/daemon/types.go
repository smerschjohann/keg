package daemon

// Actions supported by the daemon v1 protocol.
const (
	ActionCreate = "create"
	ActionExec   = "exec"
	ActionStatus = "status"
	ActionList   = "list"
	ActionStop   = "stop"
)

// LaunchOptions describes optional parameters when creating a sandbox.
type LaunchOptions struct {
	RepoConfig        string   `json:"repo_config,omitempty"`
	UserConfig        string   `json:"user_config,omitempty"`
	Ephemeral         bool     `json:"ephemeral,omitempty"`
	DiskOverlay       string   `json:"disk_overlay,omitempty"`
	IsolateCaches     bool     `json:"isolate_caches,omitempty"`
	IsolatedCacheName string   `json:"isolated_cache_name,omitempty"`
	InstanceName      string   `json:"instance_name,omitempty"`
	AuditFile         string   `json:"audit_file,omitempty"`
	Command           []string `json:"command,omitempty"`
}

// Request is the v1 wire format for daemon requests.
type Request struct {
	Action    string            `json:"action"`
	Token     string            `json:"token,omitempty"`
	RepoRoot  string            `json:"repo_root,omitempty"`
	Options   LaunchOptions     `json:"options,omitempty"`
	SandboxID string            `json:"sandbox_id,omitempty"`
	Argv      []string          `json:"argv,omitempty"`
	Dir       string            `json:"dir,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
}

// SandboxStatus describes the state of a sandbox.
type SandboxStatus struct {
	SandboxID string `json:"sandbox_id"`
	RepoRoot  string `json:"repo_root"`
	Status    string `json:"status"` // running | stopped
	Pid       int    `json:"pid"`
}

// Response is the v1 wire format for daemon responses.
type Response struct {
	Action    string          `json:"action"`
	Success   bool            `json:"success"`
	Error     string          `json:"error,omitempty"`
	SandboxID string          `json:"sandbox_id,omitempty"`
	Status    string          `json:"status,omitempty"`
	Pid       int             `json:"pid,omitempty"`
	Sandboxes []SandboxStatus `json:"sandboxes,omitempty"`
}

// ExecEvent describes one streaming event (stdout, stderr, exit, error).
type ExecEvent struct {
	Type    string `json:"type"` // stdout | stderr | exit | error
	Data    string `json:"data,omitempty"`
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}
