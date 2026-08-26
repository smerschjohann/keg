package runner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Event types streamed from host runner to the sandbox client (one framed
// JSON object each, CONCEPT.md §9: length-prefix JSON over channel C).
const (
	EventStdout = "stdout"
	EventStderr = "stderr"
	EventExit   = "exit"   // final: job exit code
	EventDenied = "denied" // final: whitelist rejection (client exits 126)
	EventError  = "error"  // final: protocol/execution failure (client exits 125)
)

// Exit codes of the delegate client (AGENTS.md §5, bestand-compatible).
const (
	CodeRejected      = 126 // delegated job denied by the whitelist
	CodeProtocolError = 125 // protocol or path-jail error
	CodeNoRunner      = 127 // runner channel/socket missing
)

// JobRequest is the single request frame a client sends per job. Every
// argument travels base64-encoded so newlines, quotes and control
// characters survive JSON verbatim (THREAT_MODEL §5.4: parameters are
// structured data, never shell input).
type JobRequest struct {
	ArgvB64 []string `json:"argv_b64"`
	Dir     string   `json:"dir,omitempty"` // subdir under the repo root (path jail)
}

// EncodeRequest serializes a request to its wire form.
func EncodeRequest(req JobRequest) []byte {
	b, err := json.Marshal(req)
	if err != nil {
		// Unreachable for this type: strings are b64-safe by construction.
		panic(fmt.Sprintf("runner: encode request: %v", err))
	}
	return b
}

// DecodeRequest parses one request frame payload.
func DecodeRequest(raw []byte) (JobRequest, error) {
	var req JobRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return JobRequest{}, fmt.Errorf("runner: decode request: %w", err)
	}
	return req, nil
}

// EncodeStrings base64-encodes every element.
func EncodeStrings(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = base64.StdEncoding.EncodeToString([]byte(s))
	}
	return out
}

// DecodeStrings reverses EncodeStrings.
func DecodeStrings(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			continue // validated on decode failure paths; keep raw fallback
		}
		out[i] = string(b)
	}
	return out
}

// Event is one streamed response frame.
type Event struct {
	Type    string `json:"type"`
	Data    string `json:"data,omitempty"`    // b64 chunk (stdout/stderr)
	Code    int    `json:"code,omitempty"`    // job exit code (exit)
	Message string `json:"message,omitempty"` // denial reason / error text
}
