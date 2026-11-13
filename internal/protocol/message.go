package protocol

import "encoding/json"

// AgentInfo is the REGISTER payload: identifies the implant (README §4.3).
type AgentInfo struct {
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	OSVersion     string `json:"os_version,omitempty"`
	Arch          string `json:"arch"`
	User          string `json:"user"`
	PID           int    `json:"pid"`
	ClientVersion string `json:"client_version"`
	Nonce         string `json:"nonce"`
}

// SessionConfig is the REGISTERED payload the teamserver hands to the agent.
type SessionConfig struct {
	HeartbeatInterval float64 `json:"heartbeat_interval"`
	HeartbeatJitter   float64 `json:"heartbeat_jitter"`
	MaxFrameBytes     int     `json:"max_frame_bytes"`
}

// TaskSpec is the TASK payload: what the operator asked the agent to do.
type TaskSpec struct {
	Kind    string          `json:"kind"`
	Args    json.RawMessage `json:"args,omitempty"`
	Timeout float64         `json:"timeout,omitempty"` // seconds
}

// Task kinds (README §4.5).
const (
	KindShell   = "shell"
	KindSysinfo = "sysinfo"
	KindExit    = "exit"
)

// ShellArgs is the args payload of a shell task.
type ShellArgs struct {
	Cmd string `json:"cmd"`
}

// TaskResult is the RESULT payload.
type TaskResult struct {
	Status     string `json:"status"`
	ExitCode   int    `json:"exit_code,omitempty"`
	Stdout     string `json:"stdout,omitempty"`
	Stderr     string `json:"stderr,omitempty"`
	Detail     string `json:"detail,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

// Result statuses (README §4.3).
const (
	StatusOK          = "ok"
	StatusError       = "error"
	StatusTimeout     = "timeout"
	StatusUnsupported = "unsupported"
)

// ErrorPayload is the ERROR envelope data (README §4.3).
type ErrorPayload struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	Recoverable bool   `json:"recoverable"`
}

// ByePayload is the BYE envelope data.
type ByePayload struct {
	Reason string `json:"reason"`
}
