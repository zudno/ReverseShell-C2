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
	Auth          string `json:"auth,omitempty"` // HMAC-SHA256(token, nonce|hostname|ts) — README §9.2
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
	KindShell    = "shell"
	KindSysinfo  = "sysinfo"
	KindExit     = "exit"
	KindUpload   = "upload"
	KindDownload = "download"
)

// Transfer limits (README §4.5): raw bytes per chunk and per-file cap.
const (
	TransferChunkBytes = 1 << 20  // 1 MiB raw per chunk
	MaxTransferBytes   = 64 << 20 // 64 MiB per file
)

// ShellArgs is the args payload of a shell task.
type ShellArgs struct {
	Cmd string `json:"cmd"`
}

// DownloadArgs is the args payload of a download task.
type DownloadArgs struct {
	Path string `json:"path"`
}

// UploadArgs is the args payload of one upload chunk task. Chunks are
// offset-addressed, so arrival order does not matter.
type UploadArgs struct {
	Path       string `json:"path"`
	Offset     int64  `json:"offset"`
	Index      int64  `json:"index"`       // this chunk's index (0-based)
	Total      int64  `json:"total"`       // total chunk count
	TotalBytes int64  `json:"total_bytes"` // complete-file size
	SHA256     string `json:"sha256"`      // complete-file hash
	Data       string `json:"data"`        // base64 chunk
	Final      bool   `json:"final"`       // last chunk: verify + rename
}

// ChunkMeta marks a RESULT as one chunk of a chunked transfer; SHA256 (the
// complete-file hash) is present on the final chunk only.
type ChunkMeta struct {
	Index  int    `json:"i"`
	Total  int    `json:"n"`
	SHA256 string `json:"sha256,omitempty"`
	Final  bool   `json:"final"`
}

// TaskResult is the RESULT payload.
type TaskResult struct {
	Status     string     `json:"status"`
	ExitCode   int        `json:"exit_code,omitempty"`
	Stdout     string     `json:"stdout,omitempty"`
	Stderr     string     `json:"stderr,omitempty"`
	Detail     string     `json:"detail,omitempty"`
	DurationMS int64      `json:"duration_ms"`
	Data       string     `json:"data,omitempty"` // base64 chunk (chunked transfers)
	Chunk      *ChunkMeta `json:"chunk,omitempty"`
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
