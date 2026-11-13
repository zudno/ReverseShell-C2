package agent

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"reverseshell/internal/protocol"
)

func TestExecuteShellEcho(t *testing.T) {
	spec := protocol.TaskSpec{
		Kind:    protocol.KindShell,
		Args:    json.RawMessage(`{"cmd":"echo rs-ok"}`),
		Timeout: 10,
	}
	res := ExecuteTask(context.Background(), spec, protocol.AgentInfo{})
	if res.Status != protocol.StatusOK {
		t.Fatalf("status = %q detail = %q stderr = %q", res.Status, res.Detail, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "rs-ok") {
		t.Fatalf("stdout = %q", res.Stdout)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d", res.ExitCode)
	}
}

func TestExecuteShellNonZeroExitIsData(t *testing.T) {
	spec := protocol.TaskSpec{
		Kind:    protocol.KindShell,
		Args:    json.RawMessage(`{"cmd":"exit 3"}`),
		Timeout: 10,
	}
	res := ExecuteTask(context.Background(), spec, protocol.AgentInfo{})
	if res.Status != protocol.StatusOK || res.ExitCode != 3 {
		t.Fatalf("status = %q exit = %d", res.Status, res.ExitCode)
	}
}

func TestExecuteShellMissingCmd(t *testing.T) {
	res := ExecuteTask(context.Background(), protocol.TaskSpec{Kind: protocol.KindShell}, protocol.AgentInfo{})
	if res.Status != protocol.StatusError {
		t.Fatalf("status = %q", res.Status)
	}
}

func TestExecuteUnsupportedKind(t *testing.T) {
	res := ExecuteTask(context.Background(), protocol.TaskSpec{Kind: "ftp"}, protocol.AgentInfo{})
	if res.Status != protocol.StatusUnsupported {
		t.Fatalf("status = %q", res.Status)
	}
}

func TestExecuteSysinfo(t *testing.T) {
	res := ExecuteTask(context.Background(), protocol.TaskSpec{Kind: protocol.KindSysinfo},
		protocol.AgentInfo{Hostname: "h", OS: "windows"})
	if res.Status != protocol.StatusOK {
		t.Fatalf("status = %q detail = %q", res.Status, res.Detail)
	}
	if !strings.Contains(res.Stdout, `"hostname"`) || !strings.Contains(res.Stdout, `"uptime_seconds"`) {
		t.Fatalf("stdout = %q", res.Stdout)
	}
}

func TestExecuteShellTimeout(t *testing.T) {
	cmd := "sleep 3"
	if runtime.GOOS == "windows" {
		cmd = "ping -n 3 127.0.0.1"
	}
	args, _ := json.Marshal(protocol.ShellArgs{Cmd: cmd})
	spec := protocol.TaskSpec{Kind: protocol.KindShell, Args: args, Timeout: 0.3}
	res := ExecuteTask(context.Background(), spec, protocol.AgentInfo{})
	if res.Status != protocol.StatusTimeout {
		t.Fatalf("status = %q stdout = %q detail = %q", res.Status, res.Stdout, res.Detail)
	}
}
