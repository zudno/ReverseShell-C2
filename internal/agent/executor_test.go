package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
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

func TestExecuteExit(t *testing.T) {
	res := ExecuteTask(context.Background(), protocol.TaskSpec{Kind: protocol.KindExit}, protocol.AgentInfo{})
	if res.Status != protocol.StatusOK {
		t.Fatalf("status = %q detail = %q", res.Status, res.Detail)
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

func uploadSpec(t *testing.T, path, data string, offset, index, total int64, sha string, final bool) protocol.TaskSpec {
	t.Helper()
	args, err := json.Marshal(protocol.UploadArgs{
		Path:       path,
		Offset:     offset,
		Index:      index,
		Total:      total,
		TotalBytes: offset + int64(len(data)),
		SHA256:     sha,
		Data:       base64.StdEncoding.EncodeToString([]byte(data)),
		Final:      final,
	})
	if err != nil {
		t.Fatal(err)
	}
	return protocol.TaskSpec{Kind: protocol.KindUpload, Args: args, Timeout: 30}
}

func TestExecuteUploadVerifiesAndWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blob.bin")
	sum := sha256.Sum256([]byte("hello upload"))
	spec := uploadSpec(t, path, "hello upload", 0, 0, 1, hex.EncodeToString(sum[:]), true)

	res := ExecuteTask(context.Background(), spec, protocol.AgentInfo{})
	if res.Status != protocol.StatusOK || !strings.Contains(res.Detail, "sha256 verified") {
		t.Fatalf("res = %+v", res)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "hello upload" {
		t.Fatalf("file = %q (%v)", got, err)
	}
}

func TestExecuteUploadRejectsBadChecksum(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blob.bin")
	spec := uploadSpec(t, path, "tampered", 0, 0, 1, "deadbeef", true)

	res := ExecuteTask(context.Background(), spec, protocol.AgentInfo{})
	if res.Status != protocol.StatusError || !strings.Contains(res.Detail, "checksum mismatch") {
		t.Fatalf("res = %+v", res)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("file must not exist after a failed verification")
	}
	if _, err := os.Stat(path + ".rs-upload"); err == nil {
		t.Fatal("temp file must be removed after a failed verification")
	}
}

func TestExecuteUploadChunksAreOffsetAddressed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blob.bin")
	// Chunks arriving out of order must still assemble correctly.
	sum := sha256.Sum256([]byte("helloworld"))

	res1 := ExecuteTask(context.Background(),
		uploadSpec(t, path, "world", 5, 1, 2, hex.EncodeToString(sum[:]), false), protocol.AgentInfo{})
	if res1.Status != protocol.StatusOK {
		t.Fatalf("chunk 1: %+v", res1)
	}
	res0 := ExecuteTask(context.Background(),
		uploadSpec(t, path, "hello", 0, 0, 2, hex.EncodeToString(sum[:]), true), protocol.AgentInfo{})
	if res0.Status != protocol.StatusOK {
		t.Fatalf("chunk 0 (final): %+v", res0)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "helloworld" {
		t.Fatalf("file = %q (%v)", got, err)
	}
}

func TestDownloadResultsChunksAndVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.bin")
	blob := make([]byte, protocol.TransferChunkBytes*2+11)
	for i := range blob {
		blob[i] = byte(i % 251)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(blob)

	args, _ := json.Marshal(protocol.DownloadArgs{Path: path})
	results := downloadResults(protocol.TaskSpec{Kind: protocol.KindDownload, Args: args})
	if len(results) != 3 {
		t.Fatalf("chunks = %d, want 3", len(results))
	}
	var assembled []byte
	for i, r := range results {
		if r.Status != protocol.StatusOK || r.Chunk == nil || r.Chunk.Index != i {
			t.Fatalf("result %d = %+v", i, r)
		}
		raw, err := base64.StdEncoding.DecodeString(r.Data)
		if err != nil {
			t.Fatal(err)
		}
		assembled = append(assembled, raw...)
		if i < len(results)-1 && r.Chunk.Final {
			t.Fatalf("result %d marked final early", i)
		}
	}
	last := results[len(results)-1]
	if !last.Chunk.Final || last.Chunk.Total != 3 ||
		last.Chunk.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("final chunk meta = %+v", last.Chunk)
	}
	if !bytes.Equal(assembled, blob) {
		t.Fatal("reassembled payload differs from the original file")
	}
}

func TestDownloadResultsEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.bin")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	args, _ := json.Marshal(protocol.DownloadArgs{Path: path})
	results := downloadResults(protocol.TaskSpec{Kind: protocol.KindDownload, Args: args})
	if len(results) != 1 || results[0].Chunk == nil || !results[0].Chunk.Final {
		t.Fatalf("results = %+v", results)
	}
	empty := sha256.Sum256(nil)
	if results[0].Chunk.SHA256 != hex.EncodeToString(empty[:]) {
		t.Fatalf("empty-file hash = %s", results[0].Chunk.SHA256)
	}
}
