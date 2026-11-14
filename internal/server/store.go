package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"reverseshell/internal/protocol"
)

// store persists task records and the nonce→sid resume map as JSONL
// (README §15, F5). It lives under the gitignored logs/ dir. Downloaded
// payload bytes are never persisted (metadata only); upload chunks keep
// their data so pending uploads can be redelivered after a restart.
type store struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

// storedTask is one task line. Result carries metadata only.
type storedTask struct {
	TID       string               `json:"tid"`
	SID       string               `json:"sid"`
	Spec      protocol.TaskSpec    `json:"spec"`
	Status    string               `json:"status"`
	Result    *protocol.TaskResult `json:"result,omitempty"`
	CreatedAt time.Time            `json:"created_at"`
}

// storeLine discriminates record kinds on the wire.
type storeLine struct {
	Type  string      `json:"type"` // "task" | "session"
	SID   string      `json:"sid,omitempty"`
	Nonce string      `json:"nonce,omitempty"`
	Task  *storedTask `json:"task,omitempty"`
}

func openStore(path string) (*store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create store dir: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open task store: %w", err)
	}
	return &store{f: f, path: path}, nil
}

func (s *store) appendLine(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.f.Write(append(b, '\n'))
	return err
}

func (s *store) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// loadStore reads every line; for tasks the last record per tid wins.
func loadStore(path string) (sessions map[string]string, tasks map[string]*storedTask, err error) {
	sessions = make(map[string]string)
	tasks = make(map[string]*storedTask)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return sessions, tasks, nil
		}
		return nil, nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		var line storeLine
		if json.Unmarshal(sc.Bytes(), &line) != nil {
			continue // tolerate corrupt lines: append-only artifacts
		}
		switch line.Type {
		case "session":
			if line.SID != "" && line.Nonce != "" {
				sessions[line.Nonce] = line.SID
			}
		case "task":
			if line.Task != nil && line.Task.TID != "" {
				tasks[line.Task.TID] = line.Task
			}
		}
	}
	return sessions, tasks, sc.Err()
}
