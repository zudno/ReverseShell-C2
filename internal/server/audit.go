package server

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

// openAudit creates the audit JSONL logger (README §9.3). It renames time→ts
// and msg→event and drops the level, so lines match the documented shape:
// {"ts":…,"event":…,…}.
func openAudit(path string) (*slog.Logger, io.Closer, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, nil, fmt.Errorf("create audit dir: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open audit log: %w", err)
	}
	h := slog.NewJSONHandler(f, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case slog.TimeKey:
				a.Key = "ts"
			case slog.MessageKey:
				a.Key = "event"
			case slog.LevelKey:
				return slog.Attr{}
			}
			return a
		},
	})
	return slog.New(h), f, nil
}
