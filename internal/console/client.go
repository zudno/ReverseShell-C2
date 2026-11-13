// Package console implements the operator CLI: a thin client of the
// teamserver's operator API. It never touches the session plane (README §3.4).
package console

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"reverseshell/internal/api"
	"reverseshell/internal/protocol"
)

// Client talks to the operator API with a bearer token.
type Client struct {
	base  string
	token string
	hc    *http.Client
	hcSSE *http.Client // no timeout: the stream lifetime is governed by ctx
}

// NewClient returns a client for serverAddr ("host:port").
func NewClient(serverAddr, token string) *Client {
	return &Client{
		base:  "http://" + serverAddr,
		token: token,
		hc:    &http.Client{Timeout: 10 * time.Second},
		hcSSE: &http.Client{},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return fmt.Errorf("%s: %s", resp.Status, e.Error)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// Sessions lists live sessions.
func (c *Client) Sessions(ctx context.Context) ([]api.SessionView, error) {
	var out []api.SessionView
	err := c.do(ctx, http.MethodGet, "/v1/sessions", nil, &out)
	return out, err
}

// CreateTask queues a task and returns its tid.
func (c *Client) CreateTask(ctx context.Context, sid string, spec protocol.TaskSpec) (string, error) {
	var out struct {
		TID string `json:"tid"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/sessions/"+sid+"/tasks", spec, &out)
	return out.TID, err
}

// Task fetches a task with its result.
func (c *Client) Task(ctx context.Context, tid string) (api.TaskView, error) {
	var out api.TaskView
	err := c.do(ctx, http.MethodGet, "/v1/tasks/"+tid, nil, &out)
	return out, err
}

// Shutdown asks the teamserver to stop.
func (c *Client) Shutdown(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/shutdown", nil, nil)
}

// Events streams SSE events, invoking onEvent per event, until ctx is done.
func (c *Client) Events(ctx context.Context, onEvent func(evType string, data []byte)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/v1/events", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := c.hcSSE.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("events: %s", resp.Status)
	}
	sc := bufio.NewScanner(resp.Body)
	var evType string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			evType = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			onEvent(evType, []byte(strings.TrimPrefix(line, "data: ")))
		}
	}
	return sc.Err()
}
