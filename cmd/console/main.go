// Command console is the operator's interactive client. It talks only to
// the teamserver operator API and never to the session plane (README §2).
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"reverseshell/internal/config"
	"reverseshell/internal/console"
)

func main() {
	var (
		cfgPath  = flag.String("config", "config.toml", "path to TOML config (optional)")
		server   = flag.String("server", "", "operator API address host:port (overrides config)")
		token    = flag.String("token", "", "operator bearer token (overrides config/env)")
		operator = flag.String("operator", "", "operator name for audit attribution (default: user@host)")
	)
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fail(err)
	}
	addr := *server
	if addr == "" {
		addr = net.JoinHostPort(cfg.Teamserver.APIHost, strconv.Itoa(cfg.Teamserver.APIPort))
	}
	if *token != "" {
		cfg.Teamserver.OperatorToken = *token
	}
	if cfg.Teamserver.OperatorToken == "" {
		fail(fmt.Errorf("operator token required: pass --token or set [teamserver] operator_token"))
	}

	// Ctrl-C must break a blocked stdin read, so exit directly on signal.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Fprintln(os.Stderr, "\nconsole: interrupted")
		os.Exit(0)
	}()

	op := *operator
	if op == "" {
		u, uerr := user.Current()
		hn, _ := os.Hostname()
		if uerr == nil {
			op = u.Username + "@" + hn
		} else {
			op = "console@" + hn
		}
	}

	repl := console.NewREPL(console.NewClient(addr, cfg.Teamserver.OperatorToken, op))
	if err := repl.Run(context.Background()); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "console:", err)
	os.Exit(1)
}
