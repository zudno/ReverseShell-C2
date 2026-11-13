// Command teamserver runs the ReverseShell central server: the embedded
// session listeners and the operator API (README §2).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"reverseshell/internal/api"
	"reverseshell/internal/config"
	"reverseshell/internal/protocol"
	"reverseshell/internal/server"
)

func main() {
	var (
		cfgPath      = flag.String("config", "config.toml", "path to TOML config (optional)")
		listenerHost = flag.String("listener-host", "", "session listener bind host (overrides config)")
		listenerPort = flag.Int("listener-port", 0, "session listener port (overrides config)")
		transport    = flag.String("transport", "", "session transport (overrides config)")
		apiHost      = flag.String("api-host", "", "operator API bind host (overrides config)")
		apiPort      = flag.Int("api-port", 0, "operator API port (overrides config)")
		token        = flag.String("token", "", "operator bearer token (overrides config/env)")
	)
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fail(err)
	}
	if *listenerHost != "" {
		cfg.Listener.Host = *listenerHost
	}
	if *listenerPort != 0 {
		cfg.Listener.Port = *listenerPort
	}
	if *transport != "" {
		cfg.Listener.Transport = *transport
	}
	if *apiHost != "" {
		cfg.Teamserver.APIHost = *apiHost
	}
	if *apiPort != 0 {
		cfg.Teamserver.APIPort = *apiPort
	}
	if *token != "" {
		cfg.Teamserver.OperatorToken = *token
	}
	if cfg.Teamserver.OperatorToken == "" {
		fail(errors.New("operator token required: set [teamserver] operator_token in the config file, RS_TEAMSERVER_OPERATOR_TOKEN, or pass --token (generate: openssl rand -hex 32)"))
	}

	srv, err := server.New(server.Config{
		TransportName: cfg.Listener.Transport,
		ListenerAddr:  net.JoinHostPort(cfg.Listener.Host, strconv.Itoa(cfg.Listener.Port)),
		MaxFrameBytes: cfg.Listener.MaxFrameBytes,
		AuditLogPath:  cfg.Audit.Log,
		SessionCfg: protocol.SessionConfig{
			HeartbeatInterval: cfg.Session.HeartbeatInterval,
			HeartbeatJitter:   cfg.Session.HeartbeatJitter,
			MaxFrameBytes:     cfg.Listener.MaxFrameBytes,
		},
	})
	if err != nil {
		fail(err)
	}
	apiSrv, err := api.New(api.Config{
		Addr:    net.JoinHostPort(cfg.Teamserver.APIHost, strconv.Itoa(cfg.Teamserver.APIPort)),
		Token:   cfg.Teamserver.OperatorToken,
		Backend: srv,
		Audit:   srv.Audit(),
	})
	if err != nil {
		fail(err)
	}

	fmt.Fprintf(os.Stderr, "teamserver: session listener %s (%s)\nteamserver: operator API http://%s\n",
		srv.ListenAddr(), cfg.Listener.Transport, apiSrv.Addr())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 2)
	go func() { errCh <- apiSrv.Run(ctx) }()
	go func() { errCh <- srv.Run(ctx) }()

	first := <-errCh
	stop()
	second := <-errCh
	for _, err := range []error{first, second} {
		if err != nil {
			fail(err)
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "teamserver:", err)
	os.Exit(1)
}
