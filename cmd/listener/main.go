// Command listener runs a standalone remote listener: it terminates implant
// connections locally and forwards whole frames to the teamserver over the
// relay plane (README §6.2).
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"

	"reverseshell/internal/config"
	"reverseshell/internal/relay"
	"reverseshell/internal/transport"
)

func main() {
	var (
		cfgPath       = flag.String("config", "config.toml", "path to TOML config (optional)")
		host          = flag.String("host", "", "session listener bind host (overrides config)")
		port          = flag.Int("port", 0, "session listener port (overrides config)")
		transportName = flag.String("transport", "", "session transport (overrides config)")
		teamserver    = flag.String("teamserver", "", "teamserver relay address host:port (overrides config)")
		token         = flag.String("token", "", "relay token (overrides config)")
		name          = flag.String("name", "", "listener name shown in the teamserver audit log")
	)
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fail(err)
	}
	if *host != "" {
		cfg.Listener.Host = *host
	}
	if *port != 0 {
		cfg.Listener.Port = *port
	}
	if *transportName != "" {
		cfg.Listener.Transport = *transportName
	}
	relayAddr := *teamserver
	if relayAddr == "" {
		if cfg.Relay.Port == 0 {
			fail(fmt.Errorf("no relay configured: pass --teamserver host:port or set [relay] host/port"))
		}
		relayAddr = net.JoinHostPort(cfg.Relay.Host, strconv.Itoa(cfg.Relay.Port))
	}
	relayToken := *token
	if relayToken == "" {
		relayToken = cfg.Relay.Token
	}
	if relayToken == "" {
		fail(fmt.Errorf("relay token required: pass --token or set [relay] token"))
	}
	listenerName := *name
	if listenerName == "" {
		listenerName, _ = os.Hostname()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tr, err := transport.ByName(cfg.Listener.Transport)
	if err != nil {
		fail(err)
	}
	l, err := tr.Listen(ctx, net.JoinHostPort(cfg.Listener.Host, strconv.Itoa(cfg.Listener.Port)), transport.Options{
		MaxFrameBytes: cfg.Listener.MaxFrameBytes,
		CertFile:      cfg.TLS.Cert,
		KeyFile:       cfg.TLS.Key,
	})
	if err != nil {
		fail(err)
	}
	defer l.Close()

	client, err := relay.Dial(ctx, relay.ClientConfig{
		Addr:     relayAddr,
		Token:    relayToken,
		Name:     listenerName,
		CAFile:   cfg.Relay.CA,
		Insecure: cfg.Relay.Insecure,
	})
	if err != nil {
		fail(err)
	}
	defer client.Close()

	fmt.Fprintf(os.Stderr, "listener %q: sessions on %s (%s), relayed to %s\n",
		listenerName, l.Addr().String(), cfg.Listener.Transport, relayAddr)

	var wg sync.WaitGroup
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			fmt.Fprintln(os.Stderr, "listener: accept:", err)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A dropped implant is routine; the teamserver's STALE
			// reaper and audit trail account for it.
			_ = client.Forward(ctx, conn)
		}()
	}
	wg.Wait()
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "listener:", err)
	os.Exit(1)
}
