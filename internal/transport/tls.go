package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
)

func init() { Register(TLS{}) }

// TLS carries the session plane over TLS on top of the shared framing
// (README §8.2). The listener authenticates with a certificate; the agent
// verifies it against a CA by default — skipping verification is an
// explicit, warned, lab-only opt-in.
type TLS struct{}

// Name implements Transport.
func (TLS) Name() string { return "tls" }

// Dial implements Transport.
func (TLS) Dial(ctx context.Context, addr string, opt Options) (Conn, error) {
	roots, err := loadCAPool(opt.CAFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		RootCAs:            roots,
		ServerName:         opt.ServerName,
		InsecureSkipVerify: opt.InsecureSkipVerify, // explicit lab opt-in (README §8.2)
	}
	if cfg.ServerName == "" {
		if host, _, serr := net.SplitHostPort(addr); serr == nil {
			cfg.ServerName = host
		}
	}
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tls dial %s: %w", addr, err)
	}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("tls handshake %s: %w", addr, err)
	}
	return newTCPConn(tc, opt), nil
}

// Listen implements Transport.
func (TLS) Listen(_ context.Context, addr string, opt Options) (Listener, error) {
	if opt.CertFile == "" || opt.KeyFile == "" {
		return nil, fmt.Errorf("tls transport requires cert and key files")
	}
	cert, err := tls.LoadX509KeyPair(opt.CertFile, opt.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("tls load keypair: %w", err)
	}
	l, err := tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return nil, fmt.Errorf("tls listen %s: %w", addr, err)
	}
	return &tcpListener{l: l, opt: opt}, nil
}

// loadCAPool reads an optional CA bundle; nil means "system roots".
func loadCAPool(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("tls read CA %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("tls CA %s contains no certificates", caFile)
	}
	return pool, nil
}
