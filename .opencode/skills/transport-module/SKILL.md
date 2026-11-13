---
name: Add a Transport Module
description: Add a new transport (e.g. tcp, tls, http) under internal/transport/ following the project's shared interface, so the teamserver's listener and the agent can carry the session over it. Use when the user wants a new connection method or asks to refactor transport code. Keeps framing in internal/protocol/ and enforces safe defaults.
---

# Add a Transport Module

Transports are pluggable and interchangeable. The teamserver and agent never embed
transport details — they talk to the common interface. Message framing stays in
`internal/protocol/`, never inside a transport.

## The interface

Each transport in `internal/transport/<name>.go` implements the same small contract:

```go
// internal/transport/transport.go (reference)

// Conn delivers whole framed messages.
type Conn interface {
    Send(ctx context.Context, frame []byte) error
    Recv(ctx context.Context) ([]byte, error)
    Close() error
}

type Listener interface {
    Accept(ctx context.Context) (Conn, error)
    Close() error
}

type Transport interface {
    Name() string
    Dial(ctx context.Context, addr string, opt Options) (Conn, error)      // client side
    Listen(ctx context.Context, addr string, opt Options) (Listener, error) // handler side
}
```

`Send`/`Recv` operate on **whole messages**. Use the length-prefix framing from
`internal/protocol/` (`WriteFrame`/`ReadFrame`) — never assume one socket read
equals one message.

## Steps

1. Create `internal/transport/<name>.go` implementing the interface. Reuse
   `internal/protocol/` framing; do not re-implement it.
2. Register it in the transport factory (`internal/transport/transport.go`) so
   `--transport <name>` selects it on both sides.
3. **Safe defaults:** the listen side binds `127.0.0.1` unless an explicit flag says
   otherwise. No `0.0.0.0` default.
4. **Validate input off the wire.** Bound-check lengths; treat the peer as untrusted.
   Fail closed on malformed frames.
5. For TLS: verify certificates by default; make "insecure/skip-verify" an explicit,
   logged opt-in used only in the lab. Keep keys/certs out of Git.
6. Add a loopback test (`<name>_test.go`) mirroring the existing transport tests
   (see `safe-test`): round-trip a few messages, including a large one that spans
   multiple reads. Use `net.Pipe()` where a real socket isn't needed.
7. Run the quality gates: `gofmt -l .`, `go vet ./...`, `go test -race ./...`.

## Don't

- Don't add transports whose point is to evade a system owner's monitoring. Transports
  exist to move the session, not to hide it from the machine's legitimate owner.
- Don't duplicate framing or session logic into the transport.
- Don't hardcode hosts/ports/keys — they come from args/env/config.
