---
name: Safe Loopback Testing
description: The checklist and workflow for running or writing tests for the reverse shell so nothing escapes the local machine. Use when running the test suite, writing a new test, or doing a manual agent↔teamserver smoke test. Enforces loopback-only, ephemeral ports, and clean teardown.
---

# Safe Loopback Testing

All routine testing happens over `127.0.0.1`. No test should open an externally
reachable listener or touch the internet.

## Before running anything

- Handler/test binds `127.0.0.1` (never `0.0.0.0`).
- If you need a second host, use the `lab-setup` skill instead of opening to the LAN.
- If a target is anything but loopback/lab, stop and run `authorization-scope` first.

## Running the suite

```bash
gofmt -l .          # must print nothing
go vet ./...
go test -race ./...
```

Fix lint/vet/test failures before declaring a task done. Report real results — if a
test fails, say so with the output; don't claim green when it isn't.

## Writing a new test

- Bind the listener to `127.0.0.1` on port `0` (ephemeral): `net.Listen("tcp", "127.0.0.1:0")`,
  read back the port with `l.Addr().(*net.TCPAddr).Port`, and point the agent at it.
  This avoids fixed open ports and collisions.
- Use short timeouts (or `context.WithTimeout`) so a hung socket fails fast instead of
  blocking the suite.
- Tear down every socket/session with `t.Cleanup`; assert nothing is left listening at
  the end.
- Prefer table-driven unit tests of `internal/protocol/` framing & envelope (fast,
  deterministic) over spinning up full agent↔teamserver for every case. Keep end-to-end
  to one small smoke test.
- Use `net.Pipe()` for in-memory integration tests when you don't need a real socket.
- Always run with `-race` — this project's concurrency is exactly what the race
  detector exists for.

## Manual smoke test

```bash
# Terminal 1 — teamserver on loopback (embedded listener + operator API)
go run ./cmd/teamserver --port 4444

# Terminal 2 — agent dials back
go run ./cmd/agent --host 127.0.0.1 --port 4444
```

Confirm a command round-trips, then Ctrl-C both. Check no listener remains:

```bash
# Windows:  netstat -ano | findstr 127.0.0.1
# Linux:    ss -ltnp | grep 127.0.0.1
```
