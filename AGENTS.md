# ReverseShell

A reverse-shell / lightweight command-and-control (C2) tool built for **authorized
security testing, education, and CTF practice**. The handler (operator side) listens
for connections that a client (agent side) initiates back to it — the "reverse"
direction that works through outbound-only / NAT'd networks.

This file is the shared contract for any agent (opencode, Claude, etc.) working in
this repo. Read it fully before editing code or running anything.

---

## ⚠️ Authorized use only — non-negotiable

This is a dual-use offensive-security tool. It is written and maintained **only** for:

- Systems you personally own.
- Lab / CTF / training environments.
- Engagements with **written authorization** and an explicit, signed scope
  (rules of engagement).

Hard rules for every contributor and every agent:

1. **Never** run the agent/teamserver against a host, network, or account you do not
   own or are not explicitly authorized (in writing) to test. If authorization or
   scope is unclear, **stop and ask the user** — see the `authorization-scope` skill.
2. **Default to loopback.** The handler binds `127.0.0.1` unless the operator passes
   an explicit flag. Automated tests must never open an externally reachable listener.
3. This repo must **not** contain real target data: no captured credentials, no live
   target IPs/hostnames, no session recordings from real engagements, no client PII.
   Keep that out of Git entirely.
4. **Out of scope for this project** (do not add, even if asked to "make it better"):
   worming / self-propagation, targeting of third parties, mass/untargeted
   deployment, supply-chain insertion, and anti-forensic or AV/EDR-evasion features
   whose purpose is to hide activity from a system's legitimate owner. Detection,
   logging, and audit features (the opposite direction) are welcome.

If a requested change would cross these lines, say so plainly and propose the
in-scope alternative instead of implementing it.

---

## Project status

Early-stage / greenfield. The repo is currently a skeleton (this file plus
`.opencode/`). The sections below describe the **intended** conventions so that the
first code written follows them. When real code lands, update this file to match
reality (prefer opencode's `/init` or edit in place rather than rewriting wholesale).

---

## Stack & layout

- **Language:** Go 1.23+ (standard library first; add dependencies only when they earn
  their place). Cross-platform: Linux and Windows.
- **Dependencies:** pinned in `go.mod`/`go.sum`. The only allowed external dependency is
  `github.com/BurntSushi/toml` (config parsing — stdlib has no TOML); everything else is
  stdlib. Binaries build statically with `CGO_ENABLED=0`.
- **Structure:** Go-idiomatic — entrypoints in `cmd/*/main.go`, all logic under
  `internal/` (compiler-enforced import boundary), tests colocated as `*_test.go`.

```
ReverseShell/
├── AGENTS.md
├── go.mod / go.sum    # module + pinned deps (the one: BurntSushi/toml)
├── Makefile           # build / lint / test / cross-compile targets
├── cmd/
│   ├── agent/         # implant/beacon binary: connects back to the listener
│   ├── teamserver/    # central server: embedded listener(s) + operator API + audit
│   ├── console/       # operator CLI: talks to the teamserver operator API only
│   └── listener/      # standalone remote listener (relay plane, later phase)
├── internal/
│   ├── protocol/      # session-plane wire protocol: framing, envelope, types, errors
│   ├── transport/     # pluggable session transports: tcp, tls, http(s) — one file each
│   ├── session/       # session registry, lifecycle, opaque IDs
│   ├── server/        # teamserver core: embedded listeners, dispatcher, audit log
│   ├── api/           # operator API (REST+SSE control plane)
│   ├── relay/         # listener↔teamserver relay protocol (remote listeners)
│   ├── agent/         # beacon loop, task executor, task kinds
│   └── console/       # operator REPL client
├── labs/              # throwaway lab configs (gitignored if they hold IPs)
└── .opencode/skills/  # reusable workflows (see "Skills" below)
```

Component model (professional C2 standard — 4 components / 3 planes):

- **Agent (implant)** connects out to a **listener**; the listener terminates implant
  connections and is embedded in the **teamserver** by default (standalone remote
  listeners come later via `internal/relay/`). The **console** is the operator's
  frontend and talks **only** to the teamserver's operator API (`internal/api/`) —
  operators never touch the session plane, so every operator action flows through one
  authenticated, auditable choke point.
- The teamserver is the crown jewel (all sessions + audit): its API binds `127.0.0.1`
  with a mandatory operator token; exposing it to a network requires an explicit flag
  plus TLS.
- Transport code is shared through `internal/transport/`, never duplicated between
  sides. The session-plane wire protocol lives in `internal/protocol/` and is
  language-agnostic by design.

---

## Commands

```bash
# Environment
go version                 # Go 1.23+

# Run the teamserver (embedded listener + operator API, loopback by default — safe)
go run ./cmd/teamserver

# Run the implant against a LOCAL listener for testing
go run ./cmd/agent --host 127.0.0.1 --port 4444

# Run the operator console against the local teamserver
go run ./cmd/console --token <operator-token-from-config>

# Quality gates — run these before declaring a task done
gofmt -l .                 # must print nothing
go vet ./...
go test -race ./...        # on Windows -race needs cgo (gcc/mingw); without a C
                           # toolchain run `go test ./...` locally — CI enforces -race
go build ./...
```

If the real commands differ, update this block — never leave agents guessing.

---

## Conventions

- **Safe defaults.** Listeners bind `127.0.0.1`; binding any other interface requires
  an explicit, documented flag. No "bind 0.0.0.0" as a default anywhere.
- **No hardcoded targets or secrets.** IPs, ports, hostnames, keys, and tokens come
  from CLI args, env vars, or a local config file that is **gitignored**. Never commit
  them. Never log a secret in plaintext.
- **One transport per module** under `internal/transport/`, all implementing the same small
  interface (`Dial`/`Listen`, `Send`, `Recv`, `Close`). Shared framing lives in
  `internal/protocol/`, not inside a transport.
- **Explicit protocol.** Length-prefix every message; never assume one `recv` equals
  one message. Validate and bound-check all input decoded off the wire — treat the
  peer as untrusted even in the lab.
- **Idiomatic Go, enforced by tooling.** Format with `gofmt`; vet with `go vet`; tests run
  with `-race`. Doc comments on exported identifiers. Wrap errors with `%w`; respect
  `context.Context` cancellation; `defer` every resource acquisition.
- **No commented-out code** and no comments that merely restate the code. Comment the
  *why* when it is not obvious.
- **Errors over silent failures.** Network and parsing errors are logged and surfaced,
  never swallowed.

---

## Testing & safety

- **Loopback only.** Tests connect agent↔teamserver (embedded listener) over `127.0.0.1`. A test must never
  open a listener reachable from outside the machine, and must never reach the public
  internet.
- Bind ephemeral ports in tests (`net.Listen("tcp", "127.0.0.1:0")`, read back the
  assigned port) so tests don't collide or require a fixed open port.
- Every test tears down its sockets/sessions with `t.Cleanup`; no lingering listeners
  after the run. Use `net.Pipe()` for in-memory integration tests.
- Prefer fast, deterministic unit tests of the protocol/framing in `internal/protocol/`
  over end-to-end tests. Keep end-to-end tests to a small loopback smoke test.
- See the `lab-setup` skill for an isolated environment when you need to test against
  a second machine, and `safe-test` for the loopback checklist.

---

## Logging & accountability

- Every operator action and every session event is logged with a timestamp to a local
  log (structured/JSON preferred). This is an accountability feature, not optional.
- Logs record **what the operator did**; they must not contain secrets or captured
  target data. See the `operator-logging` skill.
- Clean up artifacts you create while testing (temp files, sockets, lab containers).

---

## Git

- Git initialized but no commits yet. First commit: `AGENTS.md`, `README.md`,
  `.opencode/`, `.gitignore`, `go.mod`/`go.sum`, source, and tests. **Never** commit:
  `bin/`, `config.toml` (real IPs/keys), logs, session recordings, or anything under
  `labs/` that names a real host. Add a `.gitignore` first.
- Do not commit unless the user explicitly asks.

---

## Skills

Reusable workflows live in `.opencode/skills/`. opencode advertises each one and loads
it with the `skill` tool when relevant. Load the matching skill instead of improvising:

| Skill | Use it when |
|-------|-------------|
| `authorization-scope` | **Before** any run or test that could touch a host you don't own. Pre-flight authorization & scope gate. |
| `lab-setup` | Standing up an isolated, no-egress lab (VMs/containers) to test safely. |
| `safe-test` | Running or writing tests — the loopback-only checklist and how to run the suite. |
| `transport-module` | Adding a new transport (tcp/tls/http…) under `internal/transport/` following the shared interface. |
| `operator-logging` | Adding or reviewing logging/audit of operator actions and session events. |
| `engagement-report` | Writing up findings / an engagement report from authorized testing. |

When a task matches a skill's description, load it first — it carries the detailed,
up-to-date steps that this file only summarizes.
