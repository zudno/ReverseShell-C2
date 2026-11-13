---
name: Operator Logging & Audit
description: Add or review logging and audit of operator actions and session events in the teamserver/agent. Use when building command handling, session management, or when the user wants an audit trail. Enforces timestamped, structured logs that capture what the operator did without storing secrets or captured target data.
---

# Operator Logging & Audit

Accountability is a feature of this tool, not an afterthought. Every operator action
and session event is logged. This both supports authorized engagements (you can show
exactly what you did) and keeps the project honest.

## What to log

- Session lifecycle: client connected / disconnected, from which (lab) address, which
  transport, timestamps.
- Every command the operator issues and a reference to its result (e.g. result size /
  exit status), with timestamps.
- Config at startup: bind address, port, transport — so a log explains how a run was set up.
- Authorization reference for the run (scope/RoE id), captured at start per the
  `authorization-scope` skill.

## What NOT to log

- **No secrets:** keys, tokens, passwords — never in plaintext, never at all if
  avoidable. Redact.
- **No captured target data / PII.** Log *that* a command ran and its metadata, not a
  dump of what it returned. Keep real target content out of the repo and out of logs.

## How

- Structured, one event per line (JSON lines) to a local file under a `logs/` dir that
  is **gitignored**. Include an ISO-8601 UTC timestamp, an event type, and a session id.
- Use Go's `log/slog` with `slog.JSONHandler`; don't `fmt.Println`. Default level `INFO`;
  `DEBUG` only behind a flag and still subject to the redaction rules.
- Make redaction a single choke point (one `Redact()` helper) so secrets can't leak
  through a new log call someone adds later.

```go
logger.LogAttrs(ctx, slog.LevelInfo, "operator.task",
    slog.String("sid", sid), slog.String("kind", kind), slog.String("cmd", cmd))
// never: slog.String("output", rawOutput)   // captured data — don't
```

## Review checklist

- Does any log line carry a secret or raw target output? Remove/redact it.
- Is `logs/` gitignored? Are existing logs free of real target data before any commit?
- Do session start/stop and each command produce an auditable, timestamped event?
