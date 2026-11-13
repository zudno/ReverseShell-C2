---
name: Isolated Lab Setup
description: Stand up a safe, isolated environment to test the reverse shell when loopback alone isn't enough (you need a separate "target" machine). Covers an air-gapped/no-egress virtual network with throwaway VMs or containers. Use when the user wants to test agent↔listener across two hosts, or asks how to test without risk to real networks.
---

# Isolated Lab Setup

Goal: a second "target" host to test against, with **no path to any real network or
the internet**. Everything here is disposable.

## Principles

- **No egress.** The lab network must not route to the LAN or internet. Use a
  host-only / internal virtual network, not NAT/bridged.
- **Disposable.** Snapshot before testing; revert after. Never store anything you
  care about on lab machines.
- **Non-routable addressing** inside the lab (e.g. an RFC1918 range reserved for the
  lab). Document the chosen range in `labs/README.md` (gitignored if it could be
  mistaken for a real target).

## Option A — Containers (fastest)

Two containers on a user-defined bridge with `internal: true` so Docker gives them no
outbound route:

```yaml
# labs/compose.yml  (keep out of Git if it ever holds real values)
networks:
  labnet:
    internal: true          # no egress — key safety property
services:
  teamserver:              # Dockerfile building cmd/teamserver (listener embedded)
    build: ../
    networks: [labnet]
  target:                   # Dockerfile building cmd/agent (the implant)
    build: ../
    networks: [labnet]
```

Verify isolation before testing:

```bash
docker compose -f labs/compose.yml run --rm target \
  sh -c "ping -c1 -W1 8.8.8.8 || echo 'no egress — good'"
```

## Option B — Virtual machines (closest to real targets)

- Create 2 VMs (attacker + target) on a **host-only** network in VirtualBox/VMware/
  Hyper-V. Do not attach a NAT/bridged adapter.
- Snapshot both clean. Test. Revert to snapshot afterward.
- Confirm the target VM cannot reach the internet (`ping`/`curl` a public IP should
  fail) before running anything.

## After testing

- Revert snapshots / `docker compose down -v`.
- Confirm no lab listener is still bound on the host.
- Record what was run in the operator log (`operator-logging`).

Only move beyond the lab under the `authorization-scope` gate.
