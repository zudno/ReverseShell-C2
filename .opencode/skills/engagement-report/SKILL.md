---
name: Engagement Report & Findings
description: Write up findings and an engagement report from authorized testing done with this tool. Use when the user asks to document a finding, produce a pentest/CTF report, or summarize what a test demonstrated. Produces clear, reproducible, remediation-focused writeups.
---

# Engagement Report & Findings

Turn authorized testing into a report the owner can act on. A finding is only useful if
it is reproducible and tied to a fix. Only document testing that was authorized and
in scope (see `authorization-scope`).

## Per-finding template

```markdown
### <Short finding title>

- **Severity:** Critical / High / Medium / Low / Info  (+ CVSS vector if used)
- **Affected asset:** <in-scope host/app/component>  (lab or authorized target only)
- **Authorization:** <scope / RoE reference>

**Summary**
One or two sentences: what the issue is and why it matters.

**Steps to reproduce**
1. ...
2. ...
(Exact, minimal steps. Reference the operator log timestamps.)

**Evidence**
Commands run and relevant output — with secrets and real PII redacted.

**Impact**
What an attacker could do; what data/systems are at risk.

**Remediation**
Concrete, prioritized fix(es). Link vendor/standard guidance where relevant.
```

## Report structure

1. **Executive summary** — plain-language risk picture for non-technical readers.
2. **Scope & authorization** — what was tested, the window, the authorization reference.
3. **Methodology** — high-level approach and tools.
4. **Findings** — each using the template, ordered by severity.
5. **Remediation summary** — a prioritized table (finding → fix → effort).
6. **Appendix** — environment details; redacted logs.

## Rules

- **Reproducible and accurate.** If something was not confirmed, say so; don't inflate
  severity. Report real results.
- **Redact** secrets and real PII from evidence. The report should not become a second
  copy of sensitive target data.
- **Remediation-first.** Every finding ends with how to fix it. Defensive value is the
  point of the exercise.
- Write to a Markdown file in the repo (e.g. `reports/<date>-<engagement>.md`); keep
  reports with real target data **out of Git** (gitignore `reports/`).
