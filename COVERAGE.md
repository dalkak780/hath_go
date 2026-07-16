# Test coverage policy

This project excludes inherently untestable runtime/bootstrap glue from the
coverage gate, the same way a Spring application excludes `SpringApplication.run()`
or a Python project marks handlers with `# pragma: no cover`.

## How it works

`make gate` runs the tests, **strips the files in `COVERAGE_EXCLUDE`** (defined in
the Makefile) from the coverage profile, then computes the percentage and fails
below `GATE`. `make cover` prints the unfiltered per-file breakdown for inspection.

```make
GATE             := 85
COVERAGE_EXCLUDE := lifecycle.go
```

## Excluded files

| File           | Why it is excluded                                                                 |
|----------------|------------------------------------------------------------------------------------|
| `lifecycle.go` | The `os.Exit` terminal handler (`dieErr`). It cannot be unit-tested without a subprocess; tests override it via the injectable `fatalError` var. This is the direct analog of `SpringApplication.run()`. |

Note: `cmd/hath/main.go` (the process entrypoint) is not part of the
`internal/hath` package that the gate measures, so it is naturally excluded.

## Current numbers (after exclusion)

Total ~**87%** of statements, with the protocol-critical surface — the part that
can lock the account if wrong — effectively fully covered:

- `protocol.go` (auth formulas) — pinned to independent `shasum(1)` vectors
- `rpc.go` (all RPC actions, actkey, KEY_EXPIRED retry, failover) — validated by
  a mock RPC server that recomputes the actkey on every request
- `server.go` routing (`/h`, `/servercmd`, `/t`) — valid + bad signatures
- `bandwidth.go`, `stats.go`, `cert.go`, `settings.go` — ≥90%
- End-to-end: a full client + real PKCS#12 + live TLS edge server against the mock

## Residual uncovered (deliberately not chased)

The remaining ~13% is **testable-but-low-value defensive code**, not untestable glue:

- defensive network/parse error branches in `rpc.fetch`/`fetchFile` and the cache
  prune inner loop (triggered only by malformed peers / I/O races);
- the pruner's 300-tick free-disk watchdog → `dieErr` (gated on 5 min of ticks,
  impractical to drive in a unit test);
- a few long-sleep production paths (cert refresh, gallery suspend).

Cross-checking these against a live Java instance remains outside the
automated test suite.

## Pushing the gate higher

To raise the gate toward 95%: refactor the pruner's disk-watchdog tick counter
to be injectable (removes the time-gated `dieErr`), and add subprocess tests for
the real `os.Exit` (which would let `lifecycle.go` back into the measured set).
