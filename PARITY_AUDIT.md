# Java → Go behavioral parity audit

Status: **production migration blocked** pending a successful canary rerun.
The first canary exposed an unimplemented inbound `servercmd/speed_test` body:
Go returned an empty 200 where Java returns the requested random byte count.
The Java startup admission gate remains intact; production evidence is not
inferred until the corrected implementation passes a canary rerun.

Reference: `hath_java/src/hath/base/` (Hentai@Home 1.6.5, build 178).

## Closed-world behavioral model

The parity boundary is the headless Java client: command-line/filesystem input,
outbound RPC and origin traffic, inbound TLS/HTTP traffic, persistent files,
timers/signals, and resulting logs/statistics. GUI rendering and interactive
credential prompting are outside the boundary; no other behavior is assumed.

| State | Accepted events | Observable transition/output |
|---|---|---|
| Boot | args, directories, `client_login`, environment | Java-compatible defaults and validation; invalid headless credentials terminate before authenticated RPC |
| Registering | `server_stat`, `client_login` responses | clock/RPC endpoints/settings applied; NULL/FAIL/failover and KEY_EXPIRED paths are explicit |
| Cache ready | cache tree, persistent snapshot, disk space | authoritative tree scan/cleanup, counters/LRU/age table, pruner start, or terminal storage failure |
| Listening-gated | certificate response, bind, inbound connection, `client_start` | TLS 1.2/1.3 listener is bound first; only local/configured RPC IPs pass admission; `/t` and every server command have defined responses |
| Diagnostic | failed `client_start`, signal, listener death | gated listener remains alive like Java; signal exits cleanly, listener death is terminal |
| Running | inbound HTTP, timers, server commands, RPC replies | normal admission, cache/proxy/gallery service, exact 10-second scheduler counter, heartbeat/settings/blacklist/flood/prune/stat transitions |
| Suspended | timeout or resume request | cycles pause without counter movement; resume resets counter to zero, updates stats, and notifies RPC |
| Certificate restart | `refresh_certs`, suspend/fetch/bind result | suspend, delay, close listener, fetch/validate/promote PFX, rebind, allow normal traffic, send resume heartbeat; any reinitialization failure is terminal |
| Shutdown | signal/context/fatal listener | `client_stop` only if startup succeeded, listener drain, pruner stop, cache persistence, process return |

Every event accepted in a state has an explicit success, protocol failure,
transport failure, malformed-input, timeout, and shutdown outcome. Tests use
only local mock peers; the Java client and production RPC endpoint are never
executed by this audit.

## What existing evidence proves

- `rpcverify`: captured authenticated RPC query construction and `actkey` parity
  for 336 requests.
- Unit coverage: exercised approximately 95% of Go statements, excluding
  lifecycle/logging glue.
- Cross-build and container tests: proved the binaries and image can be built.

These checks do **not** prove JVM/Go library interoperability, PKCS#12 bag
semantics, filesystem behavior, listener lifecycle, scheduler/concurrency,
HTTP implementation details, or failure recovery.

## Classification

- **Equivalent**: behavior and relevant edge cases are directly verified.
- **Intentional**: different from Java by design and documented.
- **Unverified**: appears equivalent but lacks an interoperability fixture.
- **Divergent**: observable behavior differs from Java.
- **Bug**: divergence can break protocol operation, safety, or availability.

## Critical / production-blocking findings

| Area | Classification | Finding |
|---|---|---|
| PKCS#12 | Fixed and verified | An original server bundle decoded successfully as one RSA key and three certificates. The `hath.network` alias and local-key-ID match on the key and leaf, the public keys match, and both available issuer signatures verify. The final supplied certificate is intentionally not self-signed because its trust anchor is omitted. The server envelope is SHA-1 MAC/2048, three RC2-40 certificate bags/2048, and one 3DES shrouded keybag/2048. A format-matched fixture and end-to-end three-certificate TLS handshake pass. |
| TLS startup | Fixed | Listener binding is synchronous and proven before `client_start`; bind-failure coverage passes. |
| TLS refresh | Fixed | Java's suspend, delay, listener shutdown, PFX fetch, listener restart, normal-admission enable, and `still_alive;add=resume` sequence is reproduced. A failed restart is terminal while the last valid PFX remains intact. |
| Listener death | Fixed | Unexpected `Serve` termination is sent to `Run`, which terminates the client rather than continuing heartbeats. |
| RPC HTTP status | Fixed | Text RPC requires 2xx and retries three times. Status/retry/short-read/CRLF/ASCII coverage passes. |
| Settings parsing | Fixed | Numeric parse failures preserve the previous value; server time, ports, limits, and counts have regression coverage. |
| Gallery pause | Fixed | Suspension and low-space checks run before every file download. |
| Disk query failure | Fixed | Filesystem query errors return zero and all space checks fail closed. |
| Bandwidth | Fixed | Accepted non-local connections enable the shared outbound limiter. |
| Statistics | Fixed | Plaintext socket writes, including HTTP headers and bodies, update `Stats.BytesSent`. |
| Concurrency | Fixed under race gate | Client/gallery state, pruner shutdown/frequency, certificate rotation, imports/verification, and settings range maps are synchronized. `go test -race ./internal/hath` passes with the loopback-only test guard. |
| Cache persistence | Fixed | Startup always scans the authoritative filesystem instead of trusting a crash-stale snapshot; crash/restart import and deletion coverage passes. |
| Startup speedtest | Fixed; canary rerun pending | Java permits only configured RPC-server IPs during startup. Go retains that gate and now implements both `/t` and `/servercmd/speed_test`, including exact size, content type, cache header, and HEAD behavior. |

## High-impact divergences

### RPC and settings

- Text RPC and origin downloads retry three times.
- `server_stat`, including clock recovery, always uses the special
  unauthenticated URL.
- RPC text is decoded as US-ASCII; gallery metadata retains Java's UTF-8 path.
- CRLF status lines are rejected exactly like Java; only LF is accepted.
- Static/gallery source strings are accepted only as absolute HTTP(S) URLs.
- RPC server names use resolver semantics, a failed list update preserves the
  old list, and the default host ignores the custom port like Java.
- `StaticRangeCount` is derived while parsing `static_ranges` and may later be
  replaced by an explicit `static_range_count` update.

### Certificate and TLS

- A keytool fixture verifies the `hath.network` alias/local-key-ID layout.
  Selection is by private/public-key association rather than bag position.
- Only the associated, signature-verified issuer chain is transmitted, in
  leaf-to-root order; unrelated bags are ignored.
- Malformed/expired downloads never replace the persisted known-good PFX.
- Every certificate retry rebuilds its authenticated URL and timestamp.
- IP admission runs before TLS handshake; handshake failures are not counted.
- TLS 1.2/1.3 policy matches, but JSSE and Go cipher/session defaults differ.

### HTTP server

- Connection limits are counted at accept/admission time. Before `client_start`
  only configured RPC-server IPs are admitted, matching Java.
- Responses force `Connection: close`; one request is served per connection.
- Java's direct HTTP error body, MIME, cache header, and length are reproduced.
- Cached/proxied files ignore range and conditional headers like Java and send
  explicit full-response lengths.
- Command dispatch and keystamps are case-insensitive; server-command hashes
  use the original command bytes exactly like Java.
- `xres` is whole-string validated.
- Shutdown waits up to Java's 25-second drain window before forcing handlers
  closed.
- `client_stop` is sent only after successful `client_start`.

### Cache, gallery, and filesystem

- Gallery metadata rejects missing/duplicate/nonnumeric/out-of-range/duplicate
  pages and requires exactly `FILECOUNT` entries.
- Gallery SHA-1 mismatches use the same failure-report path as download errors.
- Empty/invalid ranges do not retain phantom age entries.
- Persistent snapshots are not trusted; the filesystem is revalidated on every
  startup, including existing Java cache layouts.
- Same-ID imports are idempotent and import/prune/background verification share
  the cache lock.
- File sizes above Java's signed 32-bit limit are rejected.
- Cache stats include the estimated half-block-per-file overhead.
- Directories/files use `0777`/`0666` creation masks so process umask determines
  the effective Java-compatible mode.
- Java and Go differ for directory-path collisions, Unicode/UTF-16 title length,
  and Windows reserved names. `galleryinfo.txt` preserves Java's UTF-8 content
  and platform line separator byte-for-byte, including its single final newline.
- Unix free-space uses `Bfree`, matching Java `File.getFreeSpace` semantics.

## Intentional or accepted differences

These must remain documented rather than described as exact parity:

- GUI and interactive credential prompts are omitted.
- Go uses `net/http` instead of Java's handwritten HTTP parser.
- Go uses safer atomic temporary-file replacement in several download paths.
- Go does not delete a regular file that collides with a required directory.
- Unicode filename handling is safer than Java's UTF-16/path behavior.
- Credential files use restrictive permissions on POSIX.
- Some Java thread crashes are recovered by Go maintenance goroutines.

## Required release gates

A production migration must not be recommended until all of these pass:

1. `go test ./...` — **passes with loopback-only network guard**
2. `go test -race ./internal/hath` — **passes with loopback-only network guard**
3. Java/server-issued PFX fixture test — **passes; an original server bundle
   decoded successfully and the exact server-envelope fixture passes**:
   - alias `hath.network`
   - local-key-ID association
   - leaf/intermediate/root or actual server bag layout
   - end-to-end TLS handshake proving served leaf and chain
4. Listener bind-failure and unexpected-listener-death tests — **pass**.
5. Certificate refresh/restart success and terminal failure tests, including
   preservation of the last valid PFX — **pass**.
6. Captured RPC replay including HTTP status, malformed/timeout response, and
   retry behavior—not only query/auth parity — **passes**. A sanitized replay
   pins the successful Java startup order and exact common wire headers from
   the 456-record packet-proxy capture. Synthetic tests cover status,
   malformed/short, timeout, and retry paths because the supplied capture
   contains only HTTP 200 exchanges.
7. Existing Java cache/data fixture startup, mutation, forced crash, and restart
   test — **passes against 20 files from a copied 7.3GB Java cache**. Every
   sampled path, declared size, and SHA-1 matched; actual Go `CacheHandler`
   startup/restart counts were 20, 19 after deletion with a stale snapshot,
   and 20 after restoration. The source fixture remained read-only.
8. Low-space/unavailable-mount test proving fail-closed behavior — **passes**.
9. Canary startup with container restart disabled; only enable restart after a
   complete `notifyStart` and externally verified TLS response — **first run
   failed with `FAIL_INITIAL_SPEEDTEST:` and exposed the missing
   `/servercmd/speed_test` response above; fixed locally, rerun pending**.

## Migration safety policy

- Never start a new implementation with `restart: unless-stopped` during the
  first migration.
- Keep the Java image and all five volumes available for immediate rollback.
- Do not infer whole-client compatibility from line coverage or RPC signatures.
- Classify untested runtime/library semantics as **unverified**, not equivalent.
