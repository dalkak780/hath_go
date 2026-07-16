# Java → Go behavioral parity audit

Status: **production migration blocked** pending closure of the critical items below.

Reference: `hath_java/src/hath/base/` (Hentai@Home 1.6.5, build 178).

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
| PKCS#12 | Bug, fixed in `1326bca` | The old Go decoder required exactly a private key and one certificate. Real server PFX contained additional certificate safe bags. `DecodeChain` now accepts them, but real keytool/server fixtures, alias selection, key association, and chain-order validation remain unverified. |
| TLS startup | Bug | Go starts the listener asynchronously, waits 200 ms, and reports startup success even if bind/serve fails. Java binds synchronously before `notifyStart`. |
| TLS refresh | Bug | Go shuts down the working listener before validating the replacement certificate, and clears the retry flag even after failure. It can remain registered without serving TLS. |
| Listener death | Bug | Unexpected Go HTTP server termination is only logged. Java terminates the client instead of continuing heartbeats as a dead node. |
| RPC HTTP status | Bug | Go text RPC parsing accepts bodies from non-2xx HTTP responses. Java treats HTTP errors as download failures and retries. |
| Settings parsing | Bug | Go converts malformed numeric server settings to zero. Java preserves the old value after parse failure. This can corrupt server time, ports, throttles, and limits. |
| Gallery pause | Bug | Go checks suspension/low disk after downloading a file. Java checks before the download. |
| Disk query failure | Bug | Go treats a failed free-space query as unlimited space. Java generally yields zero and pauses/stops conservatively. |
| Bandwidth | Bug | Accepted Go connections never set `trackedConn.throttle`; configured outbound throttling is bypassed. |
| Statistics | Bug | Go HTTP writes do not call `Stats.BytesSent`; byte history and totals are wrong. |
| Concurrency | Bug | `go test -race` reports races in client/gallery state, pruner state, certificate refresh/server replacement, and gallery loops. Settings map replacement also races with readers. |
| Cache persistence | Bug | Go writes a startup snapshot before validation and does not update it after imports/deletes. A crash can leave stale state that is trusted on restart. |

## High-impact divergences

### RPC and settings

- Java retries text RPC downloads three times; Go currently performs one
  60-second whole-request attempt.
- `KEY_EXPIRED` retry for `server_stat` uses an authenticated Go URL instead of
  Java's special unauthenticated stat URL.
- Java decodes RPC text as US-ASCII; Go preserves arbitrary UTF-8 bytes.
- Java rejects CRLF status lines; Go normalizes CRLF. This is a benign
  robustness difference, not exact parity.
- Java validates returned static/gallery source strings as URLs; Go returns
  malformed strings to callers.
- Go gallery/origin downloads have fewer retries than Java.
- Go accepts hostnames differently in the RPC server list and applies the
  custom RPC port differently to the default host.
- Go does not derive `StaticRangeCount` from `static_ranges` unless a separate
  count setting is sent.

### Certificate and TLS

- Java selects the `hath.network` KeyStore alias and lets KeyManagerFactory
  associate keys/certificates. Go currently assumes the first certificate bag
  is the leaf and one private key exists.
- Go transmits every extra certificate bag in input order without proving an
  issuer chain. A Java/keytool/server PFX fixture and TLS handshake assertion
  are required.
- A downloaded malformed/expired PFX replaces the persisted known-good file
  before validation. There is no rollback to the previous certificate.
- Certificate retries can reuse an authenticated URL long enough for its key to
  expire.
- TLS handshake errors are ignored during listener admission.
- TLS 1.2/1.3 policy matches, but JSSE and Go cipher/session defaults differ.

### HTTP server

- Go connection limits are counted on first read, not accept; bursts can exceed
  the configured maximum.
- Java serves one request and closes the connection. Go permits keep-alive and
  has no idle timeout.
- Java's request/header bounds and error bodies differ from `net/http`.
- `http.ServeContent` adds range and conditional-request behavior Java does not
  provide, and Go statistics/logging currently do not reflect the final status.
- Java command dispatch and keystamp hex comparison are case-insensitive; Go is
  case-sensitive.
- Go's `xres` regex is substring-based and accepts values Java rejects.
- Go immediately closes active handlers on shutdown; Java waits for sessions to
  drain.
- Go can send `client_stop` even when startup never completed; Java only reports
  shutdown after successful startup notification.

### Cache, gallery, and filesystem

- Gallery metadata parsing in Go accepts missing, duplicate, nonnumeric, or
  out-of-range pages that Java rejects.
- Go does not report a gallery SHA-1 mismatch through the same downloader
  failure path as Java.
- Go can retain a phantom static-range age entry after startup removes every
  invalid file in the range.
- Go persistent state validates structure less strictly than Java's hashed
  metadata files.
- Concurrent same-ID imports can double-count cache entries; import/prune and
  background verification can race with replacement.
- Go accepts file sizes above Java's signed 32-bit limit.
- Cache stats omit Java's estimated filesystem-block overhead.
- Go directory/file modes are not always equivalent to Java plus process umask;
  hard-coded `0755` prevents group-write even under `UMASK=0002`.
- Java and Go differ for directory-path collisions, Unicode/UTF-16 title length,
  Windows reserved names, and exact `galleryinfo.txt` bytes.
- Unix free-space values differ (`Bavail` versus Java `getFreeSpace`).

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

1. `go test ./...`
2. `go test -race ./internal/hath`
3. Java/server-issued PFX fixture test:
   - alias `hath.network`
   - local-key-ID association
   - leaf/intermediate/root or actual server bag layout
   - end-to-end TLS handshake proving served leaf and chain
4. Listener bind-failure and unexpected-listener-death tests.
5. Certificate refresh failure test proving no dead registered node and no
   replacement of a known-good certificate.
6. Captured RPC replay including HTTP status, malformed/timeout response, and
   retry behavior—not only query/auth parity.
7. Existing Java cache/data fixture startup, mutation, forced crash, and restart
   test.
8. Low-space/unavailable-mount test proving fail-closed behavior.
9. Canary startup with container restart disabled; only enable restart after a
   complete `notifyStart` and externally verified TLS response.

## Migration safety policy

- Never start a new implementation with `restart: unless-stopped` during the
  first migration.
- Keep the Java image and all five volumes available for immediate rollback.
- Do not infer whole-client compatibility from line coverage or RPC signatures.
- Classify untested runtime/library semantics as **unverified**, not equivalent.
