# Capturing & verifying against a live Java instance

The authoritative safety check: capture real RPC traffic from your running Java
H@H client, then prove the Go client would produce byte-identical requests.
Because the RPC is **plain HTTP**, a forward proxy sees every request/response in
the clear.

```
  Java container  ──(plain HTTP RPC)──▶  captureproxy (host:8888)  ──▶  rpc.hentaiathome.net
                                          │ logs request+response pairs
                                          ▼
                                   rpc_capture.jsonl  ──▶  rpcverify  ──▶  PASS/FAIL
                                                                (recomputes actkey with the Go
                                                                 formula + your real client key)
```

## 1. Build the tools (on the Docker host)

```bash
cd hath
go build -o captureproxy ./tools/captureproxy
# rpcverify runs via `go run`
```

## 2. Start the capture proxy

```bash
./captureproxy -listen :8888 -out rpc_capture.jsonl
```

- `-listen :8888` binds on **all interfaces** so the container can reach it.
- Omit `-host` to log everything (downloads are forwarded but `rpcverify`
  ignores any request without an `actkey`, so only RPC matters).
- **No IP concern:** the container already NATs out through the host's public
  IP, so routing RPC through a host-side proxy does **not** change the source IP
  the server sees. RPC auth is by actkey (cid+key+time), not source IP.

## 3. Route the Java container through the proxy

Restart the container with the JVM pointed at the proxy. `JAVA_TOOL_OPTIONS` is
honored by every `java` invocation, so it works regardless of the image's
entrypoint:

```bash
# Linux Docker: the host is reachable from containers at the bridge gateway
HOSTGW=$(docker network inspect bridge -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}')
#  (usually 172.17.0.1; Docker Desktop: use host.docker.internal)

docker restart <hath-container>   # or recreate, adding the env below
docker run ... -e JAVA_TOOL_OPTIONS="-Dhttp.proxyHost=$HOSTGW -Dhttp.proxyPort=8888" <image>
# (or, with compose:  environment: ["JAVA_TOOL_OPTIONS=-Dhttp.proxyHost=172.17.0.1 -Dhttp.proxyPort=8888"])
```

Let it run for a few minutes so the capture includes the full RPC set:
`server_stat`, `client_login` (at startup), `client_settings`, `still_alive`
(≈every 2 min), `get_cert`, `get_blacklist`, and `srfetch` (on cache misses).

Watch the proxy log to confirm traffic is flowing.

## 4. Verify parity

```bash
go run ./tools/rpcverify -in rpc_capture.jsonl -login data/client_login
# (or: -key <20-char-key> -cid <id>)
```

```
=== rpcverify summary ===
records: 142, authenticated RPC: 87, parity OK: 87, mismatches: 0
PASS: every captured actkey matches the Go formula byte-for-byte.
```

`rpcverify` recomputes `actkey = SHA1("hentai@home-"+act+"-"+add+"-"+cid+"-"+acttime+"-"+clientKey)`
for each captured authenticated request and diffs it (and the full query string)
against what the Java client actually sent. **Any mismatch means the Go client
would emit a malformed request — the condition that locks accounts.** A clean
PASS is the strongest possible assurance that the RPC is wire-compatible.

## Safety / privacy

- The capture contains your real **client id** and **actkeys** (derived from your
  client key via SHA-1). The client **key itself is never transmitted**, so it
  is not in the capture — `rpcverify` reads it locally from `client_login`.
- `rpc_capture.jsonl` is git-ignored. Redact before sharing.

## Fallback: tcpdump (no restart)

If you cannot restart the container, capture the RPC directly on the wire:

```bash
tcpdump -i any -A -s0 'tcp port 80' -w rpc.pcap
# inspect requests:
tshark -r rpc.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri
```

This is for manual inspection only; `rpcverify` consumes the proxy's JSONL.
