# hath — Hentai@Home client in Go

[![Release](https://img.shields.io/github/v/release/dalkak780/hath_go?include_prereleases&sort=semver&label=release)](https://github.com/dalkak780/hath_go/releases)
[![Docker Hub](https://img.shields.io/docker/v/dalkak780/hath_go?sort=semver&label=Docker%20Hub)](https://hub.docker.com/r/dalkak780/hath_go/tags)
[![GHCR](https://img.shields.io/github/v/release/dalkak780/hath_go?include_prereleases&sort=semver&label=GHCR)](https://github.com/dalkak780/hath_go/pkgs/container/hath_go)

A Go port of the Hentai@Home distributed-CDN client. It preserves the Java
client's RPC and cache behavior while using Go's HTTP and TLS implementations.

Images are published to both registries:

- `ghcr.io/dalkak780/hath_go`
- `dalkak780/hath_go` on Docker Hub

This is a derivative work of Hentai@Home by E-Hentai.org / tenboro, licensed
under GPL-3.0-or-later. The original Java source is kept in `hath_java/` for
reference only.

## How it works

The client has two roles:

- It contacts the H@H RPC server to receive its public listening port,
  settings, static ranges, blacklists, and server-issued TLS certificate.
- It runs a TLS edge server that answers connectivity tests, speed tests, and
  authenticated CDN file requests.

The RPC server connects back to the port configured in H@H Settings and sent
to the client during startup. That port must be forwarded through the
router/firewall and published on the same Docker container port.

## Quick start with Docker Compose

Create `compose.yaml`:

```yaml
services:
  hath:
    image: ghcr.io/dalkak780/hath_go:1.6.5-go.3
    container_name: hath
    restart: unless-stopped
    user: "${PUID:-65532}:${PGID:-65532}"
    environment:
      HATH_CLIENT_ID: "${HATH_CLIENT_ID:?set HATH_CLIENT_ID}"
      HATH_CLIENT_KEY: "${HATH_CLIENT_KEY:?set HATH_CLIENT_KEY}"
      TZ: "${TZ:-UTC}"
      UMASK: "${UMASK:-022}"
      HATH_DISABLE_FILE_LOG: "${HATH_DISABLE_FILE_LOG:-false}"
      EXTRA_ARGS: "${EXTRA_ARGS:-}"
    # Replace 12345 with the port configured for this client in H@H Settings.
    ports:
      - "12345:12345/tcp"
    volumes:
      - hath-cache:/hath/cache
      - hath-data:/hath/data
      - hath-download:/hath/download
      - hath-log:/hath/log
      - hath-tmp:/hath/tmp

volumes:
  hath-cache:
  hath-data:
  hath-download:
  hath-log:
  hath-tmp:
```

Create `.env` beside it:

```dotenv
HATH_CLIENT_ID=12345
HATH_CLIENT_KEY=your-20-character-client-key
TZ=Asia/Seoul
PUID=1000
PGID=1000

# Docker already retains stdout, so avoid a second on-disk copy of each log.
HATH_DISABLE_FILE_LOG=true
```

The client does not accept a port environment variable. Replace `12345` in
the Compose file with the port configured for this client in H@H Settings.
The published host and container ports must be identical.

Bridge mode is the default. If H@H cannot accept connections even though the
port is forwarded and reachable, replace the `ports` section with host
networking on a Linux host or NAS:

```yaml
services:
  hath:
    network_mode: host
```

> [!WARNING]
> Bridge networking normally works, but some Docker hosts or non-transparent
> proxies can expose a container-side address or rewrite the RPC request's
> source address. This may fail H@H routing, startup connectivity tests, or RPC
> server IP authentication. Try host networking before considering
> `--disable-ip-origin-check`; disabling that check reduces security and is
> discouraged.

Start it:

```bash
docker compose pull
docker compose up -d
docker compose logs -f hath
```

A successful startup contains:

```text
startup completed; normal operation
```

Normal CDN traffic produces a `served` log entry containing the HTTP status,
byte count, duration, and request path.

> [!CAUTION]
> Never run the Java and Go clients concurrently with the same Client ID.
> Preserve `client_login`, and do not repeatedly start a client with an
> invalid ID/key: malformed authenticated RPC traffic can cause the server to
> block the client or source IP.

## Logging

Logs are always written to stdout, so `docker logs` and Compose logging keep
working. By default they are also written to `/hath/log/log_all`, rotated at
64 MiB with three backups.

For Docker installations, the extra file copy is usually unnecessary. Disable
only the file log with an explicit environment variable:

```dotenv
HATH_DISABLE_FILE_LOG=true
```

Set it to `false` or omit it if `/hath/log/log_all` is required. This variable
never suppresses stdout or per-request `served` messages. The legacy
`--disable-logging=true` argument remains supported for Java compatibility,
but `HATH_DISABLE_FILE_LOG` is recommended because its scope is unambiguous.

## Credentials and configuration

Credentials are stored as `<ClientID>-<ClientKey>` in
`/hath/data/client_login`. `HATH_CLIENT_ID` and `HATH_CLIENT_KEY` are useful
for the first Docker start; the client persists them to that file.

Most operating settings come from the RPC server. Local arguments use the
Java-style `--name=value` form and can be passed through `EXTRA_ARGS`.

| Variable | Purpose | Default |
|---|---|---|
| `HATH_CLIENT_ID` | Client ID used when `client_login` is unavailable | none |
| `HATH_CLIENT_KEY` | Client key used when `client_login` is unavailable | none |
| `HATH_DISABLE_FILE_LOG` | Disable only `/hath/log/log_all`; stdout remains enabled | `false` |
| `EXTRA_ARGS` | Additional client arguments | empty |
| `TZ` | Container timezone | `UTC` |
| `UMASK` | Octal file-creation mask | `022` |
| `PUID`, `PGID` | Compose substitutions for the container user | `65532` |

The original Docker image's commonly used `EXTRA_ARGS` options are supported:

| Option | Effect |
|---|---|
| `--image-proxy-host=<host>` | Proxy backend image and cache-miss downloads |
| `--image-proxy-type=http\|socks` | HTTP or SOCKS5 proxy; defaults to `socks` |
| `--image-proxy-port=<port>` | Defaults to `8080` for HTTP or `1080` for SOCKS |
| `--disable-flood-control` | Disable per-IP connection flood control |
| `--disable-ip-origin-check` | Disable RPC source-IP validation; discouraged |
| `--disable-file-verification` | Disable periodic cache integrity checks |

For example:

```dotenv
EXTRA_ARGS=--image-proxy-host=192.0.2.10 --image-proxy-type=http --image-proxy-port=8080
```

The image runs as UID/GID `65532:65532` by default. Bind-mounted directories
must be writable by the selected numeric IDs. `PUID` and `PGID` are evaluated
by Compose; they are not privilege-escalation controls inside the container.

## Migrating an existing Java installation

The Go client uses the same layout:

| Path | Contents |
|---|---|
| `/hath/cache` | Cached CDN files |
| `/hath/data` | `client_login`, certificate, and persistent cache metadata |
| `/hath/download` | Gallery downloads |
| `/hath/log` | Optional file logs |
| `/hath/tmp` | Temporary downloads |

1. Stop the Java container. Do not use `docker compose down -v`.
2. Back up all five volumes or bind mounts.
3. Point the Go container at the exact same paths and numeric UID/GID.
4. Start with `restart: "no"` for the first migration run.
5. Confirm `startup completed; normal operation` and a successful external
   TLS probe before enabling `restart: unless-stopped`.

For named volumes from an older Compose project, preserve their real names:

```yaml
volumes:
  hath-cache:
    name: oldproject_hath-cache
  hath-data:
    name: oldproject_hath-data
```

Repeat this for the other volumes. To roll back, stop the Go container and
start the preserved Java image against the unchanged volumes. Never operate
both clients at once.

## Build locally

```bash
docker build -t hath .
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -p 12345:12345/tcp \
  -v hath-data:/hath/data \
  -v hath-cache:/hath/cache \
  -e HATH_CLIENT_ID=12345 \
  -e HATH_CLIENT_KEY=your-20-character-client-key \
  -e HATH_DISABLE_FILE_LOG=true \
  hath
```

Replace `12345` with the H@H Settings port. If bridge mode fails as described
above, replace `-p 12345:12345/tcp` with `--network host` on Linux.

Production deployments should also persist `/hath/download`, `/hath/log`, and
`/hath/tmp` as shown in the Compose example.

## Version policy

The Go client keeps the upstream Java protocol identity. The current port
reports client version `1.6.5`, build `178` on the wire.

Port releases append a Go revision without advancing the upstream version:
`v1.6.5-go.1`, `v1.6.5-go.2`, and so on. When upstream releases Java 1.6.6,
the corresponding port starts at `v1.6.6-go.1`.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
