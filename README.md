# hath — Hentai@Home client (Go port)

[![Test](https://github.com/dalkak780/hath/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/dalkak780/hath/actions/workflows/test.yml)
[![Coverage](https://github.com/dalkak780/hath/actions/workflows/coverage.yml/badge.svg?branch=main)](https://github.com/dalkak780/hath/actions/workflows/coverage.yml)

A Go reimplementation of the Hentai@Home distributed-CDN client.

> [!WARNING]
> Production migration is currently blocked by the ongoing
> [Java → Go behavioral parity audit](PARITY_AUDIT.md). RPC authentication
> parity and line coverage do not yet prove full runtime interoperability.

This is a **derivative work** of [Hentai@Home](https://repo.e-hentai.org/hath/)
by E-Hentai.org / tenboro, licensed under the GNU General Public License v3.
The original Java source is preserved under `hath_java/` for reference only.

## What this is

`hath` runs as a node in the Hentai@Home content-distribution network:

1. **RPC client** — talks to the H@H RPC server over HTTP, fetching settings,
   static-range download links, blacklists, and a TLS certificate. The
   outbound RPC is request/key authenticated with a time-corrected SHA-1
   `actkey`; sending too many malformed requests will get the account locked,
   so the client keeps its clock synchronized to the server and retries on
   `KEY_EXPIRED`.
2. **TLS edge server** — serves cached image/video files over HTTPS using a
   server-issued PKCS#12 certificate, acting as a CDN edge node. Requests are
   authenticated with `keystamp` / `servercmd` HMAC signatures.

## Why Go

- `net/http` replaces the original hand-rolled TCP HTTP parser with a
  vetted HTTP implementation, on both the client and server side.
- `crypto/tls` + `golang.org/x/crypto/pkcs12` load the server-issued cert.
- `crypto/sha1` drives every auth signature.
- Single static binary → minimal Docker image.

## Version policy

The Go client keeps the original Java client's protocol identity:

- client version: `1.6.5`
- client build: `178`

`ClientBuild` and `ClientVer` are the H@H wire-compatibility identity. Go port
releases keep that upstream version and add a port revision suffix: the first
1.6.5 port release is `v1.6.5-go.1`, followed by `-go.2` as needed. An
upstream Java 1.6.6 port starts again at `v1.6.6-go.1`.

## Configuration

Credentials are stored in `data/client_login` as `<ClientID>-<ClientKey>`.
All other settings come from the server at runtime (host, port, throttle,
disk limits, static ranges, ...). Flags mirror the original `--flag=value`
style, e.g. `--cache-dir=/cache --data-dir=/data`.

## Run (Docker)

```bash
docker build -t hath .
docker run -d --name hath \
  -p 443:443 \
  -v hath-data:/hath/data \
  -v hath-cache:/hath/cache \
  -v hath-log:/hath/log \
  -v hath-tmp:/hath/tmp \
  -v hath-download:/hath/download \
  -e TZ=UTC \
  -e HATH_CLIENT_ID=12345 \
  -e HATH_CLIENT_KEY=.................... \
  hath
```

The image runs as non-root UID/GID `65532:65532` by default. For bind mounts
owned by the host user, map that user directly with Docker's native `--user`:

```bash
PUID=$(id -u)
PGID=$(id -g)
docker run --user "$PUID:$PGID" \
  -e TZ=Asia/Seoul \
  ... hath
```

`PUID` and `PGID` are host/Compose variables used to select Docker's process
user; they are not privilege-escalation variables inside the image. The image
does not need a root entrypoint. Ensure bind-mounted
directories are writable by that UID/GID. Other supported variables are
`HATH_CLIENT_ID`, `HATH_CLIENT_KEY`, `UMASK` (octal, default `022`), `TZ`
(default `UTC`), and `EXTRA_ARGS` (additional `--flag=value` arguments).

The client listens on the port assigned by the server (default `--port`).
Map it through and make sure it is publicly reachable — the server performs
a connectivity test at startup and rejects clients it cannot reach.

## Migrate from `frosty5689/hath` (Docker Compose)

Stop the Java container first and **do not use `docker compose down -v`**. Keep
the existing `cache`, `data`, `download`, `log`, and `tmp` volumes. The Go image
uses the same paths and reads the existing `/hath/data/client_login` file.

Example Compose configuration:

```yaml
services:
  hath:
    image: ${HATH_IMAGE:-ghcr.io/dalkak780/hath_go:latest}
    container_name: hath
    # Keep this off until startup and an external TLS probe are verified.
    restart: "no"
    user: "${PUID:-65532}:${PGID:-65532}"
    environment:
      HATH_CLIENT_ID: "${HATH_CLIENT_ID:?set HATH_CLIENT_ID}"
      HATH_CLIENT_KEY: "${HATH_CLIENT_KEY:?set HATH_CLIENT_KEY}"
      UMASK: ${UMASK:-022}
      TZ: ${TZ:-UTC}
      EXTRA_ARGS: ${EXTRA_ARGS:-}
    ports:
      - "${HATH_PORT}:${HATH_PORT}"
    volumes:
      - hath-cache:/hath/cache
      - hath-data:/hath/data
      - hath-download:/hath/download
      - hath-log:/hath/log
      - hath-tmp:/hath/tmp

volumes:
  hath-cache:
    name: ${HATH_CACHE_VOLUME:-hath-cache}
  hath-data:
    name: ${HATH_DATA_VOLUME:-hath-data}
  hath-download:
    name: ${HATH_DOWNLOAD_VOLUME:-hath-download}
  hath-log:
    name: ${HATH_LOG_VOLUME:-hath-log}
  hath-tmp:
    name: ${HATH_TMP_VOLUME:-hath-tmp}
```

Create a `.env` beside the Compose file. Set the volume names to the exact
names used by the old Compose project, or replace the volume entries with the
old bind-mount paths:

```dotenv
# Canary release; keep restart disabled until startup and external TLS pass.
HATH_IMAGE=ghcr.io/dalkak780/hath_go:1.6.5-go.2
HATH_CLIENT_ID=12345
HATH_CLIENT_KEY=your-20-character-client-key
HATH_PORT=12345
PUID=99
PGID=100
HATH_CACHE_VOLUME=oldproject_hath-cache
HATH_DATA_VOLUME=oldproject_hath-data
HATH_DOWNLOAD_VOLUME=oldproject_hath-download
HATH_LOG_VOLUME=oldproject_hath-log
HATH_TMP_VOLUME=oldproject_hath-tmp
```

Use the UID/GID that own the existing files, not necessarily `99:100`:

```bash
docker compose down
# Back up the five volumes here.
docker compose pull
docker compose up -d
docker compose logs -f hath
```

Do not enable automatic restart merely because the container remains running.
First confirm the log contains `startup completed; normal operation`, then
probe the published port from a different network and verify that a TLS
handshake succeeds and `/robots.txt` returns HTTP 200. Only after both checks
pass should you change `restart` to `unless-stopped`. If either check fails,
stop the Go container and roll back to the preserved Java image and volumes.

`--user`/Compose `user` controls the ownership of newly downloaded cache files;
it does not repair existing ownership. If the old container used a custom
`--user`, preserve those numeric IDs in `PUID` and `PGID`. To roll back, stop
the Go container and restore the old image without deleting the volumes.

## License

GPL-3.0-or-later. See `LICENSE`.
