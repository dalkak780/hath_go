# hath — Hentai@Home client (Go port)

A Go reimplementation of the Hentai@Home distributed-CDN client.

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
  -v hath-data:/data -v hath-cache:/cache -v hath-log:/log \
  -e HATH_CLIENT_ID=12345 \
  -e HATH_CLIENT_KEY=.................... \
  hath
```

The client listens on the port assigned by the server (default `--port`).
Map it through and make sure it is publicly reachable — the server performs
a connectivity test at startup and rejects clients it cannot reach.

## License

GPL-3.0-or-later. See `LICENSE`.
