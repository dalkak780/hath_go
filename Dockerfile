# syntax=docker/dockerfile:1

# ---- build stage ----
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/hath ./cmd/hath

# ---- runtime stage ----
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S hath && adduser -S -G hath -h /hath hath \
 && mkdir -p /hath/data /hath/cache /hath/log /hath/tmp /hath/download \
 && chown -R hath:hath /hath
WORKDIR /hath
USER hath
COPY --from=build /out/hath /usr/local/bin/hath

# The server assigns the listening port; map it through at run time.
# Run non-root: the assigned port must be >= 1024, or grant NET_BIND_SERVICE.
EXPOSE 443
VOLUME ["/hath/data", "/hath/cache", "/hath/log", "/hath/tmp", "/hath/download"]

ENTRYPOINT ["hath"]
