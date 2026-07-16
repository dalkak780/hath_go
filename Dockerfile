# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26.5

# ---- build stage ----
# Build on the runner platform and cross-compile for TARGETOS/TARGETARCH.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags='-s -w -buildid=' \
    -o /out/hath ./cmd/hath && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags='-s -w -buildid=' \
    -o /out/hathmon ./cmd/hathmon

# Keep writable runtime directories in the image without bringing any build
# tools or source files into the final image.
RUN mkdir -p /runtime/hath/data /runtime/hath/cache /runtime/hath/log \
    /runtime/hath/tmp /runtime/hath/download

# ---- runtime stage ----
# Distroless contains only the runtime essentials and CA certificates.
# tzdata is embedded in cmd/hath via time/tzdata, so TZ needs no filesystem
# payload and can be changed at runtime: docker run -e TZ=Asia/Seoul ...
FROM gcr.io/distroless/static-debian12:nonroot

ENV TZ=UTC \
    UMASK=022
WORKDIR /hath

COPY --from=build --chown=65532:65532 /out/hath /usr/local/bin/hath
COPY --from=build --chown=65532:65532 /out/hathmon /usr/local/bin/hathmon
COPY --from=build --chown=65532:65532 /runtime/hath/ /hath/

USER 65532:65532
EXPOSE 443
VOLUME ["/hath/data", "/hath/cache", "/hath/log", "/hath/tmp", "/hath/download"]

ENTRYPOINT ["/usr/local/bin/hath"]
