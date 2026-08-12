# Multi-stage, multi-arch build for the relais backend.
#
# Build for both architectures with buildx:
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -f deploy/Dockerfile -t <registry>/relais:<tag> --push .
#
# The result is a static binary on a distroless base: no shell, no package
# manager, non-root by default.

# --- build ---------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

# BUILDPLATFORM keeps the compiler running natively while cross-compiling for
# TARGETARCH, which is far faster than emulating the target under QEMU.
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src

# Dependencies are copied first so that a source-only change does not
# re-download the module cache.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

# CGO_ENABLED=0 yields a fully static binary, which is what makes the
# distroless base viable. -trimpath keeps build paths out of the artifact, and
# -s -w drop the symbol table and DWARF data.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags "-s -w -X github.com/amenitydev/relais/internal/obs.Version=${VERSION}" \
      -o /out/relais ./cmd/relais

# --- runtime -------------------------------------------------------------
# static-debian12 carries ca-certificates (needed to verify the OTLP collector
# and any TLS backend) and /etc/passwd for the nonroot user, and nothing else.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=build /out/relais /usr/local/bin/relais

# Ports below 1024 would require CAP_NET_BIND_SERVICE for a non-root process.
# Listening high inside the container and publishing 587 outside avoids granting
# the capability at all: run with -p 587:2525.
ENV RELAIS_HTTP_ADDR=:8080 \
    RELAIS_SMTP_ADDR=:2525

EXPOSE 8080 2525

# The binary probes itself: there is no shell or curl in this image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/relais", "healthcheck"]

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/relais"]
CMD ["serve"]
