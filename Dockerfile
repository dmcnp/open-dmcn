# syntax=docker/dockerfile:1

# dmcnd — the DMCN reference daemon: serving node, webmail and (optionally) the SMTP bridge,
# in one process for one domain.
#
# Only Go is needed to build this. The web client is committed under cmd/dmcnd/web/dist and
# embedded with //go:embed, so there is no Node stage and no build-time network access beyond
# the Go module proxy.

# Pinned to the BUILD platform, not the target: the compiler runs natively on the runner and
# cross-compiles, instead of the whole toolchain running under QEMU for every extra architecture.
# Free here because CGO is off, and the difference is minutes per architecture. It also means the
# module download below is shared across targets rather than repeated per platform.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
WORKDIR /src

# Modules first: a source-only change then reuses this layer instead of re-resolving the
# dependency graph on every build.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# The build context carries no .git (see .dockerignore), so `git describe` cannot run here.
# CI passes the tag in; a local build without it is honestly labelled "dev".
ARG VERSION=dev
# TARGETOS/TARGETARCH are supplied per target platform by BuildKit; they are what turn this into
# a cross-compile rather than a native build of whatever the runner happens to be.
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/dmcnd ./cmd/dmcnd

# Stage the data directory here so it can be copied in with the right ownership. It cannot be
# created in the final image: distroless has no shell, so there is no entrypoint script to do
# it at runtime, and an unprivileged process cannot create a directory at / itself.
RUN mkdir -p /data

# distroless/static:nonroot — no shell, no package manager, no libc, and it runs as an
# unprivileged user (uid 65532) rather than root. The binary is fully static with CGO off.
# This base still carries the CA roots, which are not optional here: ACME needs them to get a
# certificate, and the bridge needs them for outbound STARTTLS.
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.source="https://github.com/dmcnp/open-dmcn"
LABEL org.opencontainers.image.description="DMCN reference daemon — a self-hostable mail node with cryptographic identity, webmail and an SMTP bridge in one binary."
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /out/dmcnd /usr/local/bin/dmcnd

# /data ships owned by the unprivileged uid the image runs as. That is what lets a named
# volume work with no setup — Docker seeds an empty one from the image, ownership included —
# and what makes a mountless `docker run` (the dev trial, `peer-id`) writable. A bind mount is
# the exception: it replaces the path wholesale, so the host directory's ownership is what
# applies and must permit uid 65532.
COPY --from=build --chown=65532:65532 /data /data

# dmcndcli is deliberately NOT in this image. It holds the domain root key, and the whole
# point of the live-domain design is that the root never sits on the node. Install it on the
# machine you administer from: go install dmcn.dev/open-dmcn/cmd/dmcndcli@latest
#
# The one operator command the node itself needs is built into the daemon. No shell is
# involved: the entrypoint is exec form, so arguments go straight to the binary.
#
#   docker compose run --rm dmcnd peer-id
#
# Run it through compose, or otherwise with the data directory mounted. `peer-id` CREATES the
# identity key if there isn't one, so without that mount it mints a key into a throwaway
# layer and prints a peer ID the real container will never use — which you would then publish
# in DNS, and only discover was wrong when another domain failed to reach you.

# Where the daemon keeps everything stateful, and the only path it ever writes to: the libp2p
# identity key (its peer ID is published in your DNS, so losing it invalidates your own seed
# record), the record and mailbox stores, the petition queue, and the autocert cache.
#
# Deliberately NOT a VOLUME. Declaring one here cannot be undone downstream — every plain
# `docker run` would get an anonymous volume whether the operator wanted one or not. Mount
# something at /data when you want the state to survive (compose.yaml does); a throwaway
# `docker run --rm` then really is throwaway.
#
# A bind-mounted host directory must be writable by uid 65532 — see compose.yaml.
ENV DMCND_DATA_DIR=/data

# 443 webmail — autocert's ACME challenge works there and nowhere else.
# 7400 libp2p federation — this is the port that goes into your published _dmcn seed=.
# 25 SMTP, only when the bridge is enabled.
#
# These are the daemon's own defaults, deliberately not pinned here with ENV. Doing so would
# duplicate a default that lives in the code, and would silently win over it: DMCND_NODE_LISTEN
# is read with envOr(), so an image-level value would force 7400 even under DMCND_DEV=true,
# where the daemon otherwise picks an ephemeral port on purpose.
#
# Two of those are privileged ports, which an unprivileged process cannot bind. Rather than
# hand the daemon CAP_NET_BIND_SERVICE or run it as root, compose.yaml sets
# net.ipv4.ip_unprivileged_port_start=0 — a per-container sysctl that lowers the privileged
# threshold inside this network namespace only, and touches nothing on the host.
EXPOSE 443 7400 25

# Numeric on purpose: it holds even if /etc/passwd is absent or changes. 65532 is distroless's
# "nonroot". There is no shell in this image for it — or anyone — to reach.
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/dmcnd"]
