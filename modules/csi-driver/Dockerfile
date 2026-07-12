# Build from the monorepo root:
#   docker build -f modules/csi-driver/Dockerfile -t inspace-csi-driver:dev .
FROM --platform=$BUILDPLATFORM golang:1.26.5-bookworm AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
COPY modules/client/go.mod ./client/
COPY modules/csi-driver/go.mod modules/csi-driver/go.sum ./csi-driver/
WORKDIR /workspace/csi-driver
RUN GOWORK=off go mod download

WORKDIR /workspace
COPY modules/client/ ./client/
COPY modules/csi-driver/ ./csi-driver/
WORKDIR /workspace/csi-driver
RUN GOWORK=off CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/inspace-csi-driver ./cmd/inspace-csi-driver

FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="InSpace CSI Driver" \
      org.opencontainers.image.description="Kubernetes RWO block storage CSI driver for InSpace Cloud" \
      org.opencontainers.image.source="https://github.com/thanet-s/inspace-cloud-kube-modules" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       ca-certificates e2fsprogs util-linux \
    && rm -rf /var/lib/apt/lists/*
COPY modules/csi-driver/LICENSE modules/csi-driver/NOTICE /licenses/inspace-cloud-kube-modules/
COPY --from=build /out/inspace-csi-driver /usr/local/bin/inspace-csi-driver

USER 0:0
ENTRYPOINT ["/usr/local/bin/inspace-csi-driver"]
