# Build with the monorepo root as context:
#   docker build --platform=linux/amd64 -f modules/karpenter-provider/Dockerfile .
FROM --platform=$BUILDPLATFORM golang:1.26.5-bookworm AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY modules/client/go.mod ./client/
COPY modules/karpenter-provider/go.mod modules/karpenter-provider/go.sum ./karpenter-provider/
WORKDIR /src/karpenter-provider
RUN GOWORK=off go mod download

WORKDIR /src
COPY modules/client ./client
COPY modules/karpenter-provider ./karpenter-provider
WORKDIR /src/karpenter-provider
RUN GOWORK=off CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/karpenter-provider-inspace ./cmd/controller

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="Karpenter Provider for InSpace Cloud" \
      org.opencontainers.image.description="Karpenter provider for elastic RKE2 agents on InSpace Cloud" \
      org.opencontainers.image.source="https://github.com/thanet-s/inspace-cloud-kube-modules" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY modules/karpenter-provider/LICENSE modules/karpenter-provider/NOTICE /licenses/inspace-cloud-kube-modules/
COPY --from=build /out/karpenter-provider-inspace /karpenter-provider-inspace
USER 65532:65532
ENTRYPOINT ["/karpenter-provider-inspace"]
