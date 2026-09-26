# Build with the monorepo root as context:
#   docker build --platform=linux/amd64 -f modules/karpenter-provider/Dockerfile .
FROM --platform=$BUILDPLATFORM golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.0.0-dev

WORKDIR /src
COPY modules/client/go.mod ./client/
COPY modules/karpenter-provider/go.mod modules/karpenter-provider/go.sum ./karpenter-provider/
WORKDIR /src/karpenter-provider
RUN GOWORK=off go mod download

WORKDIR /src
COPY modules/client ./client
COPY modules/karpenter-provider ./karpenter-provider
WORKDIR /src/karpenter-provider
RUN GOWORK=off CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags="-s -w -X=github.com/thanet-s/inspace-cloud-kube-modules/modules/client/version.Version=${VERSION} -X=sigs.k8s.io/karpenter/pkg/operator.Version=${VERSION}" \
      -o /out/karpenter-provider-inspace ./cmd/controller

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
LABEL org.opencontainers.image.title="Karpenter Provider for InSpace Cloud" \
      org.opencontainers.image.description="Karpenter provider for elastic RKE2 agents on InSpace Cloud" \
      org.opencontainers.image.source="https://github.com/thanet-s/inspace-cloud-kube-modules" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY modules/karpenter-provider/LICENSE modules/karpenter-provider/NOTICE /licenses/inspace-cloud-kube-modules/
COPY --from=build /out/karpenter-provider-inspace /karpenter-provider-inspace
USER 65532:65532
ENTRYPOINT ["/karpenter-provider-inspace"]
