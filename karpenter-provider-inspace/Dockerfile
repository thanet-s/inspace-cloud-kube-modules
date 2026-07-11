# Build with the monorepo root as context:
#   docker build --platform=linux/amd64 -f karpenter-provider-inspace/Dockerfile .
FROM --platform=$BUILDPLATFORM golang:1.26.5-bookworm AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src
COPY cloud-provider-inspace/go.mod cloud-provider-inspace/go.sum ./cloud-provider-inspace/
COPY karpenter-provider-inspace/go.mod karpenter-provider-inspace/go.sum ./karpenter-provider-inspace/
WORKDIR /src/karpenter-provider-inspace
RUN go mod download

WORKDIR /src
COPY cloud-provider-inspace ./cloud-provider-inspace
COPY karpenter-provider-inspace ./karpenter-provider-inspace
WORKDIR /src/karpenter-provider-inspace
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/karpenter-provider-inspace ./cmd/controller

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="Karpenter Provider for InSpace Cloud" \
      org.opencontainers.image.description="Karpenter provider for elastic K3s workers on InSpace Cloud" \
      org.opencontainers.image.source="https://github.com/thanet-s/inspace-cloud-kube-modules" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY karpenter-provider-inspace/LICENSE karpenter-provider-inspace/NOTICE /licenses/inspace-cloud-kube-modules/
COPY --from=build /out/karpenter-provider-inspace /karpenter-provider-inspace
USER 65532:65532
ENTRYPOINT ["/karpenter-provider-inspace"]
