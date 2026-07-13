# Build from the monorepo root:
#   docker build -f modules/cloud-provider/Dockerfile -t inspace-cloud-controller-manager:dev .
FROM --platform=$BUILDPLATFORM golang:1.26.5 AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.0.0-dev

WORKDIR /workspace
COPY modules/client/go.mod ./client/
COPY modules/cloud-provider/go.mod modules/cloud-provider/go.sum ./cloud-provider/
WORKDIR /workspace/cloud-provider
RUN GOWORK=off go mod download

WORKDIR /workspace
COPY modules/client/ ./client/
COPY modules/cloud-provider/ ./cloud-provider/
WORKDIR /workspace/cloud-provider
RUN GOWORK=off CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags="-s -w -X=github.com/thanet-s/inspace-cloud-kube-modules/modules/client/version.Version=${VERSION} -X=k8s.io/component-base/version.gitVersion=v${VERSION}" \
      -o /out/inspace-cloud-controller-manager ./cmd/inspace-cloud-controller-manager && \
    GOWORK=off CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags="-s -w -X=github.com/thanet-s/inspace-cloud-kube-modules/modules/client/version.Version=${VERSION}" \
      -o /out/inspace-cluster-controller ./cmd/inspace-cluster-controller

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="InSpace Cloud Controller Manager" \
      org.opencontainers.image.description="External Kubernetes cloud controller manager for InSpace Cloud" \
      org.opencontainers.image.source="https://github.com/thanet-s/inspace-cloud-kube-modules" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY modules/cloud-provider/LICENSE modules/cloud-provider/NOTICE /licenses/inspace-cloud-kube-modules/
COPY --from=build /out/inspace-cloud-controller-manager /usr/local/bin/inspace-cloud-controller-manager
COPY --from=build /out/inspace-cluster-controller /usr/local/bin/inspace-cluster-controller
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/inspace-cloud-controller-manager"]
