FROM --platform=$BUILDPLATFORM golang:1.26.5 AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/inspace-cloud-controller-manager ./cmd/inspace-cloud-controller-manager && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/inspace-cluster-controller ./cmd/inspace-cluster-controller

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="InSpace Cloud Controller Manager" \
      org.opencontainers.image.description="External Kubernetes cloud controller manager for InSpace Cloud" \
      org.opencontainers.image.source="https://github.com/thanet-s/inspace-cloud-kube-modules" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY LICENSE NOTICE /licenses/inspace-cloud-kube-modules/
COPY --from=build /out/inspace-cloud-controller-manager /usr/local/bin/inspace-cloud-controller-manager
COPY --from=build /out/inspace-cluster-controller /usr/local/bin/inspace-cluster-controller
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/inspace-cloud-controller-manager"]
