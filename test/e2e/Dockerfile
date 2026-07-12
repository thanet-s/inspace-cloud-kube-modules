# syntax=docker/dockerfile:1.7

ARG CONTROLLER_IMAGE=ghcr.io/thanet-s/inspace-cloud-controller-manager:0.1.0

FROM golang:1.26.5-bookworm AS local-controller-builder

WORKDIR /src
COPY modules/client/go.mod ./modules/client/go.mod
COPY modules/cloud-provider/go.mod modules/cloud-provider/go.sum ./modules/cloud-provider/
RUN cd modules/cloud-provider && GOWORK=off go mod download
COPY modules/client ./modules/client
COPY modules/cloud-provider ./modules/cloud-provider
RUN cd modules/cloud-provider && \
    CGO_ENABLED=0 GOWORK=off go build -trimpath -ldflags='-s -w' \
      -o /out/inspace-cluster-controller ./cmd/inspace-cluster-controller

FROM ubuntu:26.04 AS base

ARG TARGETARCH
ARG KUBECTL_VERSION=v1.35.6
ARG HELM_VERSION=v3.18.4

ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/opt/ansible/bin:${PATH} \
    ANSIBLE_CONFIG=/opt/e2e/ansible.cfg \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash ca-certificates curl iproute2 jq openssh-client openssl \
      python3 python3-pip python3-venv skopeo tini util-linux xz-utils && \
    rm -rf /var/lib/apt/lists/* && \
    python3 -m venv /opt/ansible

COPY test/e2e/requirements.txt /tmp/requirements.txt
RUN /opt/ansible/bin/pip install --no-cache-dir --disable-pip-version-check \
      -r /tmp/requirements.txt && rm -f /tmp/requirements.txt

RUN set -eux; \
    case "$TARGETARCH" in amd64|arm64) ;; *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1;; esac; \
    curl --fail --location --retry 5 --silent --show-error \
      -o /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl"; \
    curl --fail --location --retry 5 --silent --show-error \
      -o /tmp/kubectl.sha256 "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl.sha256"; \
    echo "$(cat /tmp/kubectl.sha256)  /usr/local/bin/kubectl" | sha256sum --check -; \
    chmod 0755 /usr/local/bin/kubectl; \
    curl --fail --location --retry 5 --silent --show-error \
      -o /tmp/helm.tar.gz "https://get.helm.sh/helm-${HELM_VERSION}-linux-${TARGETARCH}.tar.gz"; \
    curl --fail --location --retry 5 --silent --show-error \
      -o /tmp/helm.sha256 "https://get.helm.sh/helm-${HELM_VERSION}-linux-${TARGETARCH}.tar.gz.sha256sum"; \
    echo "$(awk '{print $1}' /tmp/helm.sha256)  /tmp/helm.tar.gz" | sha256sum --check -; \
    tar -xzf /tmp/helm.tar.gz -C /tmp; install -m 0755 "/tmp/linux-${TARGETARCH}/helm" /usr/local/bin/helm; \
    rm -rf /tmp/helm.tar.gz /tmp/helm.sha256 /tmp/kubectl.sha256 "/tmp/linux-${TARGETARCH}"

COPY test/e2e /opt/e2e

RUN chmod 0755 /opt/e2e/run.sh /opt/e2e/scripts/*.sh /opt/e2e/scripts/*.py && \
    mkdir -p /state /run/config /run/secrets && \
    chmod 0700 /state /run/secrets && \
    ansible-playbook --syntax-check -i /opt/e2e/inventory.yml /opt/e2e/playbook.yml && \
    ansible-playbook --syntax-check -i /opt/e2e/inventory.yml /opt/e2e/cleanup.yml

WORKDIR /opt/e2e
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/opt/e2e/scripts/container-entrypoint.sh"]

# Pull-request and local non-live validation compiles the controller from the
# checkout. The destructive launcher never selects this target.
FROM base AS local-validation
COPY --from=local-controller-builder /out/inspace-cluster-controller /usr/local/bin/inspace-cluster-controller

# Live release acceptance copies the bootstrap binary from the exact published
# controller image tag. This makes mixing local bootstrap code with released
# charts/controller images structurally impossible.
FROM ${CONTROLLER_IMAGE} AS published-controller

FROM base AS published-live
COPY --from=published-controller /usr/local/bin/inspace-cluster-controller /usr/local/bin/inspace-cluster-controller
