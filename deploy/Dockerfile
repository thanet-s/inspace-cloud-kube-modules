# syntax=docker/dockerfile:1.7

FROM docker:29.8.1-cli@sha256:1b0a4c8c69b84185904584e05e5d3b6e6b5f01d1339dcfbe1cd7dfa5d5ac7543 AS docker-cli
FROM alpine/helm:4.3.0@sha256:377d0fc44fb5513cc6efd7b04e5a44d732fa82df2389aa03097f1aa0e103a731 AS helm

FROM ubuntu:26.04@sha256:61ebaa5cc23ca45450db85eac015435199ec569e28ec222ea13f2aed2110b8a6

ARG TARGETARCH
ARG KUBECTL_VERSION=v1.36.4

ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/opt/ansible/bin:${PATH} \
    ANSIBLE_CONFIG=/opt/inspace-deploy/ansible.cfg \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash ca-certificates curl jq openssh-client openssl \
      python3 python3-pip python3-venv tini xz-utils && \
    rm -rf /var/lib/apt/lists/* && \
    python3 -m venv /opt/ansible

COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=helm /usr/bin/helm /usr/local/bin/helm
COPY deploy/requirements.lock.txt /tmp/requirements.lock.txt
RUN /opt/ansible/bin/pip install --no-cache-dir \
      -r /tmp/requirements.lock.txt && \
    rm -f /tmp/requirements.lock.txt

RUN set -eux; \
    case "$TARGETARCH" in amd64|arm64) ;; *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1;; esac; \
    curl --fail --location --retry 5 --silent --show-error \
      -o /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl"; \
    curl --fail --location --retry 5 --silent --show-error \
      -o /tmp/kubectl.sha256 "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl.sha256"; \
    echo "$(cat /tmp/kubectl.sha256)  /usr/local/bin/kubectl" | sha256sum --check -; \
    chmod 0755 /usr/local/bin/kubectl; \
    rm -f /tmp/kubectl.sha256

COPY deploy /opt/inspace-deploy
RUN chmod 0755 \
      /opt/inspace-deploy/container-entrypoint.sh \
      /opt/inspace-deploy/scripts/*.sh \
      /opt/inspace-deploy/scripts/*.py && \
    for playbook in \
      /opt/inspace-deploy/playbooks/init-cluster.yml \
      /opt/inspace-deploy/playbooks/update-control-plane.yml \
      /opt/inspace-deploy/playbooks/status.yml \
      /opt/inspace-deploy/playbooks/tunnel.yml \
      /opt/inspace-deploy/playbooks/destroy-cluster.yml; do \
      ansible-playbook \
        --inventory /opt/inspace-deploy/inventory.example.yml \
        "$playbook" --syntax-check; \
    done

WORKDIR /opt/inspace-deploy
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/opt/inspace-deploy/container-entrypoint.sh"]
