#!/usr/bin/env bash
set -Eeuo pipefail

# This host-side entrypoint is deliberately only a Docker launcher. All
# release checks, key validation, provisioning, Ansible, SSH, Kubernetes work,
# and cleanup execute inside the disposable E2E runner container.
script_dir=${BASH_SOURCE[0]%/*}
[[ $script_dir != "${BASH_SOURCE[0]}" ]] || script_dir=.
workspace=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
cd "$workspace"

command -v docker >/dev/null 2>&1 || {
  echo "Docker is required to run the E2E controller" >&2
  exit 2
}

env_file=${INSPACE_E2E_ENV_FILE:-$workspace/.env}
ssh_private_key=${INSPACE_E2E_SSH_PRIVATE_KEY:-$HOME/.ssh/id_rsa}
ssh_public_key=${INSPACE_E2E_SSH_PUBLIC_KEY:-$HOME/.ssh/id_rsa.pub}
state_volume=${INSPACE_E2E_STATE_VOLUME:-inspace-cloud-rke2-e2e-state}
runner_image=${INSPACE_E2E_RUNNER_IMAGE:-inspace-cloud-rke2-e2e:local}

[[ -f "$env_file" && -r "$env_file" ]] || {
  echo "E2E environment file is not readable: $env_file" >&2
  exit 2
}
[[ -f "$ssh_private_key" && -r "$ssh_private_key" ]] || {
  echo "SSH private key is not readable: $ssh_private_key" >&2
  exit 2
}
[[ -f "$ssh_public_key" && -r "$ssh_public_key" ]] || {
  echo "SSH public key is not readable: $ssh_public_key" >&2
  exit 2
}
[[ -n ${CONFIRM_INSPACE_CLUSTER_E2E:-} ]] || {
  echo "CONFIRM_INSPACE_CLUSTER_E2E must be exported" >&2
  exit 2
}
[[ -n ${INSPACE_E2E_VERSION:-} ]] || {
  echo "INSPACE_E2E_VERSION must be exported" >&2
  exit 2
}
[[ $INSPACE_E2E_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || {
  echo "INSPACE_E2E_VERSION must be an exact published SemVer tag" >&2
  exit 2
}

docker volume inspect "$state_volume" >/dev/null 2>&1 || docker volume create "$state_volume" >/dev/null
docker build \
  --file test/e2e/Dockerfile \
  --target published-live \
  --build-arg "CONTROLLER_IMAGE=ghcr.io/thanet-s/inspace-cloud-controller-manager:$INSPACE_E2E_VERSION" \
  --tag "$runner_image" \
  .
docker run --rm \
  --env "CONFIRM_INSPACE_CLUSTER_E2E=$CONFIRM_INSPACE_CLUSTER_E2E" \
  --env "INSPACE_E2E_VERSION=$INSPACE_E2E_VERSION" \
  --env "INSPACE_E2E_KEEP_RESOURCES=${INSPACE_E2E_KEEP_RESOURCES:-false}" \
  --env "INSPACE_E2E_RUN_ID=${INSPACE_E2E_RUN_ID:-}" \
  --env "INSPACE_E2E_RECOVERY_ONLY=${INSPACE_E2E_RECOVERY_ONLY:-false}" \
  --env "INSPACE_E2E_RECOVER_RETAINED=${INSPACE_E2E_RECOVER_RETAINED:-false}" \
  --mount "type=bind,src=$env_file,dst=/run/config/workspace.env,readonly" \
  --mount "type=bind,src=$ssh_private_key,dst=/run/secrets/e2e_ssh_key,readonly" \
  --mount "type=bind,src=$ssh_public_key,dst=/run/secrets/e2e_ssh_key.pub,readonly" \
  --mount "type=volume,src=$state_volume,dst=/state" \
  "$runner_image"
