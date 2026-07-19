#!/usr/bin/env bash
set -Eeuo pipefail

script_dir=${BASH_SOURCE[0]%/*}
[[ $script_dir != "${BASH_SOURCE[0]}" ]] || script_dir=.
deploy_dir=$(CDPATH='' cd -- "$script_dir" && pwd -P)
workspace=$(CDPATH='' cd -- "$deploy_dir/.." && pwd -P)

phase=${1:-}
inventory=${2:-${INSPACE_DEPLOY_INVENTORY:-$deploy_dir/inventory.yml}}
state_root=${INSPACE_DEPLOY_STATE_ROOT:-$deploy_dir/.state}
ssh_dir=${INSPACE_DEPLOY_SSH_DIR:-${HOME:?HOME is required}/.ssh}

[[ $# -le 2 ]] || {
  echo "usage: deploy/run.sh <init|update|status|tunnel|destroy> [inventory.yml]" >&2
  exit 2
}
case "$phase" in
  init | update | status | tunnel | destroy) ;;
  *)
    echo "usage: deploy/run.sh <init|update|status|tunnel|destroy> [inventory.yml]" >&2
    exit 2
    ;;
esac

[[ $inventory != *$'\n'* ]] || {
  echo "inventory path must contain no newline or comma" >&2
  exit 2
}
[[ $inventory != *,* ]] || {
  echo "inventory path must contain no newline or comma" >&2
  exit 2
}
if [[ $inventory != /* ]]; then
  inventory_dir=${inventory%/*}
  [[ $inventory_dir != "$inventory" ]] || inventory_dir=.
  inventory_name=${inventory##*/}
  inventory=$(CDPATH='' cd -- "$inventory_dir" && pwd -P)/$inventory_name
fi
[[ -f $inventory && ! -L $inventory && -r $inventory ]] || {
  echo "inventory is not a readable regular file: $inventory" >&2
  exit 2
}
command -v docker >/dev/null 2>&1 || {
  echo "Docker is required" >&2
  exit 2
}
command -v git >/dev/null 2>&1 || {
  echo "Git is required" >&2
  exit 2
}
if command -v sha256sum >/dev/null 2>&1; then
  sha256=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  sha256=(shasum -a 256)
else
  echo "sha256sum or shasum is required" >&2
  exit 2
fi
[[ -S /var/run/docker.sock ]] || {
  echo "Docker socket is unavailable at /var/run/docker.sock" >&2
  exit 2
}
if [[ $phase != status && $phase != tunnel ]]; then
  [[ -n ${INSPACE_API_TOKEN:-} ]] || {
    echo "INSPACE_API_TOKEN must be exported" >&2
    exit 2
  }
fi

for path_name in state_root ssh_dir; do
  path_value=${!path_name}
  [[ $path_value != *$'\n'* && $path_value != *,* ]] || {
    echo "$path_name path must contain no newline or comma" >&2
    exit 2
  }
done
mkdir -p "$state_root"
chmod 0700 "$state_root"
state_root=$(CDPATH='' cd -- "$state_root" && pwd -P)
[[ -d $state_root && ! -L $state_root && -w $state_root ]] || {
  echo "state root is not a writable regular directory: $state_root" >&2
  exit 2
}
ssh_dir=$(CDPATH='' cd -- "$ssh_dir" && pwd -P)
[[ -d $ssh_dir && ! -L $ssh_dir && -r $ssh_dir ]] || {
  echo "SSH key directory is not a readable regular directory: $ssh_dir" >&2
  exit 2
}

if [[ -n ${INSPACE_DEPLOY_RUNNER_IMAGE:-} ]]; then
  runner_image=$INSPACE_DEPLOY_RUNNER_IMAGE
  docker image inspect "$runner_image" >/dev/null 2>&1 || {
    echo "configured deploy runner image is unavailable locally: $runner_image" >&2
    exit 2
  }
else
  fingerprint=$(
    git -C "$workspace" ls-files --cached --others --exclude-standard .dockerignore deploy |
      while IFS= read -r path; do
        git -C "$workspace" hash-object "$path"
      done |
      "${sha256[@]}" |
      awk '{print $1}'
  )
  [[ $fingerprint =~ ^[0-9a-f]{64}$ ]] || {
    echo "could not derive the deploy runner source fingerprint" >&2
    exit 2
  }
  runner_arch=${INSPACE_DEPLOY_RUNNER_PLATFORM:-$(docker version --format '{{.Server.Os}}-{{.Server.Arch}}')}
  runner_arch=${runner_arch//\//-}
  [[ $runner_arch =~ ^[a-z0-9][a-z0-9_.-]*$ ]] || {
    echo "could not derive the deploy runner architecture" >&2
    exit 2
  }
  runner_image="local/inspace-deploy-runner:$runner_arch-$fingerprint"
  if ! docker image inspect "$runner_image" >/dev/null 2>&1; then
    if [[ -n ${INSPACE_DEPLOY_RUNNER_PLATFORM:-} ]]; then
      docker build \
        --platform "$INSPACE_DEPLOY_RUNNER_PLATFORM" \
        --file "$deploy_dir/Dockerfile" \
        --tag "$runner_image" \
        "$workspace"
    else
      docker build \
        --file "$deploy_dir/Dockerfile" \
        --tag "$runner_image" \
        "$workspace"
    fi
  fi
fi

tunnel_id=$(
  printf '%s\0%s' "$state_root" "$inventory" |
    "${sha256[@]}" |
    awk '{print substr($1,1,16)}'
)
tunnel_container="inspace-deploy-tunnel-$tunnel_id"
common_args=(
  --mount "type=bind,src=$inventory,dst=/run/config/inventory.yml,readonly"
  --mount "type=bind,src=$ssh_dir,dst=$ssh_dir,readonly"
  --mount "type=bind,src=$state_root,dst=$state_root"
  --mount "type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock"
  --env INSPACE_DEPLOY_INVENTORY=/run/config/inventory.yml
  --env "INSPACE_DEPLOY_HOST_INVENTORY=$inventory"
  --env "INSPACE_DEPLOY_STATE_ROOT=$state_root"
  --env "INSPACE_DEPLOY_HOST_UID=$(id -u)"
  --env "INSPACE_DEPLOY_HOST_GID=$(id -g)"
  --env INSPACE_API_TOKEN
  --env CONFIRM_CLUSTER_DESTROY
)
if [[ -n ${INSPACE_DEPLOY_RUNNER_PLATFORM:-} ]]; then
  common_args=(
    --platform "$INSPACE_DEPLOY_RUNNER_PLATFORM"
    "${common_args[@]}"
  )
fi

if [[ $phase == tunnel ]]; then
  if [[ $(docker inspect --format '{{.State.Running}}' "$tunnel_container" 2>/dev/null || true) == true ]]; then
    echo "API tunnel is already running in $tunnel_container"
    ready_line=$(docker logs "$tunnel_container" 2>&1 |
      grep -F "InSpace deploy API tunnel is ready|" |
      tail -1 || true)
    [[ -z $ready_line ]] || echo "Kubeconfig: ${ready_line#*|}"
    exit 0
  fi
  docker container rm "$tunnel_container" >/dev/null 2>&1 || true
  docker run --detach --rm \
    --name "$tunnel_container" \
    --publish 127.0.0.1:16443:16443 \
    "${common_args[@]}" \
    --env INSPACE_DEPLOY_TUNNEL_BIND=0.0.0.0 \
    "$runner_image" tunnel >/dev/null
  for _ in {1..60}; do
    ready_line=$(docker logs "$tunnel_container" 2>&1 |
      grep -F "InSpace deploy API tunnel is ready|" |
      tail -1 || true)
    if [[ -n $ready_line ]]; then
      echo "API tunnel started in $tunnel_container"
      echo "Kubeconfig: ${ready_line#*|}"
      exit 0
    fi
    if [[ $(docker inspect --format '{{.State.Running}}' "$tunnel_container" 2>/dev/null || true) != true ]]; then
      docker logs "$tunnel_container" >&2 || true
      echo "API tunnel container exited before becoming ready" >&2
      exit 1
    fi
    sleep 1
  done
  docker stop "$tunnel_container" >/dev/null
  echo "API tunnel did not become ready within 60 seconds" >&2
  exit 1
fi

if [[ $phase == destroy ]] &&
  [[ $(docker inspect --format '{{.State.Running}}' "$tunnel_container" 2>/dev/null || true) == true ]]; then
  docker stop "$tunnel_container" >/dev/null
fi
exec docker run --rm \
  "${common_args[@]}" \
  "$runner_image" "$phase"
