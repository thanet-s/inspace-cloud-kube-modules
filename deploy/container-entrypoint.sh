#!/usr/bin/env bash
set -Eeuo pipefail

phase=${1:-}
inventory=${INSPACE_DEPLOY_INVENTORY:-/run/config/inventory.yml}
state_root=${INSPACE_DEPLOY_STATE_ROOT:?INSPACE_DEPLOY_STATE_ROOT is required}

case "$phase" in
  init)
    playbook=/opt/inspace-deploy/playbooks/init-cluster.yml
    ;;
  update)
    playbook=/opt/inspace-deploy/playbooks/update-control-plane.yml
    ;;
  status)
    playbook=/opt/inspace-deploy/playbooks/status.yml
    ;;
  tunnel)
    playbook=/opt/inspace-deploy/playbooks/tunnel.yml
    ;;
  destroy)
    playbook=/opt/inspace-deploy/playbooks/destroy-cluster.yml
    ;;
  *)
    echo "usage: container-entrypoint.sh <init|update|status|tunnel|destroy>" >&2
    exit 2
    ;;
esac

[[ -f $inventory && ! -L $inventory && -r $inventory ]] || {
  echo "inventory is not a readable regular file: $inventory" >&2
  exit 2
}
[[ -d $state_root && ! -L $state_root && -w $state_root ]] || {
  echo "state root is not a writable regular directory: $state_root" >&2
  exit 2
}
if [[ $phase != status && $phase != tunnel ]]; then
  [[ -n ${INSPACE_API_TOKEN:-} ]] || {
    echo "INSPACE_API_TOKEN must be exported" >&2
    exit 2
  }
fi

finish() {
  if [[ ${EUID:-$(id -u)} == 0 && -n ${INSPACE_DEPLOY_HOST_UID:-} && -n ${INSPACE_DEPLOY_HOST_GID:-} ]]; then
    chown -R \
      "${INSPACE_DEPLOY_HOST_UID}:${INSPACE_DEPLOY_HOST_GID}" \
      "$state_root"
  fi
}
trap finish EXIT

args=(--inventory "$inventory" "$playbook")
if [[ $phase == destroy ]]; then
  args+=(--extra-vars "confirm_cluster_name=${CONFIRM_CLUSTER_DESTROY:-}")
fi

auto_recover=${INSPACE_DEPLOY_INIT_AUTO_RECOVER:-false}
[[ $auto_recover == true || $auto_recover == false ]] || {
  echo "INSPACE_DEPLOY_INIT_AUTO_RECOVER must be true or false" >&2
  exit 2
}

if [[ $phase == init && $auto_recover == true ]]; then
  # InSpace's floating-IP pool has repeatedly handed a bastion or
  # control-plane VM an address with no working SSH/internet path (see
  # RELEASING.md's "known open issue"). Setting this flag is the operator's
  # advance, one-time authorization to destroy and retry the exact cluster
  # named by this inventory, unattended, if init does not converge -- it is
  # the same class of pre-authorization CONFIRM_CLUSTER_DESTROY itself
  # grants for a single explicit destroy.
  init_attempt=1
  init_max_attempts=2
  while :; do
    init_status=0
    ansible-playbook "${args[@]}" || init_status=$?
    (( init_status == 0 )) && break
    (( init_attempt >= init_max_attempts )) && exit "$init_status"
    cluster_name=$(
      ansible-inventory --inventory "$inventory" --host localhost | jq -er '.cluster_name'
    ) || {
      echo "init attempt $init_attempt failed and the cluster name could not be read back from inventory; refusing automatic destroy" >&2
      exit "$init_status"
    }
    [[ $cluster_name =~ ^[a-z0-9]([a-z0-9-]{0,53}[a-z0-9])?$ ]] || {
      echo "inventory returned an invalid cluster name; refusing automatic destroy" >&2
      exit "$init_status"
    }
    echo "init attempt $init_attempt/$init_max_attempts failed; destroying $cluster_name and retrying with a fresh run in case of a transient provisioning fault (e.g. a bad floating IP)" >&2
    if ! ansible-playbook --inventory "$inventory" /opt/inspace-deploy/playbooks/destroy-cluster.yml \
      --extra-vars "confirm_cluster_name=$cluster_name"; then
      echo "destroy after failed init attempt $init_attempt did not converge; refusing retry" >&2
      exit "$init_status"
    fi
    cooldown=${INSPACE_DEPLOY_INIT_RETRY_COOLDOWN_SECONDS:-300}
    [[ $cooldown =~ ^[0-9]+$ && $cooldown -le 3600 ]] || {
      echo "INSPACE_DEPLOY_INIT_RETRY_COOLDOWN_SECONDS must be an integer at most 3600" >&2
      exit "$init_status"
    }
    echo "cooling down ${cooldown}s before retry, so an auto-assigned address just freed by teardown is less likely to be handed straight back" >&2
    sleep "$cooldown"
    init_attempt=$((init_attempt + 1))
  done
else
  ansible-playbook "${args[@]}"
fi

if [[ $phase == tunnel ]]; then
  cluster_name=$(
    ansible-inventory \
      --inventory "$inventory" \
      --host localhost |
      jq -er '.cluster_name'
  )
  [[ $cluster_name =~ ^[a-z0-9]([a-z0-9-]{0,53}[a-z0-9])?$ ]] || {
    echo "inventory returned an invalid cluster name" >&2
    exit 2
  }
  state_dir=$state_root/$cluster_name
  finish
  trap '/opt/inspace-deploy/scripts/api-tunnel.sh stop "$state_dir" 2>/dev/null || true; finish' EXIT
  echo "InSpace deploy API tunnel is ready|$state_dir/kubeconfig.yaml"
  while /opt/inspace-deploy/scripts/api-tunnel.sh status "$state_dir" >/dev/null 2>&1; do
    sleep 30
  done
  echo "API tunnel exited unexpectedly" >&2
  exit 1
fi
