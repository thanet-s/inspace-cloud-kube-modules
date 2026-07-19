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
ansible-playbook "${args[@]}"

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
