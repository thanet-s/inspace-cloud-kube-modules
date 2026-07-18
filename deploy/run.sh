#!/usr/bin/env bash
set -Eeuo pipefail

script_dir=${BASH_SOURCE[0]%/*}
[[ $script_dir != "${BASH_SOURCE[0]}" ]] || script_dir=.
deploy_dir=$(CDPATH='' cd -- "$script_dir" && pwd -P)
workspace=$(CDPATH='' cd -- "$deploy_dir/.." && pwd -P)

phase=${1:-}
inventory=${2:-${INSPACE_DEPLOY_INVENTORY:-$deploy_dir/inventory.yml}}

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
  echo "inventory path must contain no newline" >&2
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
command -v ansible-playbook >/dev/null 2>&1 || {
  echo "ansible-playbook is required (ansible-core 2.21 recommended)" >&2
  exit 2
}

if [[ $phase != status && $phase != tunnel ]]; then
  [[ -n ${INSPACE_API_TOKEN:-} ]] || {
    echo "INSPACE_API_TOKEN must be exported" >&2
    exit 2
  }
fi

export ANSIBLE_CONFIG=$deploy_dir/ansible.cfg
case "$phase" in
  init)
    exec ansible-playbook -i "$inventory" "$deploy_dir/playbooks/init-cluster.yml"
    ;;
  update)
    exec ansible-playbook -i "$inventory" "$deploy_dir/playbooks/update-control-plane.yml"
    ;;
  status)
    exec ansible-playbook -i "$inventory" "$deploy_dir/playbooks/status.yml"
    ;;
  tunnel)
    exec ansible-playbook -i "$inventory" "$deploy_dir/playbooks/tunnel.yml"
    ;;
  destroy)
    exec ansible-playbook -i "$inventory" "$deploy_dir/playbooks/destroy-cluster.yml" \
      --extra-vars "confirm_cluster_name=${CONFIRM_CLUSTER_DESTROY:-}"
    ;;
esac
