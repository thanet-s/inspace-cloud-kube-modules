#!/usr/bin/env bash
set -Eeuo pipefail

[[ $# == 2 ]] || {
  echo "usage: api-tunnel.sh <start|stop|status> <state-dir>" >&2
  exit 2
}

action=$1
state_dir=$2
ssh_config=$state_dir/ssh-config
state=$state_dir/state.json
socket_id=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest()[:16])' "$state_dir")
socket=${TMPDIR:-/tmp}/inspace-api-$socket_id.sock

case "$action" in
  start)
    [[ -f $ssh_config && -f $state ]] || {
      echo "deployment state or SSH config is missing" >&2
      exit 2
    }
    vip=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["privateControlPlaneEndpoint"].split("//",1)[1].rsplit(":",1)[0])' "$state")
    if ssh -F "$ssh_config" -S "$socket" -O check inspace-bastion >/dev/null 2>&1; then
      exit 0
    fi
    rm -f "$socket"
    ssh -F "$ssh_config" \
      -M -S "$socket" -f -N \
      -o ExitOnForwardFailure=yes \
      -L "127.0.0.1:16443:${vip}:6443" \
      inspace-bastion
    ;;
  stop)
    if [[ -S $socket ]]; then
      ssh -F "$ssh_config" -S "$socket" -O exit inspace-bastion >/dev/null 2>&1 || true
    fi
    rm -f "$socket"
    ;;
  status)
    ssh -F "$ssh_config" -S "$socket" -O check inspace-bastion
    ;;
  *)
    echo "unsupported action: $action" >&2
    exit 2
    ;;
esac
