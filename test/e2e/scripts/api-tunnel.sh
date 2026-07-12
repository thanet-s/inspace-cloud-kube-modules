#!/usr/bin/env bash
set -Eeuo pipefail

action=${1:?usage: api-tunnel.sh start|check|stop STATE}
state_file=${2:?usage: api-tunnel.sh start|check|stop STATE}
state_dir=${state_file%/*}
socket=$state_dir/api-tunnel.sock
known_hosts=$state_dir/known-hosts-bastion
key=${E2E_PRIVATE_KEY:?E2E_PRIVATE_KEY is required}
user=$(jq -er '.sshUsername' "$state_file")
public_ip=$(jq -er '.bastionPublicIPv4' "$state_file")
virtual_ip=$(jq -er '.virtualIPv4' "$state_file")
target=$user@$public_ip
options=(
  -i "$key"
  -o IdentitiesOnly=yes
  -o BatchMode=yes
  -o UserKnownHostsFile="$known_hosts"
  -o StrictHostKeyChecking=yes
  -o ConnectTimeout=10
  -o ServerAliveInterval=5
  -o ServerAliveCountMax=3
)

control() {
  ssh "${options[@]}" -S "$socket" -O "$1" "$target" >/dev/null 2>&1
}

case "$action" in
  start)
    if [[ -S $socket ]] && control check; then
      exit 0
    fi
    rm -f "$socket"
    ssh "${options[@]}" -M -S "$socket" -fNT \
      -o ExitOnForwardFailure=yes \
      -L "127.0.0.1:16443:$virtual_ip:6443" \
      "$target"
    for _ in {1..30}; do
      if [[ -S $socket ]] && control check; then
        exit 0
      fi
      sleep 0.2
    done
    echo "SSH API tunnel did not become ready" >&2
    exit 1
    ;;
  check)
    [[ -S $socket ]] && control check
    ;;
  stop)
    if [[ -S $socket ]]; then
      control exit || true
    fi
    rm -f "$socket"
    ;;
  *)
    echo "unsupported tunnel action: $action" >&2
    exit 2
    ;;
esac
