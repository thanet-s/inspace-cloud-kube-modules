#!/bin/sh
set -eu

workspace=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ -f "$workspace/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$workspace/.env"
  set +a
fi

: "${INSPACE_API_URL:?INSPACE_API_URL is required}"
: "${INSPACE_API_TOKEN:?INSPACE_API_TOKEN is required}"
: "${INSPACE_LOCATION:?INSPACE_LOCATION is required}"

prefix=${INSPACE_LIVE_RESOURCE_PREFIX:-inspace-e2e-}
base=${INSPACE_API_URL%/}/v1/${INSPACE_LOCATION}

get() {
  curl --fail --silent --show-error --max-time 30 \
    -H "apikey: $INSPACE_API_TOKEN" "$1"
}

vms=$(get "$base/user-resource/vm/list" | jq --arg prefix "$prefix" \
  '[.[] | select((.name // "") | startswith($prefix)) | {kind:"vm", uuid, name, status}]')
disks=$(get "$base/storage/disks" | jq --arg prefix "$prefix" \
  '[.[] | select((.display_name // "") | startswith($prefix)) | {kind:"disk", uuid, name:.display_name, status}]')
load_balancers=$(get "$base/network/load_balancers" | jq --arg prefix "$prefix" \
  '[.[] | select((.display_name // "") | startswith($prefix)) | {kind:"load-balancer", uuid, name:.display_name, is_deleted}]')
firewalls=$(get "$base/network/firewalls" | jq --arg prefix "$prefix" \
  '[.[] | select(((.display_name // .name // "") | startswith($prefix))) | {kind:"firewall", uuid, name:(.display_name // .name), resources_assigned}]')
floating_ips=$(get "$base/network/ip_addresses" | jq --arg prefix "$prefix" \
  '[.[] | select((.name // "") | startswith($prefix)) | {kind:"floating-ip", address, name, assigned_to, assigned_to_resource_type}]')

jq -n --argjson vms "$vms" --argjson disks "$disks" --argjson lbs "$load_balancers" --argjson firewalls "$firewalls" --argjson ips "$floating_ips" \
  '{resources: ($vms + $disks + $lbs + $firewalls + $ips), count: (($vms + $disks + $lbs + $firewalls + $ips) | length)}'

count=$(jq -n --argjson vms "$vms" --argjson disks "$disks" --argjson lbs "$load_balancers" --argjson firewalls "$firewalls" --argjson ips "$floating_ips" \
  '($vms + $disks + $lbs + $firewalls + $ips) | length')
if [ "$count" -ne 0 ]; then
  echo "live-test resources with prefix '$prefix' remain" >&2
  exit 1
fi
