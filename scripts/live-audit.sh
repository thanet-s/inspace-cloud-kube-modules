#!/bin/sh
set -eu

workspace=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

if [ "${INSPACE_SKIP_DOTENV:-false}" != true ] && [ -f "$workspace/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$workspace/.env"
  set +a
fi

: "${INSPACE_API_URL:?INSPACE_API_URL is required}"
: "${INSPACE_API_TOKEN:?INSPACE_API_TOKEN is required}"
: "${INSPACE_LOCATION:?INSPACE_LOCATION is required}"

case "$INSPACE_API_URL" in
  https://*|http://127.0.0.1|http://127.0.0.1:*|http://localhost|http://localhost:*) ;;
  *)
    echo "INSPACE_API_URL must use HTTPS except for literal loopback HTTP test endpoints" >&2
    exit 2
    ;;
esac

prefix=${INSPACE_LIVE_RESOURCE_PREFIX:-inspace-e2e-}
api_root=${INSPACE_API_URL%/}/v1

get() {
  curl --fail --silent --show-error --max-time 30 \
    -H "apikey: $INSPACE_API_TOKEN" "$1"
}

locations_response=$(get "$api_root/config/locations")
locations=$(printf '%s' "$locations_response" | jq -er '
  if type != "array" or length == 0 or any(.[]; .slug as $slug |
    if ($slug | type) != "string" then true
    else ($slug | test("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$") | not)
    end)
  then error("invalid location inventory")
  else [.[].slug] | if length != (unique | length) then error("duplicate location slug") else .[] end
  end')
if ! printf '%s\n' "$locations" | grep -Fx "$INSPACE_LOCATION" >/dev/null; then
  echo "configured location $INSPACE_LOCATION is absent from the authoritative location inventory" >&2
  exit 1
fi

vms='[]'
disks='[]'
load_balancers='[]'
firewalls='[]'
floating_ips='[]'
for location in $locations; do
  base=$api_root/$location
  vms_response=$(get "$base/user-resource/vm/list")
  location_vms=$(printf '%s' "$vms_response" | jq --arg prefix "$prefix" --arg location "$location" \
    '[.[] | select((.name // "") | startswith($prefix)) | {kind:"vm", location:$location, uuid, name, status}]')
  vms=$(jq -cn --argjson current "$vms" --argjson next "$location_vms" '$current + $next')
  disks_response=$(get "$base/storage/disks")
  location_disks=$(printf '%s' "$disks_response" | jq --arg prefix "$prefix" --arg location "$location" \
    '[.[] | select((.display_name // "") | startswith($prefix)) | {kind:"disk", location:$location, uuid, name:.display_name, status}]')
  disks=$(jq -cn --argjson current "$disks" --argjson next "$location_disks" '$current + $next')
  load_balancers_response=$(get "$base/network/load_balancers")
  location_load_balancers=$(printf '%s' "$load_balancers_response" | jq --arg prefix "$prefix" --arg location "$location" \
    '[.[] | select((.display_name // "") | startswith($prefix)) | {kind:"load-balancer", location:$location, uuid, name:.display_name, is_deleted}]')
  load_balancers=$(jq -cn --argjson current "$load_balancers" --argjson next "$location_load_balancers" '$current + $next')
  firewalls_response=$(get "$base/network/firewalls")
  location_firewalls=$(printf '%s' "$firewalls_response" | jq --arg prefix "$prefix" --arg location "$location" \
    '[.[] | select(((.display_name // .name // "") | startswith($prefix))) | {kind:"firewall", location:$location, uuid, name:(.display_name // .name), resources_assigned}]')
  firewalls=$(jq -cn --argjson current "$firewalls" --argjson next "$location_firewalls" '$current + $next')
  floating_ips_response=$(get "$base/network/ip_addresses")
  location_floating_ips=$(printf '%s' "$floating_ips_response" | jq --arg prefix "$prefix" --arg location "$location" \
    '[.[] | select((.name // "") | startswith($prefix)) | {kind:"floating-ip", location:$location, address, name, assigned_to, assigned_to_resource_type}]')
  floating_ips=$(jq -cn --argjson current "$floating_ips" --argjson next "$location_floating_ips" '$current + $next')
done

jq -n --argjson vms "$vms" --argjson disks "$disks" --argjson lbs "$load_balancers" --argjson firewalls "$firewalls" --argjson ips "$floating_ips" \
  '{resources: ($vms + $disks + $lbs + $firewalls + $ips), count: (($vms + $disks + $lbs + $firewalls + $ips) | length)}'

count=$(jq -n --argjson vms "$vms" --argjson disks "$disks" --argjson lbs "$load_balancers" --argjson firewalls "$firewalls" --argjson ips "$floating_ips" \
  '($vms + $disks + $lbs + $firewalls + $ips) | length')
if [ "$count" -ne 0 ]; then
  echo "live-test resources with prefix '$prefix' remain" >&2
  exit 1
fi
