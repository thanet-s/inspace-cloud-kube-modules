#!/bin/sh
set -eu

workspace=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

if [ -f "$workspace/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$workspace/.env"
  set +a
fi

: "${INSPACE_API_URL:?INSPACE_API_URL is required}"
: "${INSPACE_API_TOKEN:?INSPACE_API_TOKEN is required}"
: "${INSPACE_LOCATION:?INSPACE_LOCATION is required}"
: "${INSPACE_BILLING_ACCOUNT_ID:?INSPACE_BILLING_ACCOUNT_ID is required}"
: "${INSPACE_NETWORK_UUID:?INSPACE_NETWORK_UUID is required}"
: "${INSPACE_INTEL_HOST_POOL_UUID:?INSPACE_INTEL_HOST_POOL_UUID is required}"
: "${INSPACE_AMD_HOST_POOL_UUID:?INSPACE_AMD_HOST_POOL_UUID is required}"

if [ "${CONFIRM_INSPACE_LIVE_TEST:-}" != "$INSPACE_BILLING_ACCOUNT_ID" ]; then
  echo "refusing live mutations: set CONFIRM_INSPACE_LIVE_TEST to the test billing-account ID" >&2
  exit 2
fi

export INSPACE_RUN_LIVE_TESTS=true
export INSPACE_ALLOW_REMOTE_MUTATIONS=true
export INSPACE_API_BASE_URL="$INSPACE_API_URL"
export INSPACE_TEST_BILLING_ACCOUNT_ID="$INSPACE_BILLING_ACCOUNT_ID"
export INSPACE_TEST_NETWORK_UUID="$INSPACE_NETWORK_UUID"
export INSPACE_TEST_HOST_POOL_UUID="$INSPACE_INTEL_HOST_POOL_UUID"
export INSPACE_HOST_POOL_UUID="$INSPACE_INTEL_HOST_POOL_UUID"
make_command=${MAKE:-make}

"$workspace/scripts/live-audit.sh"

created_firewall=false
firewall_uuid=${INSPACE_FIREWALL_UUID:-}
prefix=${INSPACE_LIVE_RESOURCE_PREFIX:-inspace-e2e-}
base=${INSPACE_API_URL%/}/v1/${INSPACE_LOCATION}

api_get() {
  curl --fail --silent --show-error --max-time 30 \
    -H "apikey: $INSPACE_API_TOKEN" "$1"
}

cleanup() {
  status=$?
  trap - EXIT INT TERM
  set +e
  if [ "$created_firewall" = true ] && [ -n "$firewall_uuid" ]; then
    assigned=$(api_get "$base/network/firewalls" | jq --arg uuid "$firewall_uuid" \
      '[.[] | select(.uuid == $uuid) | .resources_assigned[]?] | length')
    if [ "${assigned:-1}" -eq 0 ]; then
      if ! curl --fail --silent --show-error --max-time 30 -X DELETE \
        -H "apikey: $INSPACE_API_TOKEN" "$base/network/firewalls/$firewall_uuid" >/dev/null; then
        echo "failed to delete live-suite firewall $firewall_uuid" >&2
        status=1
      fi
    else
      echo "refusing to remove a firewall that still protects $assigned resource(s)" >&2
      status=1
    fi
  fi
  if ! "$workspace/scripts/live-audit.sh"; then
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -z "$firewall_uuid" ]; then
  subnet=$(api_get "$base/network/network/$INSPACE_NETWORK_UUID" | jq -er '.subnet')
  firewall_name="${prefix}suite-$(date -u +%Y%m%d%H%M%S)-$$"
  payload=$(jq -n --arg name "$firewall_name" --arg subnet "$subnet" --argjson billing "$INSPACE_BILLING_ACCOUNT_ID" '
    {
      display_name: $name,
      description: "Ephemeral firewall for the gated InSpace live suite",
      billing_account_id: $billing,
      rules: (["tcp", "udp", "icmp"] | map([
        {protocol: ., direction: "inbound", port_start: null, port_end: null,
         endpoint_spec_type: "ip_prefixes", endpoint_spec: [$subnet]},
        {protocol: ., direction: "outbound", port_start: null, port_end: null,
         endpoint_spec_type: "any"}
      ]) | add)
    }')
  firewall_response=$(curl --fail --silent --show-error --max-time 30 -X POST \
    -H "apikey: $INSPACE_API_TOKEN" -H 'Content-Type: application/json' \
    --data "$payload" "$base/network/firewalls")
  firewall_uuid=$(printf '%s' "$firewall_response" | jq -er '.uuid')
  created_firewall=true
fi

export INSPACE_FIREWALL_UUID="$firewall_uuid"
export INSPACE_TEST_FIREWALL_UUID="$firewall_uuid"

for module in modules/cloud-provider modules/csi-driver modules/karpenter-provider; do
  echo "==> live-test $module"
  "$make_command" -C "$workspace/$module" live-test
done
