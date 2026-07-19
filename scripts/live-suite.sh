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
: "${INSPACE_BILLING_ACCOUNT_ID:?INSPACE_BILLING_ACCOUNT_ID is required}"
: "${INSPACE_NETWORK_UUID:?INSPACE_NETWORK_UUID is required}"

case "$INSPACE_API_URL" in
  https://*|http://127.0.0.1|http://127.0.0.1:*|http://localhost|http://localhost:*) ;;
  *)
    echo "INSPACE_API_URL must use HTTPS except for literal loopback HTTP test endpoints" >&2
    exit 2
    ;;
esac

if [ "${CONFIRM_INSPACE_LIVE_TEST:-}" != "$INSPACE_BILLING_ACCOUNT_ID" ]; then
  echo "refusing live mutations: set CONFIRM_INSPACE_LIVE_TEST to the test billing-account ID" >&2
  exit 2
fi

export INSPACE_RUN_LIVE_TESTS=true
export INSPACE_ALLOW_REMOTE_MUTATIONS=true
export INSPACE_API_BASE_URL="$INSPACE_API_URL"
export INSPACE_TEST_BILLING_ACCOUNT_ID="$INSPACE_BILLING_ACCOUNT_ID"
export INSPACE_TEST_NETWORK_UUID="$INSPACE_NETWORK_UUID"

for command_name in curl date grep jq mktemp od python3; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "$command_name is required for the durable live-suite mutation journal" >&2
    exit 2
  fi
done
if command -v sha256sum >/dev/null 2>&1; then
  sha256_command=sha256sum
elif command -v shasum >/dev/null 2>&1; then
  sha256_command='shasum -a 256'
else
  echo "sha256sum or shasum is required for the durable live-suite mutation journal" >&2
  exit 2
fi

prefix=${INSPACE_LIVE_RESOURCE_PREFIX:-inspace-e2e-}
base=${INSPACE_API_URL%/}/v1/${INSPACE_LOCATION}
state_dir=${INSPACE_LIVE_STATE_DIR:-$workspace/.e2e/live-suite}
receipt_file=$state_dir/firewall-mutation.json
lock_dir=$state_dir/lock
readback_attempts=${INSPACE_LIVE_READBACK_ATTEMPTS:-15}
readback_delay=${INSPACE_LIVE_READBACK_DELAY_SECONDS:-2}
absence_observations=${INSPACE_LIVE_ABSENCE_OBSERVATIONS:-3}
destructive_absence_delay=${INSPACE_LIVE_DESTRUCTIVE_ABSENCE_DELAY_SECONDS:-30}
firewall_uuid=
lock_held=false

case "$readback_attempts:$readback_delay:$absence_observations:$destructive_absence_delay" in
  *[!0-9:]*)
    echo "live readback settings must be non-negative integers" >&2
    exit 2
    ;;
esac
if [ "$readback_attempts" -lt 3 ] || [ "$absence_observations" -ne 3 ]; then
  echo "live readback attempts must be at least three and destructive absence observations must be exactly three" >&2
  exit 2
fi
case "$INSPACE_API_URL" in
  http://127.0.0.1|http://127.0.0.1:*|http://localhost|http://localhost:*) ;;
  *)
    if [ "$destructive_absence_delay" -lt 30 ]; then
      echo "live destructive absence observations must be spaced by at least 30 seconds" >&2
      exit 2
    fi
    ;;
esac

mkdir -p "$state_dir"
chmod 0700 "$state_dir"
if ! mkdir "$lock_dir" 2>/dev/null; then
  echo "live-suite state is locked at $lock_dir; verify no live-suite process is running before removing a stale lock" >&2
  exit 1
fi
lock_held=true

api_get() {
  curl --fail --silent --show-error --max-time 30 \
    -H "apikey: $INSPACE_API_TOKEN" "$1"
}

read_network_subnet() {
  network_response=$(api_get "$base/network/network/$INSPACE_NETWORK_UUID") || return 1
  observed_network_uuid=$(printf '%s' "$network_response" | jq -er '.uuid | ascii_downcase') || return 1
  expected_network_uuid=$(printf '%s' "$INSPACE_NETWORK_UUID" | tr '[:upper:]' '[:lower:]')
  if [ "$observed_network_uuid" != "$expected_network_uuid" ]; then
    echo "configured network read returned UUID $observed_network_uuid, expected $expected_network_uuid" >&2
    return 1
  fi
  observed_subnet=$(printf '%s' "$network_response" | jq -er '.subnet | select(type == "string" and length > 0)') || return 1
  python3 - "$observed_subnet" <<'PY'
import ipaddress
import sys

network = ipaddress.ip_network(sys.argv[1], strict=True)
if network.version != 4:
    raise SystemExit("configured InSpace network must have an IPv4 subnet")
print(network)
PY
}

receipt_value() {
  jq -er "$1" "$receipt_file"
}

write_receipt() {
  phase=$1
  name=$2
  uuid=${3:-}
  policy_hash=$4
  absence_count=${5:-0}
  absence_first=${6:-0}
  absence_last=${7:-0}
  temporary=$(mktemp "$state_dir/.firewall-mutation.XXXXXX")
  if ! jq -n \
    --arg phase "$phase" \
    --arg apiURL "${INSPACE_API_URL%/}" \
    --arg location "$INSPACE_LOCATION" \
    --arg billingAccountID "$INSPACE_BILLING_ACCOUNT_ID" \
    --arg networkUUID "$INSPACE_NETWORK_UUID" \
    --arg name "$name" \
    --arg uuid "$uuid" \
    --arg policyHash "$policy_hash" \
    --argjson absenceCount "$absence_count" \
    --argjson absenceFirst "$absence_first" \
    --argjson absenceLast "$absence_last" \
    '{schema:"inspace-live-firewall-mutation-v1", phase:$phase,
      scope:{apiURL:$apiURL, location:$location, billingAccountID:$billingAccountID, networkUUID:$networkUUID},
      firewall:{name:$name, uuid:$uuid, policyHash:$policyHash},
      absence:{count:$absenceCount, firstObservedUnix:$absenceFirst, lastObservedUnix:$absenceLast}}' >"$temporary"; then
    rm -f "$temporary"
    return 1
  fi
  chmod 0600 "$temporary"
  python3 "$workspace/scripts/durable-state.py" replace "$temporary" "$receipt_file"
}

remove_receipt() {
  python3 "$workspace/scripts/durable-state.py" remove "$receipt_file"
}

validate_receipt_scope() {
  jq -e \
    --arg apiURL "${INSPACE_API_URL%/}" \
    --arg location "$INSPACE_LOCATION" \
    --arg billingAccountID "$INSPACE_BILLING_ACCOUNT_ID" \
    --arg networkUUID "$INSPACE_NETWORK_UUID" '
      .schema == "inspace-live-firewall-mutation-v1" and
      (.phase == "prepared" or .phase == "create-issued" or .phase == "present" or .phase == "delete-issued") and
      .scope.apiURL == $apiURL and .scope.location == $location and
      .scope.billingAccountID == $billingAccountID and .scope.networkUUID == $networkUUID and
      (.firewall.name | type == "string" and length > 0) and
      (.firewall.uuid | type == "string") and
      (.firewall.uuid == "" or (.firewall.uuid | test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))) and
      (.firewall.policyHash | test("^[0-9a-f]{64}$")) and
      ((.absence? == null) or (
        (.absence.count | type == "number" and floor == . and . >= 0 and . <= 3) and
        (.absence.firstObservedUnix | type == "number" and floor == . and . >= 0) and
        (.absence.lastObservedUnix | type == "number" and floor == . and . >= 0) and
        ((.absence.count == 0 and .absence.firstObservedUnix == 0 and .absence.lastObservedUnix == 0) or
         (.absence.count == 1 and .absence.firstObservedUnix > 0 and .absence.lastObservedUnix == 0) or
         (.absence.count >= 2 and .absence.firstObservedUnix > 0 and .absence.lastObservedUnix >= .absence.firstObservedUnix))
      ))
    ' "$receipt_file" >/dev/null
}

matching_firewalls() {
  expected_name=$1
  expected_uuid=${2:-}
  firewall_inventory=$(api_get "$base/network/firewalls") || return 1
  printf '%s' "$firewall_inventory" | jq \
    --arg name "$expected_name" \
    --arg uuid "$expected_uuid" \
    '[.[] | select(
      ((.display_name // .name // "") == $name) or
      ($uuid != "" and (.uuid // "") == $uuid)
    )]'
}

firewall_policy_hash() {
  normalized_policy=$(jq -cS '
    [(. // [])[] | {
      protocol: ((.protocol // "") | ascii_downcase),
      direction: ((.direction // "") | ascii_downcase),
      port_start: (.port_start // null),
      port_end: (.port_end // null),
      endpoint_spec_type: ((.endpoint_spec_type // "") | ascii_downcase),
      endpoint_spec: ((.endpoint_spec // []) | sort)
    }] | sort_by(.protocol, .direction, (.port_start // 0), (.port_end // 0), .endpoint_spec_type, (.endpoint_spec | join(",")))
  ') || return 1
  printf '%s' "$normalized_policy" | hash_sha256
}

hash_sha256() {
  case $sha256_command in
    sha256sum) sha256sum | awk '{print $1}' ;;
    *) shasum -a 256 | awk '{print $1}' ;;
  esac
}

validate_firewall_match() {
  matches=$1
  expected_uuid=${2:-}
  require_unassigned=${3:-false}
  observed_billing=$(printf '%s' "$matches" | jq -er '.[0].billing_account_id | tostring') || return 1
  observed_uuid=$(printf '%s' "$matches" | jq -er '.[0].uuid') || return 1
  observed_name=$(printf '%s' "$matches" | jq -er '.[0].display_name // .[0].name') || return 1
  expected_name=$(receipt_value '.firewall.name')
  observed_policy_hash=$(printf '%s' "$matches" | jq '.[0].rules // []' | firewall_policy_hash) || return 1
  expected_policy_hash=$(receipt_value '.firewall.policyHash')
  if [ "$observed_billing" != "$INSPACE_BILLING_ACCOUNT_ID" ]; then
    echo "refusing firewall name collision in billing account $observed_billing" >&2
    return 1
  fi
  if [ -n "$expected_uuid" ] && [ "$observed_uuid" != "$expected_uuid" ]; then
    echo "refusing firewall name collision: read UUID $observed_uuid, expected $expected_uuid" >&2
    return 1
  fi
  if [ "$observed_name" != "$expected_name" ]; then
    echo "refusing firewall identity drift: exact UUID $observed_uuid was renamed from $expected_name to $observed_name" >&2
    return 1
  fi
  if [ "$observed_policy_hash" != "$expected_policy_hash" ]; then
    echo "refusing firewall adoption: exact-name resource has a different normalized policy" >&2
    return 1
  fi
  if [ "$require_unassigned" = true ]; then
    assigned=$(printf '%s' "$matches" | jq -r '[.[0].resources_assigned[]?] | length')
    if [ "$assigned" -ne 0 ]; then
      echo "refusing firewall adoption while exact-name resource protects $assigned resource(s)" >&2
      return 1
    fi
  fi
}

resolve_create_receipt() {
  validate_receipt_scope || {
    echo "live-suite firewall receipt is malformed or belongs to a different account scope: $receipt_file" >&2
    return 1
  }
  phase=$(receipt_value '.phase')
  name=$(receipt_value '.firewall.name')
  policy_hash=$(receipt_value '.firewall.policyHash')
  [ "$phase" = create-issued ] || return 2

  attempt=1
  while [ "$attempt" -le "$readback_attempts" ]; do
    # A create response UUID is never ownership evidence. During the issued
    # phase, recover only the unique exact deterministic name and prove its
    # complete policy/account identity before anchoring its canonical UUID.
    # Ignoring any UUID in an older issued receipt also makes recovery safe
    # across upgrades from versions that persisted the response handle.
    matches=$(matching_firewalls "$name" "") || return 1
    count=$(printf '%s' "$matches" | jq -r 'length')
    if [ "$count" -gt 1 ]; then
      echo "refusing ambiguous firewall ownership: multiple exact live-suite firewalls match $name" >&2
      return 1
    fi
    if [ "$count" -eq 1 ]; then
      validate_firewall_match "$matches" "" true || return 1
      observed_uuid=$(printf '%s' "$matches" | jq -er '.[0].uuid') || return 1
      write_receipt present "$name" "$observed_uuid" "$policy_hash" || return 1
      firewall_uuid=$observed_uuid
      return 0
    fi
    if [ "$attempt" -lt "$readback_attempts" ]; then
      sleep "$readback_delay"
    fi
    attempt=$((attempt + 1))
  done
  echo "firewall create remains ambiguous; kept durable receipt $receipt_file and will not replay POST" >&2
  return 1
}

prove_firewall_absent() {
  name=$1
  uuid=$2
  policy_hash=$(receipt_value '.firewall.policyHash')
  observed=$(jq -r '.absence.count // 0' "$receipt_file")
  first_observed=$(jq -r '.absence.firstObservedUnix // 0' "$receipt_file")
  last_observed=$(jq -r '.absence.lastObservedUnix // 0' "$receipt_file")
  if [ "$observed" -ge 2 ] && [ $((last_observed - first_observed)) -lt $(((observed - 1) * destructive_absence_delay)) ]; then
    echo "refusing malformed destructive absence receipt with insufficient observation spacing" >&2
    return 1
  fi
  attempt=1
  while [ "$attempt" -le "$readback_attempts" ]; do
    matches=$(matching_firewalls "$name" "$uuid") || return 1
    count=$(printf '%s' "$matches" | jq -r 'length')
    if [ "$count" -gt 1 ]; then
      echo "refusing ambiguous firewall absence proof: multiple resources match $name/$uuid" >&2
      return 1
    fi
    if [ "$count" -eq 1 ]; then
      validate_firewall_match "$matches" "$uuid" false || return 1
      if [ "$observed" -ne 0 ]; then
        write_receipt delete-issued "$name" "$uuid" "$policy_hash" 0 0 0 || return 1
        observed=0
        first_observed=0
        last_observed=0
      fi
    fi
    if [ "$count" -eq 0 ]; then
      if [ "$observed" -ge "$absence_observations" ]; then
        # A restart after the terminal persisted observation performs one more
        # independent exact read before completing the receipt.
        return 0
      fi
      now=$(date +%s)
      if [ "$observed" -gt 0 ]; then
        previous=$last_observed
        if [ "$previous" -eq 0 ]; then
          previous=$first_observed
        fi
        not_before=$((previous + destructive_absence_delay))
        if [ "$now" -lt "$not_before" ]; then
          sleep $((not_before - now))
          attempt=$((attempt + 1))
          continue
        fi
      fi
      observed=$((observed + 1))
      if [ "$first_observed" -eq 0 ]; then
        first_observed=$now
      fi
      if [ "$observed" -gt 1 ]; then
        last_observed=$now
      fi
      write_receipt delete-issued "$name" "$uuid" "$policy_hash" "$observed" "$first_observed" "$last_observed" || return 1
      if [ "$observed" -ge "$absence_observations" ]; then
        return 0
      fi
    fi
    if [ "$attempt" -lt "$readback_attempts" ]; then
      sleep "$readback_delay"
    fi
    attempt=$((attempt + 1))
  done
  return 1
}

cleanup_receipt() {
  [ -f "$receipt_file" ] || return 0
  validate_receipt_scope || {
    echo "refusing cleanup from malformed or foreign live-suite receipt: $receipt_file" >&2
    return 1
  }
  phase=$(receipt_value '.phase')
  name=$(receipt_value '.firewall.name')
  uuid=$(jq -r '.firewall.uuid' "$receipt_file")
  policy_hash=$(receipt_value '.firewall.policyHash')

  if [ "$phase" = prepared ]; then
    # The only transition that proves no request was dispatched. The script
    # always stores create-issued before entering curl.
    remove_receipt
    return 0
  fi
  if [ "$phase" = create-issued ]; then
    if ! resolve_create_receipt; then
      return 1
    fi
    phase=present
    name=$(receipt_value '.firewall.name')
    uuid=$(receipt_value '.firewall.uuid')
    policy_hash=$(receipt_value '.firewall.policyHash')
  fi

  if [ "$phase" = present ]; then
    matches=$(matching_firewalls "$name" "$uuid") || return 1
    count=$(printf '%s' "$matches" | jq -r 'length')
    if [ "$count" -gt 1 ]; then
      echo "refusing cleanup: exact firewall identity is not unique" >&2
      return 1
    fi
    if [ "$count" -eq 1 ]; then
      validate_firewall_match "$matches" "$uuid" false || return 1
      assigned=$(printf '%s' "$matches" | jq -r '[.[0].resources_assigned[]?] | length')
      if [ "$assigned" -ne 0 ]; then
        echo "refusing to remove live-suite firewall $uuid while it protects $assigned resource(s)" >&2
        return 1
      fi
      # Persist the exact destructive intent before dispatch. Any result from
      # curl, including HTTP 4xx/5xx, timeout, or success, remains ambiguous.
      write_receipt delete-issued "$name" "$uuid" "$policy_hash" || return 1
      # The durable fsync/CAS is a scheduling boundary. Re-read exact identity,
      # account, policy, and zero assignments after it; never dispatch from the
      # stale pre-journal snapshot.
      final_matches=$(matching_firewalls "$name" "$uuid") || return 1
      final_count=$(printf '%s' "$final_matches" | jq -r 'length')
      if [ "$final_count" -gt 1 ]; then
        echo "refusing post-journal firewall delete: exact identity is not unique" >&2
        return 1
      fi
      if [ "$final_count" -eq 1 ]; then
        validate_firewall_match "$final_matches" "$uuid" true || return 1
        set +e
        curl --fail --silent --show-error --max-time 30 -X DELETE \
          -H "apikey: $INSPACE_API_TOKEN" "$base/network/firewalls/$uuid" >/dev/null
        delete_status=$?
        set -e
        if [ "$delete_status" -ne 0 ]; then
          echo "firewall DELETE returned an ambiguous error; resolving only by exact readback" >&2
        fi
      fi
    else
      write_receipt delete-issued "$name" "$uuid" "$policy_hash" || return 1
    fi
  fi

  if prove_firewall_absent "$name" "$uuid"; then
    remove_receipt
    firewall_uuid=
    return 0
  fi
  echo "firewall delete remains ambiguous; kept durable receipt $receipt_file and will not replay DELETE" >&2
  return 1
}

cleanup() {
  status=$?
  trap - EXIT INT TERM
  set +e
  if ! cleanup_receipt; then
    status=1
  fi
  if ! "$workspace/scripts/live-audit.sh"; then
    status=1
  fi
  if [ "$lock_held" = true ]; then
    rmdir "$lock_dir" 2>/dev/null || status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Resolve and remove a previous invocation's exact journaled resource before
# accepting a new run. An unresolved issued receipt blocks every fresh POST.
if [ -f "$receipt_file" ]; then
  cleanup_receipt
fi
"$workspace/scripts/live-audit.sh"

if [ -z "$firewall_uuid" ]; then
  subnet=$(read_network_subnet)
  owner=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')
  firewall_name="${prefix}suite-${owner}"
  if [ "${#firewall_name}" -gt 63 ] || ! printf '%s' "$firewall_name" | grep -Eq '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'; then
    echo "live firewall name must be a lowercase DNS label no longer than 63 characters: $firewall_name" >&2
    exit 2
  fi
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
  firewall_policy_hash_value=$(printf '%s' "$payload" | jq '.rules' | firewall_policy_hash)
  write_receipt prepared "$firewall_name" "" "$firewall_policy_hash_value"
  write_receipt create-issued "$firewall_name" "" "$firewall_policy_hash_value"
  # Winning the durable issue is a scheduling boundary. Re-list after fsync:
  # one exact owned match is adopted without POST, foreign/duplicate/read error
  # stays blocked, and only authoritative deterministic-name absence may create.
  post_issue_matches=$(matching_firewalls "$firewall_name" "")
  post_issue_count=$(printf '%s' "$post_issue_matches" | jq -r 'length')
  if [ "$post_issue_count" -gt 1 ]; then
    echo "refusing post-journal firewall create: deterministic name is not unique" >&2
    exit 1
  fi
  if [ "$post_issue_count" -eq 1 ]; then
    validate_firewall_match "$post_issue_matches" "" true
    firewall_uuid=$(printf '%s' "$post_issue_matches" | jq -er '.[0].uuid')
    write_receipt present "$firewall_name" "$firewall_uuid" "$firewall_policy_hash_value"
  else
    # The journal fsync is a scheduling boundary. Re-read the exact configured
    # VPC as the final non-firewall authority and reject any UUID/subnet drift
    # before using the pre-journal policy in a paid cloud mutation.
    post_issue_subnet=$(read_network_subnet)
    if [ "$post_issue_subnet" != "$subnet" ]; then
      echo "refusing post-journal firewall create: configured network subnet changed from $subnet to $post_issue_subnet" >&2
      exit 1
    fi
    set +e
    firewall_response=$(curl --fail --silent --show-error --max-time 30 -X POST \
      -H "apikey: $INSPACE_API_TOKEN" -H 'Content-Type: application/json' \
      --data "$payload" "$base/network/firewalls")
    create_status=$?
    set -e
    # Treat every response body as diagnostic only. Canonical ownership is
    # established exclusively by the deterministic-name inventory readback.
    if ! resolve_create_receipt; then
      exit 1
    fi
    if [ "$create_status" -ne 0 ]; then
      echo "firewall POST returned an ambiguous error; adopted the exact durable-name readback $firewall_uuid" >&2
    fi
  fi
fi

cleanup_receipt
"$workspace/scripts/live-audit.sh"
echo "durable firewall API lifecycle passed; use full cluster E2E for component release acceptance"
