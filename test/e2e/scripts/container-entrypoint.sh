#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

phase=${1:-all}
[[ $# -le 1 ]] || { echo "usage: container-entrypoint.sh [all|init|test|shell|destroy]" >&2; exit 2; }
case "$phase" in
  all | init | test | shell | destroy) ;;
  *) echo "unsupported E2E phase: $phase" >&2; exit 2 ;;
esac
active_phase=$phase

exec 9>/state/inspace-cloud-rke2-e2e.lock
chmod 0600 /state/inspace-cloud-rke2-e2e.lock
if ! flock -n 9; then
  echo "another E2E runner already holds the shared state-volume lock" >&2
  exit 2
fi

mounted_confirm=${CONFIRM_INSPACE_CLUSTER_E2E:-}
mounted_version=${INSPACE_E2E_VERSION:-}
mounted_release_revision=${INSPACE_E2E_RELEASE_REVISION:-}
mounted_release_artifact_root=${INSPACE_E2E_RELEASE_ARTIFACT_ROOT:-}
mounted_keep=${INSPACE_E2E_KEEP_RESOURCES:-false}
mounted_run_id=${INSPACE_E2E_RUN_ID:-}
mounted_recover_retained=${INSPACE_E2E_RECOVER_RETAINED:-false}
mounted_ccm_release_digest=${INSPACE_E2E_CCM_RELEASE_DIGEST:-}
mounted_ccm_platform_digest=${INSPACE_E2E_CCM_PLATFORM_DIGEST:-}
mounted_csi_release_digest=${INSPACE_E2E_CSI_RELEASE_DIGEST:-}
mounted_csi_platform_digest=${INSPACE_E2E_CSI_PLATFORM_DIGEST:-}
mounted_karpenter_release_digest=${INSPACE_E2E_KARPENTER_RELEASE_DIGEST:-}
mounted_karpenter_platform_digest=${INSPACE_E2E_KARPENTER_PLATFORM_DIGEST:-}
mounted_crds_chart_digest=${INSPACE_E2E_CRDS_CHART_DIGEST:-}
mounted_modules_chart_digest=${INSPACE_E2E_MODULES_CHART_DIGEST:-}
built_version=${INSPACE_E2E_BUILT_VERSION:-}
built_release_revision=${INSPACE_E2E_BUILT_REVISION:-}
built_ccm_release_digest=${INSPACE_E2E_BUILT_CCM_RELEASE_DIGEST:-}
built_ccm_platform_digest=${INSPACE_E2E_BUILT_CCM_PLATFORM_DIGEST:-}
built_csi_release_digest=${INSPACE_E2E_BUILT_CSI_RELEASE_DIGEST:-}
built_csi_platform_digest=${INSPACE_E2E_BUILT_CSI_PLATFORM_DIGEST:-}
built_karpenter_release_digest=${INSPACE_E2E_BUILT_KARPENTER_RELEASE_DIGEST:-}
built_karpenter_platform_digest=${INSPACE_E2E_BUILT_KARPENTER_PLATFORM_DIGEST:-}
built_crds_chart_digest=${INSPACE_E2E_BUILT_CRDS_CHART_DIGEST:-}
built_modules_chart_digest=${INSPACE_E2E_BUILT_MODULES_CHART_DIGEST:-}
env_file=/run/config/workspace.env

[[ -f $env_file ]] || { echo "mounted E2E environment file is missing" >&2; exit 2; }
[[ $(stat -c '%a' "$env_file") == 600 ]] || {
  echo "mounted E2E environment file must have mode 0600" >&2
  exit 2
}

set -a
# shellcheck disable=SC1091
source "$env_file"
set +a

# Explicit launcher values take precedence over values in the mounted file.
[[ -z $mounted_confirm ]] || export CONFIRM_INSPACE_CLUSTER_E2E=$mounted_confirm
[[ -z $mounted_version ]] || export INSPACE_E2E_VERSION=$mounted_version
export INSPACE_E2E_RELEASE_REVISION=$mounted_release_revision
export INSPACE_E2E_RELEASE_ARTIFACT_ROOT=$mounted_release_artifact_root
export INSPACE_E2E_KEEP_RESOURCES=$mounted_keep
export INSPACE_E2E_RECOVER_RETAINED=$mounted_recover_retained
[[ -z $mounted_run_id ]] || export INSPACE_E2E_RUN_ID=$mounted_run_id
export INSPACE_E2E_CCM_RELEASE_DIGEST=$mounted_ccm_release_digest
export INSPACE_E2E_CCM_PLATFORM_DIGEST=$mounted_ccm_platform_digest
export INSPACE_E2E_CSI_RELEASE_DIGEST=$mounted_csi_release_digest
export INSPACE_E2E_CSI_PLATFORM_DIGEST=$mounted_csi_platform_digest
export INSPACE_E2E_KARPENTER_RELEASE_DIGEST=$mounted_karpenter_release_digest
export INSPACE_E2E_KARPENTER_PLATFORM_DIGEST=$mounted_karpenter_platform_digest
export INSPACE_E2E_CRDS_CHART_DIGEST=$mounted_crds_chart_digest
export INSPACE_E2E_MODULES_CHART_DIGEST=$mounted_modules_chart_digest
export INSPACE_E2E_BUILT_VERSION=$built_version
export INSPACE_E2E_BUILT_REVISION=$built_release_revision
export INSPACE_E2E_BUILT_CCM_RELEASE_DIGEST=$built_ccm_release_digest
export INSPACE_E2E_BUILT_CCM_PLATFORM_DIGEST=$built_ccm_platform_digest
export INSPACE_E2E_BUILT_CSI_RELEASE_DIGEST=$built_csi_release_digest
export INSPACE_E2E_BUILT_CSI_PLATFORM_DIGEST=$built_csi_platform_digest
export INSPACE_E2E_BUILT_KARPENTER_RELEASE_DIGEST=$built_karpenter_release_digest
export INSPACE_E2E_BUILT_KARPENTER_PLATFORM_DIGEST=$built_karpenter_platform_digest
export INSPACE_E2E_BUILT_CRDS_CHART_DIGEST=$built_crds_chart_digest
export INSPACE_E2E_BUILT_MODULES_CHART_DIGEST=$built_modules_chart_digest

for name in INSPACE_API_URL INSPACE_API_TOKEN INSPACE_LOCATION \
  INSPACE_BILLING_ACCOUNT_ID INSPACE_NETWORK_UUID INSPACE_CONTROL_PLANE_VIP \
  INSPACE_PRIVATE_LOAD_BALANCER_POOL_START INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP \
  INSPACE_AMD_HOST_POOL_UUID INSPACE_E2E_VERSION; do
  [[ -n ${!name:-} ]] || { echo "$name is required" >&2; exit 2; }
done
python3 - "$INSPACE_API_URL" <<'PY'
import sys
import urllib.parse

value = sys.argv[1]
parsed = urllib.parse.urlsplit(value)
if (
    value != "https://api.inspace.cloud"
    or parsed.scheme != "https"
    or parsed.hostname != "api.inspace.cloud"
    or parsed.port is not None
    or parsed.username is not None
    or parsed.password is not None
    or parsed.path
    or parsed.query
    or parsed.fragment
):
    raise SystemExit("INSPACE_API_URL must be exactly https://api.inspace.cloud for destructive E2E")
PY
[[ ${CONFIRM_INSPACE_CLUSTER_E2E:-} == "$INSPACE_BILLING_ACCOUNT_ID" ]] || {
  echo "refusing cluster mutations: confirmation does not equal the isolated billing-account ID" >&2
  exit 2
}
for name in INSPACE_E2E_KEEP_RESOURCES INSPACE_E2E_RECOVER_RETAINED; do
  [[ ${!name} == false || ${!name} == true ]] || { echo "$name must be true or false" >&2; exit 2; }
done

require_release_runner_binding() {
  [[ $INSPACE_E2E_BUILT_VERSION == "$INSPACE_E2E_VERSION" ]] || {
    echo "runner image version does not match INSPACE_E2E_VERSION" >&2
    return 2
  }
  [[ $INSPACE_E2E_RELEASE_REVISION =~ ^[0-9a-f]{40}$ &&
     $INSPACE_E2E_BUILT_REVISION == "$INSPACE_E2E_RELEASE_REVISION" ]] || {
    echo "runner image revision does not match the canonical peeled release commit" >&2
    return 2
  }
  local expected_name built_name expected built
  for expected_name in \
    INSPACE_E2E_CCM_RELEASE_DIGEST INSPACE_E2E_CCM_PLATFORM_DIGEST \
    INSPACE_E2E_CSI_RELEASE_DIGEST INSPACE_E2E_CSI_PLATFORM_DIGEST \
    INSPACE_E2E_KARPENTER_RELEASE_DIGEST INSPACE_E2E_KARPENTER_PLATFORM_DIGEST \
    INSPACE_E2E_CRDS_CHART_DIGEST INSPACE_E2E_MODULES_CHART_DIGEST; do
    built_name=${expected_name/INSPACE_E2E_/INSPACE_E2E_BUILT_}
    expected=${!expected_name:-}
    built=${!built_name:-}
    [[ $expected =~ ^sha256:[0-9a-f]{64}$ && $built == "$expected" ]] || {
      echo "$expected_name does not match the immutable runner binding" >&2
      return 2
    }
  done
}

require_release_runner_binding

for command_name in ansible-playbook autossh curl date flock helm jq kubectl openssl ping setsid skopeo ss ssh ssh-keygen stat; do
  command -v "$command_name" >/dev/null || { echo "runner image is missing $command_name" >&2; exit 2; }
done
api_tunnel_instance_file=/run/inspace-e2e-api-tunnel-instance
openssl rand -hex 16 >"$api_tunnel_instance_file"
chmod 0600 "$api_tunnel_instance_file"

private_key=/run/secrets/e2e_ssh_key
public_key=/run/secrets/e2e_ssh_key.pub
[[ -f $private_key && -f $public_key ]] || { echo "mounted SSH keypair is missing" >&2; exit 2; }
[[ $(stat -c '%a' "$private_key") == 600 ]] || {
  echo "mounted SSH private key must have mode 0600" >&2
  exit 2
}
derived_key=$(ssh-keygen -y -f "$private_key" | awk '{print $1, $2}')
configured_key=$(awk 'NF >= 2 {print $1, $2; exit}' "$public_key")
[[ $derived_key == "$configured_key" ]] || { echo "SSH public key does not match private key" >&2; exit 2; }

export E2E_PRIVATE_KEY=$private_key
export E2E_PUBLIC_KEY=$public_key
active_ansible_pid=
ansible_starting=false
ansible_process_group_quiesced=true
durable_io=/opt/e2e/scripts/durable_io.py

durable_write_text() {
  "$durable_io" write-text "$1" "$2"
}

durable_remove() {
  "$durable_io" remove "$1"
}

durable_sync_directory() {
  "$durable_io" sync-directory "$1"
}

valid_run_id() {
  local value=$1
  [[ ${#value} -le 24 && $value =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]]
}

strict_regular_file() {
  local path=$1 expected_mode=${2:-600}
  [[ ! -L $path && -f $path ]] || return 1
  [[ $(stat -c '%F|%a' -- "$path") == "regular file|$expected_mode" ]]
}

require_run_directory() {
  local path=$1
  [[ ${path%/*} == /state && ! -L $path && -d $path ]] || return 1
  [[ $(stat -c '%F|%a' -- "$path") == 'directory|700' ]]
}

read_last_run_id() {
  strict_regular_file /state/last-run-id || {
    echo "persisted last-run-id must be a mode-0600 regular file" >&2
    return 2
  }
  local first
  IFS= read -r first </state/last-run-id || {
    echo "persisted last-run-id is empty" >&2
    return 2
  }
  (( $(wc -l </state/last-run-id) == 1 )) || {
    echo "persisted last-run-id must contain exactly one newline-terminated line" >&2
    return 2
  }
  valid_run_id "$first" || {
    echo "persisted last-run-id is invalid" >&2
    return 2
  }
  printf '%s\n' "$first"
}

state_binds_run_directory() {
  local directory=$1 run_id=${directory##*/}
  strict_regular_file "$directory/state.json" &&
    jq -e --arg run_id "$run_id" '
      type == "object" and
      (.runID | type == "string") and
      .runID == $run_id
    ' "$directory/state.json" >/dev/null 2>&1
}

set_run_context() {
  local value=$1
  valid_run_id "$value" || { echo "E2E run ID must be a lowercase DNS label of at most 24 characters" >&2; return 2; }
  export E2E_RUN_ID=$value
  export E2E_STATE_DIR=/state/$value
  if [[ -e $E2E_STATE_DIR || -L $E2E_STATE_DIR ]]; then
    require_run_directory "$E2E_STATE_DIR" || {
      echo "E2E run must be a direct mode-0700 non-symlink state child" >&2
      return 2
    }
  else
    mkdir "$E2E_STATE_DIR"
    chmod 0700 "$E2E_STATE_DIR"
  fi
  durable_sync_directory /state
}

final_audit_is_zero() {
  local directory=$1
  require_run_directory "$directory" || return 1
  strict_regular_file "$directory/final-audit.json" || return 1
  if [[ ! -e $directory/state.json && ! -L $directory/state.json ]]; then
    strict_regular_file "$directory/mutations-not-started" || return 1
    (( $(wc -c <"$directory/mutations-not-started") == 22 )) || return 1
    [[ $(<"$directory/mutations-not-started") == mutations-not-started ]] || return 1
    [[ ! -e $directory/mutations-may-exist && ! -L $directory/mutations-may-exist ]] || return 1
    jq -e '
      type == "object" and
      (keys | sort) == ["count", "mutationsNeverStarted"] and
      .count == 0 and .mutationsNeverStarted == true
    ' "$directory/final-audit.json" >/dev/null 2>&1
    return
  fi
  state_binds_run_directory "$directory" || return 1
  strict_regular_file "$directory/baseline-inventory.json" || return 1
  jq -e '
    def resources:
      ["buckets", "disks", "firewalls", "floatingIPs", "loadBalancers",
       "networks", "servicePackages", "vms"];
    type == "object" and
    (keys | sort) == resources and
    all(.[]; type == "array" and
      all(.[]; type == "string" and length > 0) and
      . == (sort | unique))
  ' "$directory/baseline-inventory.json" >/dev/null 2>&1 || return 1
  jq -e '
    def resources:
      ["buckets", "disks", "firewalls", "floatingIPs", "loadBalancers",
       "networks", "servicePackages", "vms"];
    type == "object" and
    (keys | sort) == ["accountInventory", "count", "deterministicOwners"] and
    .count == 0 and
    (.deterministicOwners | type == "object") and
    (.deterministicOwners | keys | sort) ==
      ["count", "disks", "firewalls", "floatingIPs", "loadBalancers",
       "strictReadCount", "vms"] and
    .deterministicOwners.count == 0 and
    .deterministicOwners.strictReadCount == 3 and
    all(.deterministicOwners.disks,
        .deterministicOwners.firewalls,
        .deterministicOwners.floatingIPs,
        .deterministicOwners.loadBalancers,
        .deterministicOwners.vms; type == "array" and length == 0) and
    (.accountInventory | type == "object") and
    (.accountInventory | keys | sort) ==
      ["differenceCount", "extra", "matches", "missing", "strictReadCount"] and
    .accountInventory.matches == true and
    .accountInventory.differenceCount == 0 and
    .accountInventory.strictReadCount == 3 and
    (.accountInventory.extra | type == "object" and (keys | sort) == resources) and
    (.accountInventory.missing | type == "object" and (keys | sort) == resources) and
    all(.accountInventory.extra[]; type == "array" and length == 0) and
    all(.accountInventory.missing[]; type == "array" and length == 0)
  ' "$directory/final-audit.json" >/dev/null 2>&1
}

read_retention_state() {
  local state=$1
  jq -rs '
    if length != 1 then
      error("retention state must contain exactly one JSON value")
    elif (.[0] | type) != "object" then
      error("retention state must be an object")
    elif (.[0] | has("retained") | not) then
      "false"
    elif (.[0].retained | type) == "boolean" then
      (.[0].retained | tostring)
    else
      error("retained must be a boolean")
    end
  ' "$state"
}

retention_for_directory() {
  local directory=$1
  if [[ -e $directory/retained || -L $directory/retained ]]; then
    strict_regular_file "$directory/retained" || {
      echo "retained marker must be a mode-0600 regular file" >&2
      return 1
    }
    printf 'true\n'
  elif [[ -e $directory/state.json || -L $directory/state.json ]]; then
    state_binds_run_directory "$directory" || {
      echo "ownership journal does not bind its direct-child run directory" >&2
      return 1
    }
    read_retention_state "$directory/state.json"
  else
    printf 'false\n'
  fi
}

pid_is_running() {
  local pid=$1 proc_pid proc_name proc_state remainder
  [[ -r /proc/$pid/stat ]] || return 1
  read -r proc_pid proc_name proc_state remainder 2>/dev/null <"/proc/$pid/stat" || return 1
  [[ $proc_state != Z && $proc_state != X ]]
}

terminate_process_group() {
  local pid=$1
  if kill -0 -- "-$pid" 2>/dev/null; then
    kill -TERM -- "-$pid" 2>/dev/null || true
  elif pid_is_running "$pid"; then
    # Cover the tiny interval before setsid establishes the new group.
    kill -TERM "$pid" 2>/dev/null || true
  fi
  for _ in {1..100}; do
    if ! pid_is_running "$pid" && ! kill -0 -- "-$pid" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  kill -KILL -- "-$pid" 2>/dev/null || true
  kill -KILL "$pid" 2>/dev/null || true
  for _ in {1..100}; do
    if ! pid_is_running "$pid" && ! kill -0 -- "-$pid" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

terminate_active_ansible() {
  local pid=${active_ansible_pid:-}
  if [[ -z $pid ]]; then
    [[ $ansible_process_group_quiesced == true ]]
    return
  fi
  terminate_process_group "$pid" || {
    ansible_process_group_quiesced=false
    return 1
  }
  wait "$pid" 2>/dev/null || true
  active_ansible_pid=
}

run_ansible() {
  [[ $ansible_process_group_quiesced == true ]] || {
    echo "refusing another Ansible phase while an earlier process group may still exist" >&2
    return 1
  }
  ansible_starting=true
  setsid ansible-playbook "$@" --forks 10 &
  active_ansible_pid=$!
  ansible_starting=false
  local result=0
  wait "$active_ansible_pid" || result=$?
  if kill -0 -- "-$active_ansible_pid" 2>/dev/null; then
    echo "Ansible exited with a lingering process group; terminating it before continuing" >&2
    terminate_process_group "$active_ansible_pid" || ansible_process_group_quiesced=false
    result=1
  fi
  active_ansible_pid=
  return "$result"
}

mark_phase_preserved() {
  [[ -n ${E2E_STATE_DIR:-} ]] || return 0
  local marker=$E2E_STATE_DIR/phase-preserved
  durable_write_text "$marker" $'phase-preserved\n'
}

clear_phase_preserved() {
  local directory=$1
  durable_remove "$directory/phase-preserved"
}

mark_retained() {
  [[ -n ${E2E_STATE_DIR:-} ]] || return 0
  local marker=$E2E_STATE_DIR/retained
  durable_write_text "$marker" $'retained\n'
  local state=$E2E_STATE_DIR/state.json
  [[ -f $state ]] || return 0
  /opt/e2e/scripts/state-update.py "$state" retained true
}

clear_retained() {
  local directory=$1
  if [[ -f $directory/state.json ]]; then
    /opt/e2e/scripts/state-update.py "$directory/state.json" retained false
  fi
  durable_remove "$directory/retained"
}

stop_api_tunnel() {
  [[ -n ${E2E_STATE_DIR:-} && -f $E2E_STATE_DIR/state.json ]] || return 0
  /opt/e2e/scripts/api-tunnel.sh stop "$E2E_STATE_DIR/state.json" || true
}

require_exact_state_version() {
  local directory=$1
  if [[ ! -e $directory/state.json && ! -L $directory/state.json ]]; then
    return 0
  fi
  state_binds_run_directory "$directory" || {
    echo "run ${directory##*/} has an invalid or misbound ownership journal" >&2
    return 1
  }
  local state_version
  state_version=$(jq -er '.version | select(type == "string" and length > 0)' "$directory/state.json") || {
    echo "run ${directory##*/} lacks its exact released version; refusing recovery with an unknown controller" >&2
    return 1
  }
  if [[ $state_version != "$INSPACE_E2E_VERSION" ]]; then
    echo "run ${directory##*/} requires INSPACE_E2E_VERSION=$state_version for exact-artifact access" >&2
    return 2
  fi
}

require_persisted_release_binding() {
  local directory=$1
  strict_regular_file "$directory/release-images.json" || {
    echo "run ${directory##*/} lacks its durable verified release-artifact manifest" >&2
    return 2
  }
  /opt/e2e/scripts/verify-release-images.py \
    --persisted-state-root /state \
    --run-id "${directory##*/}" \
    --output /run/inspace-e2e-persisted-release-images.json \
    --expect-environment-prefix INSPACE_E2E_BUILT_ \
    >/dev/null
}

persist_preflight_release_artifacts() {
  local expected_root="/state/release-preflight/v$INSPACE_E2E_VERSION-$INSPACE_E2E_RELEASE_REVISION"
  [[ $INSPACE_E2E_RELEASE_ARTIFACT_ROOT == "$expected_root" ]] || {
    echo "mounted preflight artifacts do not match the exact release identity" >&2
    return 2
  }
  /opt/e2e/scripts/verify-release-images.py \
    --artifact-root "$INSPACE_E2E_RELEASE_ARTIFACT_ROOT" \
    --copy-to-state "$E2E_STATE_DIR" \
    --output /run/inspace-e2e-copied-release-images.json \
    --expect-environment-prefix INSPACE_E2E_ \
    >/dev/null
}

select_existing_run() {
  local selected=${INSPACE_E2E_RUN_ID:-}
  if [[ -z $selected ]]; then
    if [[ ! -e /state/last-run-id && ! -L /state/last-run-id ]]; then
      echo "$phase requires INSPACE_E2E_RUN_ID or a persisted last run" >&2
      return 2
    fi
    selected=$(read_last_run_id)
  fi
  [[ -n $selected ]] || { echo "$phase requires INSPACE_E2E_RUN_ID or a persisted last run" >&2; return 2; }
  valid_run_id "$selected" || { echo "selected E2E run ID is invalid" >&2; return 2; }
  require_run_directory "/state/$selected" || {
    echo "selected E2E run $selected is not a direct mode-0700 state child" >&2
    return 2
  }
  set_run_context "$selected"
}

select_initialized_run() {
  select_existing_run
  [[ -f $E2E_STATE_DIR/state.json ]] || { echo "run $E2E_RUN_ID has no initialization journal" >&2; return 2; }
  require_exact_state_version "$E2E_STATE_DIR"
  require_persisted_release_binding "$E2E_STATE_DIR"
  jq -e '.initComplete == true' "$E2E_STATE_DIR/state.json" >/dev/null || {
    echo "run $E2E_RUN_ID did not complete cluster initialization" >&2
    return 2
  }
  if final_audit_is_zero "$E2E_STATE_DIR"; then
    echo "run $E2E_RUN_ID has already been destroyed" >&2
    return 2
  fi
}

select_debuggable_run() {
  select_existing_run
  [[ -f $E2E_STATE_DIR/state.json ]] || { echo "run $E2E_RUN_ID has no cluster access journal" >&2; return 2; }
  require_exact_state_version "$E2E_STATE_DIR"
  require_persisted_release_binding "$E2E_STATE_DIR"
  if final_audit_is_zero "$E2E_STATE_DIR"; then
    echo "run $E2E_RUN_ID has already been destroyed" >&2
    return 2
  fi
}

cleanup_current_run() {
  [[ $ansible_process_group_quiesced == true ]] || {
    echo "refusing cleanup while a prior Ansible process group may still be active" >&2
    return 1
  }
  run_ansible /opt/e2e/destroy-cluster.yml || return 1
  final_audit_is_zero "$E2E_STATE_DIR" || {
    echo "cleanup lacks a final zero audit for $E2E_RUN_ID" >&2
    return 1
  }
}

refuse_unfinished_previous_run() {
  [[ -e /state/last-run-id || -L /state/last-run-id ]] || return 0
  local previous_run
  previous_run=$(read_last_run_id)
  local previous_dir=/state/$previous_run
  require_run_directory "$previous_dir" || { echo "persisted E2E run $previous_run is missing or unsafe; refusing new mutations" >&2; return 2; }
  if [[ -e $previous_dir/phase-preserved || -L $previous_dir/phase-preserved ]]; then
    strict_regular_file "$previous_dir/phase-preserved" || {
      echo "phase-preserved marker is not a mode-0600 regular file" >&2
      return 2
    }
    echo "run $previous_run is preserved by the phased workflow; use test, shell, or destroy" >&2
    return 2
  fi
  local retained
  retained=$(retention_for_directory "$previous_dir") || {
    echo "previous run has an unreadable retention state; preserving it" >&2
    return 1
  }
  if [[ $retained == true ]] || ! final_audit_is_zero "$previous_dir"; then
    echo "run $previous_run is unfinished; use test, shell, or destroy before another init" >&2
    return 2
  fi
}

recover_previous_run_for_all() {
  [[ -e /state/last-run-id || -L /state/last-run-id ]] || return 0
  local previous_run
  previous_run=$(read_last_run_id)
  local previous_dir=/state/$previous_run
  require_run_directory "$previous_dir" || { echo "persisted E2E run $previous_run is missing or unsafe; refusing new mutations" >&2; return 2; }
  if [[ -e $previous_dir/phase-preserved || -L $previous_dir/phase-preserved ]]; then
    strict_regular_file "$previous_dir/phase-preserved" || {
      echo "phase-preserved marker is not a mode-0600 regular file" >&2
      return 2
    }
    echo "run $previous_run is preserved by the phased workflow; run the explicit destroy phase first" >&2
    return 2
  fi
  local retained
  retained=$(retention_for_directory "$previous_dir") || {
    echo "unfinished run has an unreadable retention state; preserving it" >&2
    return 1
  }
  if [[ $retained == true && $INSPACE_E2E_RECOVER_RETAINED != true ]]; then
    echo "run $previous_run was explicitly retained; set INSPACE_E2E_RECOVER_RETAINED=true to authorize cleanup" >&2
    return 2
  fi
  if [[ $retained == true ]] || ! final_audit_is_zero "$previous_dir"; then
    set_run_context "$previous_run"
    require_exact_state_version "$previous_dir"
    require_persisted_release_binding "$previous_dir"
    echo "recovering unfinished E2E run $previous_run before any new provisioning" >&2
    cleanup_current_run || {
      echo "unfinished-run cleanup failed closed; refusing new provisioning" >&2
      return 1
    }
    clear_retained "$previous_dir"
  fi
}

start_new_run() {
  local run_id=${INSPACE_E2E_RUN_ID:-$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 3)}
  if [[ -e /state/$run_id ]]; then
    echo "refusing to reuse existing E2E run ID $run_id; choose a new ID" >&2
    return 2
  fi
  set_run_context "$run_id"
  persist_preflight_release_artifacts
  durable_write_text "$E2E_STATE_DIR/mutations-not-started" $'mutations-not-started\n'
  durable_write_text /state/last-run-id "$run_id"$'\n'
}

cleanup_on_signal() {
  local signal=$1
  trap '' INT TERM
  if [[ $ansible_starting == true ]]; then
    ansible_process_group_quiesced=false
    echo "received $signal while the Ansible process group identity was not yet stable; refusing concurrent cleanup" >&2
    mark_phase_preserved || true
    [[ $signal == INT ]] && exit 130
    exit 143
  fi
  if ! terminate_active_ansible; then
    echo "could not prove the active Ansible process group stopped; refusing concurrent cleanup" >&2
    mark_phase_preserved || true
    [[ $signal == INT ]] && exit 130
    exit 143
  fi
  case "$active_phase" in
    all)
      if [[ $INSPACE_E2E_KEEP_RESOURCES == true ]]; then
        mark_retained || echo "retention journal update failed; durable retained marker still prevents implicit cleanup" >&2
        echo "received $signal; resources retained by explicit request at ${E2E_STATE_DIR:-preflight}" >&2
      elif [[ -n ${E2E_STATE_DIR:-} ]]; then
        echo "received $signal; starting fail-closed Ansible cleanup" >&2
        cleanup_current_run || \
          echo "signal cleanup failed closed; inspect the persisted ownership journal" >&2
      fi
      ;;
    destroy)
      if [[ -n ${E2E_STATE_DIR:-} ]]; then
        echo "received $signal; retrying fail-closed destroy" >&2
        cleanup_current_run || \
          echo "signal cleanup failed closed; rerun the destroy phase" >&2
      fi
      ;;
    init | test | shell)
      mark_phase_preserved || echo "failed to refresh the durable phase-preserved marker" >&2
      stop_api_tunnel
      echo "received $signal during $active_phase; cluster preserved for debugging or explicit destroy" >&2
      ;;
  esac
  [[ $signal == INT ]] && exit 130
  exit 143
}
trap 'cleanup_on_signal INT' INT
trap 'cleanup_on_signal TERM' TERM

case "$phase" in
  all)
    recover_previous_run_for_all
    start_new_run
    set +e
    run_ansible /opt/e2e/init-cluster.yml
    suite_status=$?
    if (( suite_status == 0 )); then
      run_ansible /opt/e2e/test.yml
      suite_status=$?
    fi
    cleanup_status=0
    retention_status=0
    if [[ $INSPACE_E2E_KEEP_RESOURCES == true ]]; then
      mark_retained || retention_status=$?
      stop_api_tunnel
      echo "E2E resources retained by explicit request; state volume path: $E2E_STATE_DIR" >&2
    else
      cleanup_current_run || cleanup_status=$?
    fi
    set -e
    (( cleanup_status == 0 && retention_status == 0 )) || exit 1
    exit "$suite_status"
    ;;
  init)
    refuse_unfinished_previous_run
    start_new_run
    mark_phase_preserved
    set +e
    run_ansible /opt/e2e/init-cluster.yml
    phase_status=$?
    stop_api_tunnel
    set -e
    echo "cluster $E2E_RUN_ID preserved; run test, shell, or destroy as the next phase" >&2
    exit "$phase_status"
    ;;
  test)
    select_initialized_run
    mark_phase_preserved
    set +e
    run_ansible /opt/e2e/test.yml
    phase_status=$?
    stop_api_tunnel
    set -e
    echo "cluster $E2E_RUN_ID preserved after test phase" >&2
    exit "$phase_status"
    ;;
  shell)
    select_debuggable_run
    mark_phase_preserved
    run_ansible /opt/e2e/test.yml --tags e2e-attach --extra-vars e2e_attach_require_initialized=false
    export KUBECONFIG=$E2E_STATE_DIR/kubeconfig.yaml
    echo "Tunneled kubectl shell for E2E run $E2E_RUN_ID; exit leaves the cluster running." >&2
    set +e
    PS1="(inspace-e2e:$E2E_RUN_ID) \\u@\\h:\\w\\$ " /bin/bash --noprofile --norc
    phase_status=$?
    stop_api_tunnel
    set -e
    exit "$phase_status"
    ;;
  destroy)
    select_existing_run
    retained=$(retention_for_directory "$E2E_STATE_DIR") || {
      echo "selected run has an unreadable retention state; preserving it" >&2
      exit 1
    }
    if [[ $retained == true && $INSPACE_E2E_RECOVER_RETAINED != true ]]; then
      echo "run $E2E_RUN_ID was explicitly retained; set INSPACE_E2E_RECOVER_RETAINED=true to authorize cleanup" >&2
      exit 2
    fi
    if ! final_audit_is_zero "$E2E_STATE_DIR"; then
      require_exact_state_version "$E2E_STATE_DIR"
      require_persisted_release_binding "$E2E_STATE_DIR"
      cleanup_current_run
    fi
    final_audit_is_zero "$E2E_STATE_DIR" || { echo "destroy lacks a final zero audit" >&2; exit 1; }
    clear_retained "$E2E_STATE_DIR"
    clear_phase_preserved "$E2E_STATE_DIR"
    echo "E2E run $E2E_RUN_ID destroyed with a final zero cloud audit"
    ;;
esac
