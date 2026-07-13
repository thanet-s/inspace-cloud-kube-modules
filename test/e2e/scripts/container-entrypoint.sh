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
mounted_keep=${INSPACE_E2E_KEEP_RESOURCES:-false}
mounted_run_id=${INSPACE_E2E_RUN_ID:-}
mounted_recover_retained=${INSPACE_E2E_RECOVER_RETAINED:-false}
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
export INSPACE_E2E_KEEP_RESOURCES=$mounted_keep
export INSPACE_E2E_RECOVER_RETAINED=$mounted_recover_retained
[[ -z $mounted_run_id ]] || export INSPACE_E2E_RUN_ID=$mounted_run_id

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

for command_name in ansible-playbook autossh curl flock helm jq kubectl openssl setsid skopeo ss ssh ssh-keygen stat; do
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

valid_run_id() {
  local value=$1
  [[ ${#value} -le 24 && $value =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]]
}

set_run_context() {
  local value=$1
  valid_run_id "$value" || { echo "E2E run ID must be a lowercase DNS label of at most 24 characters" >&2; return 2; }
  export E2E_RUN_ID=$value
  export E2E_STATE_DIR=/state/$value
  mkdir -p "$E2E_STATE_DIR"
  chmod 0700 "$E2E_STATE_DIR"
}

final_audit_is_zero() {
  local directory=$1
  [[ -f $directory/final-audit.json ]] && jq -e '.count == 0' "$directory/final-audit.json" >/dev/null 2>&1
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
  if [[ -f $directory/retained ]]; then
    printf 'true\n'
  elif [[ -f $directory/state.json ]]; then
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
  local temporary=$E2E_STATE_DIR/.phase-preserved.$$.tmp
  printf 'phase-preserved\n' >"$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$marker"
}

clear_phase_preserved() {
  local directory=$1
  rm -f "$directory/phase-preserved"
}

mark_retained() {
  [[ -n ${E2E_STATE_DIR:-} ]] || return 0
  local marker=$E2E_STATE_DIR/retained
  local temporary=$E2E_STATE_DIR/.retained.$$.tmp
  printf 'retained\n' >"$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$marker"
  local state=$E2E_STATE_DIR/state.json
  [[ -f $state ]] || return 0
  /opt/e2e/scripts/state-update.py "$state" retained true
}

clear_retained() {
  local directory=$1
  if [[ -f $directory/state.json ]]; then
    /opt/e2e/scripts/state-update.py "$directory/state.json" retained false
  fi
  rm -f "$directory/retained"
}

stop_api_tunnel() {
  [[ -n ${E2E_STATE_DIR:-} && -f $E2E_STATE_DIR/state.json ]] || return 0
  /opt/e2e/scripts/api-tunnel.sh stop "$E2E_STATE_DIR/state.json" || true
}

require_exact_state_version() {
  local directory=$1
  [[ -f $directory/state.json ]] || return 0
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

select_existing_run() {
  local selected=${INSPACE_E2E_RUN_ID:-}
  if [[ -z $selected && -f /state/last-run-id ]]; then
    selected=$(< /state/last-run-id)
  fi
  [[ -n $selected ]] || { echo "$phase requires INSPACE_E2E_RUN_ID or a persisted last run" >&2; return 2; }
  valid_run_id "$selected" || { echo "selected E2E run ID is invalid" >&2; return 2; }
  [[ -d /state/$selected ]] || { echo "selected E2E run $selected does not exist in the state volume" >&2; return 2; }
  set_run_context "$selected"
}

select_initialized_run() {
  select_existing_run
  [[ -f $E2E_STATE_DIR/state.json ]] || { echo "run $E2E_RUN_ID has no initialization journal" >&2; return 2; }
  require_exact_state_version "$E2E_STATE_DIR"
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
  [[ -f /state/last-run-id ]] || return 0
  local previous_run
  previous_run=$(< /state/last-run-id)
  valid_run_id "$previous_run" || { echo "persisted last-run-id is invalid; refusing new mutations" >&2; return 2; }
  local previous_dir=/state/$previous_run
  [[ -d $previous_dir ]] || { echo "persisted E2E run $previous_run is missing; refusing new mutations" >&2; return 2; }
  if [[ -f $previous_dir/phase-preserved ]]; then
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
  [[ -f /state/last-run-id ]] || return 0
  local previous_run
  previous_run=$(< /state/last-run-id)
  valid_run_id "$previous_run" || { echo "persisted last-run-id is invalid; refusing new mutations" >&2; return 2; }
  local previous_dir=/state/$previous_run
  [[ -d $previous_dir ]] || { echo "persisted E2E run $previous_run is missing; refusing new mutations" >&2; return 2; }
  if [[ -f $previous_dir/phase-preserved ]]; then
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
  printf 'mutations-not-started\n' >"$E2E_STATE_DIR/mutations-not-started"
  chmod 0600 "$E2E_STATE_DIR/mutations-not-started"
  printf '%s\n' "$run_id" >/state/last-run-id
  chmod 0600 /state/last-run-id
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
      cleanup_current_run
    fi
    final_audit_is_zero "$E2E_STATE_DIR" || { echo "destroy lacks a final zero audit" >&2; exit 1; }
    clear_retained "$E2E_STATE_DIR"
    clear_phase_preserved "$E2E_STATE_DIR"
    echo "E2E run $E2E_RUN_ID destroyed with a final zero cloud audit"
    ;;
esac
