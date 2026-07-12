#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

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
mounted_recovery_only=${INSPACE_E2E_RECOVERY_ONLY:-false}
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
export INSPACE_E2E_RECOVERY_ONLY=$mounted_recovery_only
export INSPACE_E2E_RECOVER_RETAINED=$mounted_recover_retained
[[ -z $mounted_run_id ]] || export INSPACE_E2E_RUN_ID=$mounted_run_id

for name in INSPACE_API_URL INSPACE_API_TOKEN INSPACE_LOCATION \
  INSPACE_BILLING_ACCOUNT_ID INSPACE_NETWORK_UUID INSPACE_CONTROL_PLANE_VIP \
  INSPACE_PRIVATE_LOAD_BALANCER_POOL_START INSPACE_PRIVATE_LOAD_BALANCER_POOL_STOP \
  INSPACE_INTEL_HOST_POOL_UUID INSPACE_E2E_VERSION; do
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
for name in INSPACE_E2E_KEEP_RESOURCES INSPACE_E2E_RECOVERY_ONLY INSPACE_E2E_RECOVER_RETAINED; do
  [[ ${!name} == false || ${!name} == true ]] || { echo "$name must be true or false" >&2; exit 2; }
done

for command_name in ansible-playbook curl flock helm jq kubectl openssl skopeo ssh ssh-keygen stat; do
  command -v "$command_name" >/dev/null || { echo "runner image is missing $command_name" >&2; exit 2; }
done

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

terminate_active_ansible() {
  local pid=${active_ansible_pid:-}
  [[ -n $pid ]] || return 0
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    for _ in {1..100}; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  wait "$pid" 2>/dev/null || true
  active_ansible_pid=
}

run_ansible() {
  ansible-playbook "$@" --forks 10 &
  active_ansible_pid=$!
  local result=0
  wait "$active_ansible_pid" || result=$?
  active_ansible_pid=
  return "$result"
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

cleanup_on_signal() {
  local signal=$1
  trap '' INT TERM
  terminate_active_ansible
  if [[ $INSPACE_E2E_KEEP_RESOURCES == true ]]; then
    if ! mark_retained; then
      echo "retention journal update failed; durable retained marker still prevents implicit cleanup" >&2
    fi
    echo "received $signal; resources retained by explicit request at ${E2E_STATE_DIR:-preflight}" >&2
  elif [[ -z ${E2E_STATE_DIR:-} ]]; then
    echo "received $signal before any run could mutate cloud state" >&2
  else
    echo "received $signal; starting fail-closed Ansible cleanup" >&2
    if ! ansible-playbook /opt/e2e/cleanup.yml --forks 10; then
      echo "signal cleanup failed closed; inspect the persisted ownership journal" >&2
    fi
  fi
  [[ $signal == INT ]] && exit 130
  exit 143
}
trap 'cleanup_on_signal INT' INT
trap 'cleanup_on_signal TERM' TERM

previous_run=
if [[ -n ${INSPACE_E2E_RUN_ID:-} && $INSPACE_E2E_RECOVERY_ONLY == true ]]; then
  previous_run=$INSPACE_E2E_RUN_ID
elif [[ -f /state/last-run-id ]]; then
  previous_run=$(< /state/last-run-id)
fi
if [[ -n $previous_run ]]; then
  valid_run_id "$previous_run" || { echo "persisted last-run-id is invalid; refusing new mutations" >&2; exit 2; }
  previous_dir=/state/$previous_run
  retained=false
  if [[ -f $previous_dir/retained ]]; then
    retained=true
  elif [[ -f $previous_dir/state.json ]]; then
    retained=$(jq -er '.retained // false' "$previous_dir/state.json") || {
      echo "unfinished run has an unreadable retention state; preserving it" >&2
      exit 1
    }
  fi
  if [[ $retained == true && $INSPACE_E2E_RECOVER_RETAINED != true ]]; then
    echo "run $previous_run was explicitly retained; set INSPACE_E2E_RECOVER_RETAINED=true to authorize cleanup" >&2
    exit 2
  fi
  # A durable retention marker always forces an explicitly authorized cleanup,
  # even if a stale or manually restored zero-audit file is present.
  if [[ $retained == true ]] || ! final_audit_is_zero "$previous_dir"; then
    set_run_context "$previous_run"
    if [[ -f $previous_dir/state.json ]]; then
      previous_version=$(jq -er '.version' "$previous_dir/state.json") || {
        echo "unfinished run lacks its exact released version; refusing recovery with an unknown controller" >&2
        exit 1
      }
      if [[ $previous_version != "$INSPACE_E2E_VERSION" ]]; then
        echo "unfinished run $previous_run requires INSPACE_E2E_VERSION=$previous_version for exact-artifact recovery" >&2
        exit 2
      fi
    fi
    echo "recovering unfinished E2E run $previous_run before any new provisioning" >&2
    if ! run_ansible /opt/e2e/cleanup.yml; then
      echo "unfinished-run cleanup failed closed; refusing new provisioning" >&2
      exit 1
    fi
    final_audit_is_zero "$previous_dir" || {
      echo "unfinished-run cleanup lacks a final zero audit; refusing new provisioning" >&2
      exit 1
    }
  fi
  if [[ $retained == true && $INSPACE_E2E_RECOVER_RETAINED == true ]]; then
    rm -f "$previous_dir/retained"
    if [[ -f $previous_dir/state.json ]]; then
      /opt/e2e/scripts/state-update.py "$previous_dir/state.json" retained false
    fi
  fi
fi

if [[ $INSPACE_E2E_RECOVERY_ONLY == true ]]; then
  [[ -n $previous_run ]] || { echo "recovery-only mode requires INSPACE_E2E_RUN_ID or a persisted last run" >&2; exit 2; }
  echo "E2E recovery completed with a final zero audit for $previous_run"
  exit 0
fi

run_id=${INSPACE_E2E_RUN_ID:-$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 3)}
if [[ -e /state/$run_id ]]; then
  echo "refusing to reuse existing E2E run ID $run_id; choose a new ID or use recovery-only mode" >&2
  exit 2
fi
set_run_context "$run_id"
printf 'mutations-not-started\n' >"$E2E_STATE_DIR/mutations-not-started"
chmod 0600 "$E2E_STATE_DIR/mutations-not-started"
printf '%s\n' "$run_id" >/state/last-run-id
chmod 0600 /state/last-run-id

set +e
run_ansible /opt/e2e/playbook.yml
suite_status=$?
cleanup_status=0
retention_status=0
if [[ $INSPACE_E2E_KEEP_RESOURCES == true ]]; then
  mark_retained || retention_status=$?
  echo "E2E resources retained by explicit request; state volume path: $E2E_STATE_DIR" >&2
else
  run_ansible /opt/e2e/cleanup.yml
  cleanup_status=$?
fi
set -e

if (( cleanup_status != 0 )); then
  exit 1
fi
if (( retention_status != 0 )); then
  exit 1
fi
exit "$suite_status"
