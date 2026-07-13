#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

action=${1:?usage: api-tunnel.sh start|check|stop STATE}
state_file=${2:?usage: api-tunnel.sh start|check|stop STATE}
state_dir=${state_file%/*}
socket=$state_dir/api-tunnel.sock
pid_file=$state_dir/api-tunnel.pid
log_file=$state_dir/api-tunnel.log
instance_file=/run/inspace-e2e-api-tunnel-instance
known_hosts=$state_dir/known-hosts-bastion
key=${E2E_PRIVATE_KEY:?E2E_PRIVATE_KEY is required}
[[ -r $instance_file ]] || { echo "API tunnel container-instance file is missing" >&2; exit 2; }
instance_token=$(<"$instance_file")
[[ $instance_token =~ ^[0-9a-f]{32}$ ]] || { echo "API tunnel container-instance token is invalid" >&2; exit 2; }
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
tunnel_arguments=(
  -N
  -T
  "${options[@]}"
  -o ExitOnForwardFailure=yes
  -L "127.0.0.1:16443:$virtual_ip:6443"
  "$target"
)

legacy_control() {
  ssh "${options[@]}" -S "$socket" -O "$1" "$target" >/dev/null 2>&1
}

tunnel_ready() {
  local expected_group=$1 line listener_state recv_queue send_queue local_address peer_address process_details extra owner_pid
  local listener_count=0
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    read -r listener_state recv_queue send_queue local_address peer_address process_details extra <<<"$line" || return 1
    [[ $listener_state == LISTEN && $local_address == 127.0.0.1:16443 && -z ${extra:-} ]] || return 1
    [[ $process_details =~ pid=([1-9][0-9]*),fd= ]] || return 1
    owner_pid=${BASH_REMATCH[1]}
    ssh_child_identity "$owner_pid" "$expected_group" || return 1
    ((listener_count += 1))
  done < <(ss -H -ltnp "sport = :16443" 2>/dev/null)
  ((listener_count == 1))
}

read_supervisor_record() {
  local pid start_time record_token extra
  [[ -s $pid_file ]] || return 1
  read -r pid start_time record_token extra <"$pid_file" || return 1
  [[ $pid =~ ^[1-9][0-9]*$ && $start_time =~ ^[1-9][0-9]*$ &&
     $record_token =~ ^[0-9a-f]{32}$ && -z ${extra:-} ]] || return 1
  printf '%s %s %s\n' "$pid" "$start_time" "$record_token"
}

read_process_metadata() {
  local pid=$1 stat remainder
  local -a fields
  [[ -r /proc/$pid/stat ]] || return 1
  IFS= read -r stat 2>/dev/null <"/proc/$pid/stat" || return 1
  remainder=${stat##*) }
  read -r -a fields <<<"$remainder" || return 1
  ((${#fields[@]} > 19)) || return 1
  [[ ${fields[0]} != Z && ${fields[0]} != X && ${fields[2]} =~ ^[1-9][0-9]*$ && ${fields[19]} =~ ^[1-9][0-9]*$ ]] || return 1
  printf '%s %s %s\n' "${fields[0]}" "${fields[2]}" "${fields[19]}"
}

read_process_comm() {
  local pid=$1 comm
  [[ -r /proc/$pid/comm ]] || return 1
  IFS= read -r comm 2>/dev/null <"/proc/$pid/comm" || return 1
  [[ -n $comm ]] || return 1
  printf '%s\n' "$comm"
}

same_process_instance() {
  local pid=$1 expected_start_time=$2 state process_group actual_start_time
  read -r state process_group actual_start_time < <(read_process_metadata "$pid") || return 1
  [[ $actual_start_time == "$expected_start_time" ]]
}

supervisor_identity() {
  local pid=$1 expected_start_time=$2
  local state process_group actual_start_time final_state final_group final_start_time
  local process_comm final_comm
  local index argument_offset=1
  local -a arguments expected_arguments
  read -r state process_group actual_start_time < <(read_process_metadata "$pid") || return 1
  [[ $actual_start_time == "$expected_start_time" && $process_group == "$pid" ]] || return 1
  process_comm=$(read_process_comm "$pid") || return 1
  [[ $process_comm == autossh ]] || return 1
  mapfile -d '' -t arguments 2>/dev/null <"/proc/$pid/cmdline" || return 1
  expected_arguments=(-M 0 "${tunnel_arguments[@]}")
  ((${#arguments[@]} > 0)) || return 1
  [[ ${arguments[0]##*/} == autossh ]] || return 1
  if ((${#arguments[@]} == ${#expected_arguments[@]} + 2)); then
    [[ ${arguments[1]##*/} == autossh ]] || return 1
    argument_offset=2
  else
    ((${#arguments[@]} == ${#expected_arguments[@]} + 1)) || return 1
  fi
  for ((index = 0; index < ${#expected_arguments[@]}; index++)); do
    [[ ${arguments[index + argument_offset]} == "${expected_arguments[index]}" ]] || return 1
  done
  read -r final_state final_group final_start_time < <(read_process_metadata "$pid") || return 1
  final_comm=$(read_process_comm "$pid") || return 1
  [[ $final_start_time == "$expected_start_time" && $final_group == "$pid" && $final_comm == "$process_comm" ]]
}

process_group_is_running() {
  local expected_group=$1 proc stat remainder
  local -a fields
  for proc in /proc/[0-9]*/stat; do
    [[ -r $proc ]] || continue
    IFS= read -r stat 2>/dev/null <"$proc" || continue
    remainder=${stat##*) }
    read -r -a fields <<<"$remainder" || continue
    ((${#fields[@]} > 2)) || continue
    if [[ ${fields[2]} == "$expected_group" && ${fields[0]} != Z && ${fields[0]} != X ]]; then
      return 0
    fi
  done
  return 1
}

ssh_child_identity() {
  local pid=$1 expected_group=$2
  local state process_group start_time final_state final_group final_start_time
  local process_comm final_comm
  local index argument_offset=0
  local -a arguments
  read -r state process_group start_time < <(read_process_metadata "$pid") || return 1
  [[ $process_group == "$expected_group" ]] || return 1
  process_comm=$(read_process_comm "$pid") || return 1
  [[ $process_comm == ssh ]] || return 1
  mapfile -d '' -t arguments 2>/dev/null <"/proc/$pid/cmdline" || return 1
  if ((${#arguments[@]} == ${#tunnel_arguments[@]} + 1)); then
    [[ ${arguments[0]##*/} == ssh ]] || return 1
    argument_offset=1
  else
    # OrbStack/Rosetta exposes autossh's SSH child without an argv[0] entry.
    ((${#arguments[@]} == ${#tunnel_arguments[@]})) || return 1
  fi
  for ((index = 0; index < ${#tunnel_arguments[@]}; index++)); do
    [[ ${arguments[index + argument_offset]} == "${tunnel_arguments[index]}" ]] || return 1
  done
  read -r final_state final_group final_start_time < <(read_process_metadata "$pid") || return 1
  final_comm=$(read_process_comm "$pid") || return 1
  [[ $final_group == "$expected_group" && $final_start_time == "$start_time" && $final_comm == "$process_comm" ]]
}

tunnel_healthy() {
  local pid=$1 expected_start_time=$2
  supervisor_identity "$pid" "$expected_start_time" &&
    tunnel_ready "$pid" &&
    supervisor_identity "$pid" "$expected_start_time"
}

orphaned_tunnel_group_identity() {
  local expected_group=$1 proc pid stat remainder live_members=0
  local -a fields
  for proc in /proc/[0-9]*; do
    pid=${proc##*/}
    [[ -r $proc/stat ]] || continue
    IFS= read -r stat 2>/dev/null <"$proc/stat" || continue
    remainder=${stat##*) }
    read -r -a fields <<<"$remainder" || continue
    ((${#fields[@]} > 2)) || continue
    [[ ${fields[2]} == "$expected_group" && ${fields[0]} != Z && ${fields[0]} != X ]] || continue
    ((live_members += 1))
    ssh_child_identity "$pid" "$expected_group" || return 1
  done
  ((live_members > 0))
}

snapshot_verified_tunnel_members() {
  local expected_group=$1 expected_supervisor_start=${2:-} proc pid stat remainder state process_group start_time
  local output_name=$3 starts_name=$4 contaminated_name=$5 verified
  local -n output=$output_name starts=$starts_name contaminated_ref=$contaminated_name
  local -a fields
  output=()
  starts=()
  contaminated_ref=false
  for proc in /proc/[0-9]*; do
    pid=${proc##*/}
    [[ -r $proc/stat ]] || continue
    IFS= read -r stat 2>/dev/null <"$proc/stat" || continue
    remainder=${stat##*) }
    read -r -a fields <<<"$remainder" || continue
    ((${#fields[@]} > 19)) || continue
    state=${fields[0]}
    process_group=${fields[2]}
    start_time=${fields[19]}
    [[ $process_group == "$expected_group" && $state != Z && $state != X ]] || continue
    verified=false
    if [[ $pid == "$expected_group" && -n $expected_supervisor_start ]]; then
      supervisor_identity "$pid" "$expected_supervisor_start" && verified=true
    else
      ssh_child_identity "$pid" "$expected_group" && verified=true
    fi
    if [[ $verified != true ]]; then
      same_process_instance "$pid" "$start_time" && contaminated_ref=true
      continue
    fi
    output+=("$pid")
    starts+=("$start_time")
  done
}

verified_members_are_running() {
  local pids_name=$1 starts_name=$2 index
  local -n pids=$pids_name starts=$starts_name
  for ((index = 0; index < ${#pids[@]}; index++)); do
    same_process_instance "${pids[index]}" "${starts[index]}" && return 0
  done
  return 1
}

signal_verified_members() {
  local signal=$1 pids_name=$2 starts_name=$3 index
  local -n pids=$pids_name starts=$starts_name
  for ((index = 0; index < ${#pids[@]}; index++)); do
    same_process_instance "${pids[index]}" "${starts[index]}" || continue
    kill "-$signal" "${pids[index]}" 2>/dev/null || true
  done
}

terminate_verified_group() {
  local expected_group=$1 expected_supervisor_start=${2:-} contaminated _round
  local -a member_pids member_starts
  for _round in {1..3}; do
    snapshot_verified_tunnel_members "$expected_group" "$expected_supervisor_start" member_pids member_starts contaminated
    [[ $contaminated == false ]] || {
      echo "refusing to signal a tunnel process group containing an unverified live member" >&2
      return 1
    }
    ((${#member_pids[@]} > 0)) || return 0
    signal_verified_members TERM member_pids member_starts
    for _ in {1..100}; do
      verified_members_are_running member_pids member_starts || break
      sleep 0.1
    done
    if verified_members_are_running member_pids member_starts; then
      signal_verified_members KILL member_pids member_starts
      for _ in {1..100}; do
        verified_members_are_running member_pids member_starts || break
        sleep 0.1
      done
    fi
    verified_members_are_running member_pids member_starts && {
      echo "verified API tunnel processes did not stop" >&2
      return 1
    }
    # Only the original leader can match the recorded start time. Later
    # rounds target any exact SSH children it created during termination.
    expected_supervisor_start=
  done
  snapshot_verified_tunnel_members "$expected_group" "" member_pids member_starts contaminated
  [[ $contaminated == false ]] || {
    echo "API tunnel process group was reused or contaminated during termination" >&2
    return 1
  }
  ((${#member_pids[@]} == 0)) || {
    echo "verified API tunnel children kept appearing during termination" >&2
    return 1
  }
}

terminate_supervisor() {
  local pid=$1 expected_start_time=$2
  supervisor_identity "$pid" "$expected_start_time" || {
    echo "refusing to signal an unverified API tunnel supervisor" >&2
    return 1
  }
  terminate_verified_group "$pid" "$expected_start_time"
}

terminate_orphaned_tunnel_group() {
  local pid=$1
  orphaned_tunnel_group_identity "$pid" || {
    echo "refusing to signal an unverified orphaned API tunnel process group" >&2
    return 1
  }
  terminate_verified_group "$pid"
}

launch_active=false
launch_pid=
launch_initial_start_time=
launch_owner_pid=
launch_owner_start_time=

cleanup_failed_launch() {
  local record_pid record_start_time record_token state process_group current_start_time
  for _ in {1..40}; do
    if [[ -e $pid_file ]]; then
      read -r record_pid record_start_time record_token < <(read_supervisor_record) || {
        echo "failed tunnel launch left a malformed PID record" >&2
        return 1
      }
      if [[ -z $launch_pid && $record_token == "$instance_token" ]]; then
        launch_pid=$record_pid
        launch_initial_start_time=$record_start_time
      fi
      [[ $record_pid == "$launch_pid" && $record_token == "$instance_token" &&
         ( -z $launch_initial_start_time || $record_start_time == "$launch_initial_start_time" ) ]] || {
        echo "failed tunnel launch lost its exact PID record ownership" >&2
        return 1
      }
      stop_tunnel && return 0
    elif [[ -n $launch_pid ]]; then
      if [[ -z $launch_initial_start_time ]]; then
        if read -r state process_group current_start_time < <(read_process_metadata "$launch_pid"); then
          launch_initial_start_time=$current_start_time
        elif ! kill -0 "$launch_pid" 2>/dev/null; then
          return 0
        fi
      elif ! same_process_instance "$launch_pid" "$launch_initial_start_time"; then
        return 0
      fi
    fi
    sleep 0.05
  done

  if [[ -e $pid_file ]]; then
    read -r record_pid record_start_time record_token < <(read_supervisor_record) || return 1
    if [[ -z $launch_pid && $record_token == "$instance_token" ]]; then
      launch_pid=$record_pid
      launch_initial_start_time=$record_start_time
    fi
    [[ $record_pid == "$launch_pid" && $record_token == "$instance_token" &&
       ( -z $launch_initial_start_time || $record_start_time == "$launch_initial_start_time" ) ]] || return 1
    stop_tunnel
    return
  fi

  # The child publishes its record before setsid. Without a record it is
  # still the exact pre-session process launched by this helper.
  if [[ -n $launch_pid && -n $launch_initial_start_time ]] &&
     same_process_instance "$launch_pid" "$launch_initial_start_time"; then
    read -r state process_group current_start_time < <(read_process_metadata "$launch_pid") || return 1
    [[ $process_group != "$launch_pid" ]] || {
      echo "unrecorded tunnel launch unexpectedly entered its own process group" >&2
      return 1
    }
    kill -TERM "$launch_pid" 2>/dev/null || true
    for _ in {1..100}; do
      same_process_instance "$launch_pid" "$launch_initial_start_time" || break
      sleep 0.05
    done
    if same_process_instance "$launch_pid" "$launch_initial_start_time"; then
      kill -KILL "$launch_pid" 2>/dev/null || true
      for _ in {1..100}; do
        same_process_instance "$launch_pid" "$launch_initial_start_time" || break
        sleep 0.05
      done
    fi
    same_process_instance "$launch_pid" "$launch_initial_start_time" && return 1
  fi

  # Close the publication race: a record that appeared while the pre-session
  # child was being stopped must still be converged through normal validation.
  if [[ -e $pid_file ]]; then
    read -r record_pid record_start_time record_token < <(read_supervisor_record) || return 1
    if [[ -z $launch_pid && $record_token == "$instance_token" ]]; then
      launch_pid=$record_pid
      launch_initial_start_time=$record_start_time
    fi
    [[ $record_pid == "$launch_pid" && $record_token == "$instance_token" &&
       ( -z $launch_initial_start_time || $record_start_time == "$launch_initial_start_time" ) ]] || return 1
    stop_tunnel
  elif [[ -z $launch_pid || -z $launch_initial_start_time ]] ||
       same_process_instance "$launch_pid" "$launch_initial_start_time"; then
    echo "interrupted tunnel launch did not converge to a durable record or stopped child" >&2
    return 1
  fi
}

launch_cleanup_on_exit() {
  local status=$?
  trap - EXIT INT TERM
  if [[ $launch_active == true ]] && ! cleanup_failed_launch; then
    echo "failed to converge the interrupted API tunnel launch; preserving its PID record" >&2
    status=1
  fi
  exit "$status"
}

stop_tunnel() {
  local pid expected_start_time record_token
  if [[ -e $pid_file ]]; then
    read -r pid expected_start_time record_token < <(read_supervisor_record) || {
      echo "refusing to trust a malformed API tunnel PID file" >&2
      return 1
    }
    if [[ $record_token != "$instance_token" ]]; then
      # PID namespaces are reused between phased runner containers. A record
      # from another instance cannot identify a process in this container.
      rm -f "$pid_file" "$socket"
    elif supervisor_identity "$pid" "$expected_start_time"; then
      terminate_supervisor "$pid" "$expected_start_time" || return 1
    elif same_process_instance "$pid" "$expected_start_time"; then
      echo "refusing to signal a PID that is not the expected API tunnel supervisor" >&2
      return 1
    elif orphaned_tunnel_group_identity "$pid"; then
      terminate_orphaned_tunnel_group "$pid" || return 1
    elif process_group_is_running "$pid"; then
      echo "refusing to signal an unverified API tunnel process group" >&2
      return 1
    fi
  fi
  if [[ -S $socket ]]; then
    legacy_control exit || true
  fi
  rm -f "$pid_file" "$socket"
}

start_tunnel() {
  local pid record_pid expected_start_time record_token state process_group actual_start_time
  if [[ -e $pid_file ]]; then
    read -r pid expected_start_time record_token < <(read_supervisor_record) || {
      echo "refusing to trust a malformed API tunnel PID file" >&2
      return 1
    }
    if [[ $record_token != "$instance_token" ]]; then
      rm -f "$pid_file" "$socket"
    elif supervisor_identity "$pid" "$expected_start_time"; then
      for _ in {1..60}; do
        tunnel_healthy "$pid" "$expected_start_time" && return 0
        sleep 0.5
      done
      stop_tunnel || return 1
    elif same_process_instance "$pid" "$expected_start_time"; then
      echo "refusing to replace an unverified API tunnel process" >&2
      return 1
    elif orphaned_tunnel_group_identity "$pid"; then
      terminate_orphaned_tunnel_group "$pid" || return 1
      rm -f "$pid_file" "$socket"
    elif process_group_is_running "$pid"; then
      echo "refusing to replace an unverified API tunnel process group" >&2
      return 1
    else
      rm -f "$pid_file" "$socket"
    fi
  elif [[ -S $socket ]]; then
    legacy_control exit || true
    rm -f "$socket"
  fi

  : >"$log_file"
  chmod 0600 "$log_file"
  launch_active=true
  launch_pid=
  launch_initial_start_time=
  launch_owner_pid=$BASHPID
  read -r state process_group launch_owner_start_time < <(read_process_metadata "$launch_owner_pid")
  trap launch_cleanup_on_exit EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  (
    trap - EXIT INT TERM
    child_pid=$BASHPID
    read -r child_state child_group child_start_time < <(read_process_metadata "$child_pid")
    [[ $child_group != "$child_pid" ]] || {
      echo "refusing API tunnel launch from an existing process-group leader" >&2
      exit 1
    }
    child_temporary=$pid_file.$child_pid.tmp
    printf '%s %s %s\n' "$child_pid" "$child_start_time" "$instance_token" >"$child_temporary"
    chmod 0600 "$child_temporary"
    mv -f "$child_temporary" "$pid_file"
    same_process_instance "$launch_owner_pid" "$launch_owner_start_time" || exit 1
    exec env AUTOSSH_GATETIME=0 AUTOSSH_POLL=10 AUTOSSH_FIRST_POLL=10 \
      setsid autossh -M 0 "${tunnel_arguments[@]}"
  ) </dev/null >>"$log_file" 2>&1 &
  pid=$!
  launch_pid=$pid
  for _ in {1..40}; do
    if read -r state process_group actual_start_time < <(read_process_metadata "$pid"); then
      launch_initial_start_time=$actual_start_time
      break
    fi
    sleep 0.05
  done
  [[ ${launch_initial_start_time:-} =~ ^[1-9][0-9]*$ ]] || {
    echo "API tunnel launch child did not expose a process start time" >&2
    return 1
  }
  for _ in {1..40}; do
    if read -r record_pid expected_start_time record_token < <(read_supervisor_record) &&
       [[ $record_pid == "$pid" && $record_token == "$instance_token" &&
          $expected_start_time == "$launch_initial_start_time" ]]; then
      break
    fi
    sleep 0.05
  done
  [[ ${record_pid:-} == "$pid" && ${record_token:-} == "$instance_token" &&
     ${expected_start_time:-} == "$launch_initial_start_time" ]] || {
    echo "API tunnel launch child did not publish its exact PID record" >&2
    return 1
  }

  for _ in {1..120}; do
    if tunnel_healthy "$pid" "$expected_start_time"; then
      launch_active=false
      trap - EXIT INT TERM
      return 0
    fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.25
  done
  echo "autossh API tunnel did not become ready" >&2
  return 1
}

case "$action" in
  start)
    start_tunnel
    ;;
  check)
    read -r pid expected_start_time record_token < <(read_supervisor_record)
    [[ $record_token == "$instance_token" ]] &&
      tunnel_healthy "$pid" "$expected_start_time"
    ;;
  stop)
    stop_tunnel
    ;;
  *)
    echo "unsupported tunnel action: $action" >&2
    exit 2
    ;;
esac
