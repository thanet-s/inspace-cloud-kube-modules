#!/usr/bin/env bash
set -Eeuo pipefail

stop_file=${1:?usage: monitor-readyz.sh STOP_FILE READY_FILE MAX_SECONDS}
ready_file=${2:?usage: monitor-readyz.sh STOP_FILE READY_FILE MAX_SECONDS}
maximum=${3:?usage: monitor-readyz.sh STOP_FILE READY_FILE MAX_SECONDS}
[[ $maximum =~ ^[1-9][0-9]*$ ]] || { echo "MAX_SECONDS must be positive" >&2; exit 2; }
deadline=$((SECONDS + maximum))
started=false
while [[ ! -e $stop_file ]]; do
  if (( SECONDS >= deadline )); then
    echo "API continuity monitor exceeded its hard deadline" >&2
    exit 1
  fi
  kubectl --request-timeout=5s get --raw=/readyz >/dev/null
  if [[ $started == false ]]; then
    temporary=$ready_file.$$.tmp
    (umask 077; printf 'ready\n' >"$temporary")
    mv -f "$temporary" "$ready_file"
    started=true
  fi
  sleep 1
done
