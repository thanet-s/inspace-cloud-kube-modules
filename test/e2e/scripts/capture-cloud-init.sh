#!/usr/bin/env bash
# Best-effort evidence for a host's first boot. While the E2E waits for
# cloud-init, keep copying its status and output log into the run's state
# directory, so the last good view survives when the host becomes unreachable
# mid-boot (a bad InSpace floating IPv4 dropped the bastion this way and left
# no logs to inspect). It never fails the run: every path exits 0.
set -u

usage() {
  cat >&2 <<'EOF'
usage: capture-cloud-init.sh --ssh-config PATH --host ALIAS --output PATH --stop-file PATH
                             [--interval SECONDS] [--max-misses N] [--deadline SECONDS]
EOF
  exit 0
}

ssh_config= host= output= stop_file=
interval=20 max_misses=30 deadline=3000
while (($#)); do
  case "$1" in
    --ssh-config) ssh_config=${2:-}; shift 2 ;;
    --host) host=${2:-}; shift 2 ;;
    --output) output=${2:-}; shift 2 ;;
    --stop-file) stop_file=${2:-}; shift 2 ;;
    --interval) interval=${2:-}; shift 2 ;;
    --max-misses) max_misses=${2:-}; shift 2 ;;
    --deadline) deadline=${2:-}; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n $ssh_config && -n $host && -n $output && -n $stop_file ]] || usage

umask 077
mkdir -p "$(dirname "$output")" || exit 0
timeline=$output.timeline
end=$((SECONDS + deadline))
misses=0
while ((SECONDS < end)) && [[ ! -e $stop_file ]]; do
  now=$(date -u +%FT%TZ)
  if snapshot=$(timeout 40 ssh -F "$ssh_config" -o ConnectTimeout=10 -o BatchMode=yes "$host" \
    'sudo cloud-init status --long 2>&1; echo "---- cloud-init-output.log"; sudo tail -n 200 /var/log/cloud-init-output.log 2>&1' 2>&1); then
    misses=0
    printf '%s snapshot of %s\n%s\n' "$now" "$host" "$snapshot" >"$output.tmp" && mv -f "$output.tmp" "$output"
    status=$(awk '/^status:/ { print $2; exit }' <<<"$snapshot")
    printf '%s status=%s\n' "$now" "${status:-unknown}" >>"$timeline"
    case $status in done | error | degraded) break ;; esac
  else
    misses=$((misses + 1))
    printf '%s ssh-failed (%d)\n' "$now" "$misses" >>"$timeline"
    ((misses >= max_misses)) && break
  fi
  sleep "$interval"
done
exit 0
