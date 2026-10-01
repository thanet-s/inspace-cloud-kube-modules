#!/bin/sh
# One-time reboot of a deploy-created host (control plane or bastion) after the
# first-boot `apt-get upgrade`, so a new kernel or libc takes effect.
#
#   check   print "needed" only when the host never rebooted since cloud-init
#           ran its scripts and has no marker; otherwise print "done".
#   reboot  print the current boot_id, then reboot five seconds later (the
#           delay lets the SSH session that started it exit cleanly).
#   mark    record that the post-upgrade reboot is complete.
#
# `check` is idempotent: after any reboot, the cloud-init scripts semaphore is
# older than this boot, so a re-run of init never reboots a host twice.
set -eu

# INSPACE_POST_UPGRADE_TEST_ROOT relocates the host paths for the offline tests
# only; sudo never passes it through.
root=${INSPACE_POST_UPGRADE_TEST_ROOT:-}
marker="$root/var/lib/inspace/post-upgrade-reboot.done"
semaphore="$root/var/lib/cloud/instance/sem/config_scripts_user"
proc_stat="$root/proc/stat"
boot_id_file="$root/proc/sys/kernel/random/boot_id"

case "${1:-}" in
  check)
    if [ -e "$marker" ] || [ ! -e "$semaphore" ]; then
      printf done
      exit 0
    fi
    boot_time=$(awk '$1 == "btime" { print $2; exit }' "$proc_stat")
    ran_at=$(stat -c %Y "$semaphore")
    if [ -n "$boot_time" ] && [ "$ran_at" -ge "$boot_time" ]; then
      printf needed
    else
      printf done
    fi
    ;;
  reboot)
    cat "$boot_id_file"
    systemd-run --on-active=5 /bin/systemctl reboot >/dev/null 2>&1
    ;;
  mark)
    install -d -m 0755 "$(dirname "$marker")"
    date -u +%Y-%m-%dT%H:%M:%SZ >"$marker"
    sync
    ;;
  *)
    echo "usage: post-upgrade-reboot.sh check|reboot|mark" >&2
    exit 2
    ;;
esac
