#!/bin/sh
# One-time reboot of a deploy-created host (control plane or bastion) after the
# first-boot `apt-get upgrade`, so a new kernel or libc takes effect.
#
#   check   print "needed" only when the OS upgrade left /run/reboot-required
#           and this host has not already been rebooted for it; else "done".
#   reboot  wait for cloud-init to finish, print the current boot_id, then
#           reboot five seconds later (the delay lets the SSH session that
#           started it exit cleanly). A failure to schedule the reboot is
#           reported on stderr and fails the command.
#   mark    record that the post-upgrade reboot is complete.
#
# /run is a tmpfs, so /run/reboot-required exists only while a reboot is
# genuinely pending in the current boot. That alone makes `check` idempotent:
# after the reboot the file is gone and a re-run of init finds nothing to do,
# so no extra "still in the cloud-init boot" guard is needed. The marker only
# stops a second reboot if a later package upgrade raises the flag again.
set -eu

# INSPACE_POST_UPGRADE_TEST_ROOT relocates the host paths for the offline tests
# only; sudo never passes it through.
root=${INSPACE_POST_UPGRADE_TEST_ROOT:-}
marker="$root/var/lib/inspace/post-upgrade-reboot.done"
reboot_required="$root/run/reboot-required"
boot_id_file="$root/proc/sys/kernel/random/boot_id"

case "${1:-}" in
  check)
    if [ ! -e "$marker" ] && [ -e "$reboot_required" ]; then
      printf needed
    else
      printf done
    fi
    ;;
  reboot)
    # cloud-init may still be running its final stage on a host that just
    # finished first boot; a reboot then would cut it off. Its own exit status
    # (an error result) does not matter here, only that it has stopped.
    if command -v cloud-init >/dev/null 2>&1; then
      timeout 1800 cloud-init status --wait >/dev/null 2>&1 || true
    fi
    cat "$boot_id_file"
    systemd-run --on-active=5 /bin/systemctl reboot >&2
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
