#!/bin/sh
set -eu

target_version="$1"
release_base="https://github.com/rancher/rke2/releases/download/${target_version}"

if /usr/local/bin/rke2 --version 2>/dev/null | grep -F -- "rke2 version $target_version" >/dev/null; then
  rm -f /tmp/inspace-upgrade-rke2-server.sh
  printf unchanged
  exit 0
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT INT TERM
attempt=0
until curl --fail --location --silent --show-error --connect-timeout 15 --max-time 300 --retry 3 --retry-all-errors \
      --output "$tmpdir/rke2.linux-amd64.tar.gz" "$release_base/rke2.linux-amd64.tar.gz" && \
      curl --fail --location --silent --show-error --connect-timeout 15 --max-time 300 --retry 3 --retry-all-errors \
      --output "$tmpdir/sha256sum-amd64.txt" "$release_base/sha256sum-amd64.txt"; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then exit 1; fi
  sleep 10
done
expected="$(awk '$2 == "rke2.linux-amd64.tar.gz" || $2 == "./rke2.linux-amd64.tar.gz" {print $1; exit}' "$tmpdir/sha256sum-amd64.txt")"
test -n "$expected"
actual="$(sha256sum "$tmpdir/rke2.linux-amd64.tar.gz" | awk '{print $1}')"
test "$actual" = "$expected"

# The bastion bootstrap cache pins exactly one audited RKE2 release per
# controller build (see modules/cloud-provider/pkg/bootstrap/cache.go), so an
# in-place version upgrade always fetches the new release directly from
# upstream, independent of the cluster's original bootstrap-cache mode.
systemctl stop rke2-server.service
tar --extract --gzip --file "$tmpdir/rke2.linux-amd64.tar.gz" --directory /usr/local
/usr/local/bin/rke2 --version | grep -F -- "rke2 version $target_version" >/dev/null
systemctl daemon-reload
systemctl start --no-block rke2-server.service
attempt=0
until systemctl is-active --quiet rke2-server.service; do
  attempt=$((attempt + 1))
  if systemctl is-failed --quiet rke2-server.service || [ "$attempt" -ge 180 ]; then exit 1; fi
  sleep 5
done

rm -f /tmp/inspace-upgrade-rke2-server.sh
printf changed
