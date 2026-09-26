#!/bin/sh
# Adds the entries of one controller-printed refresh manifest
# (inspace-cluster-controller --print-bootstrap-cache-refresh) to this
# bastion's bootstrap cache before `deploy update` upgrades RKE2 or the charts.
#
# It only adds. A tag that already holds another digest, or a release archive
# with another checksum, is never overwritten: the refresh fails closed before
# any mutation. Images are pulled with the same skopeo options as the
# build-time seed, but by the linux/amd64 manifest digest resolved from the
# (digest-verified) source, and every entry is read back through the private
# TLS front. The registry is writable only on 127.0.0.1 while images are
# imported and is always restored to read-only; NGINX stays GET/HEAD-only.
set -eu

tab=$(printf '\t')
fail() {
  echo "bootstrap cache refresh: $*" >&2
  exit 1
}
[ "$#" -eq 2 ] || fail "usage: refresh-bootstrap-cache.sh MANIFEST cache.<cluster>.inspace.internal:8443"
manifest=$1
front=$2
printf '%s\n' "$front" | grep -Eqx 'cache\.[a-z0-9]([a-z0-9-]{0,53}[a-z0-9])?\.inspace\.internal:8443' ||
  fail "cache endpoint $front is not cache.<cluster>.inspace.internal:8443"
[ -s "$manifest" ] || fail "refresh manifest $manifest is empty"
if grep -Evx "rke2${tab}v[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?\+rke2r[0-9]+${tab}[0-9a-f]{64}|image${tab}docker://[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+(:[A-Za-z0-9._-]+|@sha256:[0-9a-f]{64})${tab}[a-z0-9._/-]+:[A-Za-z0-9._-]+" \
  "$manifest" >/dev/null; then
  fail "refresh manifest $manifest has a malformed line"
fi
[ "$(grep -c "^rke2${tab}" "$manifest" || true)" -le 1 ] || fail "refresh manifest lists more than one RKE2 release"
grep -q "^image${tab}" "$manifest" || fail "refresh manifest lists no images"
[ -z "$(cut -f3 "$manifest" | sort | uniq -d)" ] || fail "refresh manifest lists a cache target twice"

# INSPACE_CACHE_REFRESH_TEST_ROOT relocates the bastion paths for the offline
# tests only; sudo never passes it through.
root=${INSPACE_CACHE_REFRESH_TEST_ROOT:-}
cache_root="$root/var/lib/inspace/bootstrap-cache"
ca_file="$root/etc/inspace-cache/tls/ca.crt"
compose_dir="$root/opt/inspace-cache"
maintenance_script="$root/usr/local/sbin/inspace-cache-maintain"
local_registry=http://127.0.0.1:5000
manifest_accept='application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json'
deadline=$(( $(date +%s) + 2400 ))

for command in curl docker findmnt flock python3 skopeo; do
  command -v "$command" >/dev/null || fail "$command is not installed on the bastion"
done
test "$(findmnt -n -o TARGET "$cache_root")" = "$cache_root" || fail "$cache_root is not mounted"
[ -f "$cache_root/state/ready" ] || fail "the bootstrap cache is not ready; inspect inspace-cache.service on the bastion"
exec 9>"$cache_root/locks-seed"
flock -w 600 9 || fail "another cache seed or refresh still holds $cache_root/locks-seed"

work=$(mktemp -d)
writable=false
# Restoring read-only has its own bound so it still runs after the refresh
# deadline has expired.
restore_read_only() {
  if ! (cd "$compose_dir" && timeout --kill-after=30s 300s env REGISTRY_READONLY=true \
    docker compose up -d --wait --force-recreate registry nginx </dev/null); then
    echo "bootstrap cache refresh: could not restore the read-only registry; run systemctl restart inspace-cache.service on the bastion" >&2
    return 1
  fi
  writable=false
}
cleanup() {
  status=$?
  if [ "$writable" = true ]; then
    restore_read_only || status=1
  fi
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

bounded() {
  left=$(( deadline - $(date +%s) ))
  [ "$left" -gt 0 ] || fail "exceeded its 40-minute deadline"
  timeout --kill-after=30s "${left}s" "$@"
}
ensure_capacity() {
  available="$(df --output=avail -B1 "$cache_root" | tail -1 | tr -d ' ')"
  [ "$available" -ge 1000000000 ] || fail "the bootstrap cache has less than 1 GB free"
}

# registry_digest BASE TARGET [CURL-OPTION...] prints the digest TARGET holds,
# or nothing when the registry reports it absent.
registry_digest() {
  base=$1
  target=$2
  shift 2
  status=$(bounded curl --silent --show-error --head --connect-timeout 10 --max-time 60 "$@" \
    --header "Accept: $manifest_accept" --dump-header "$work/headers" --output /dev/null \
    --write-out '%{http_code}' "$base/v2/${target%:*}/manifests/${target##*:}" </dev/null) ||
    fail "cannot read $target from $base"
  case "$status" in
    404) ;;
    200)
      digest=$(awk 'tolower($1) == "docker-content-digest:" { sub(/\r$/, "", $2); print $2 }' "$work/headers")
      printf '%s\n' "$digest" | grep -Eqx 'sha256:[0-9a-f]{64}' || fail "$base returned no digest for $target"
      printf '%s\n' "$digest"
      ;;
    *) fail "$base answered HTTP $status for $target" ;;
  esac
}

# platform_digest SOURCE prints the linux/amd64 manifest digest SOURCE names.
# A digest-pinned source must return exactly the pinned bytes.
platform_digest() {
  bounded skopeo inspect --retry-times 8 --raw "$1" >"$work/raw" </dev/null || fail "cannot fetch $1"
  python3 - "$work/raw" "$1" <<'PY' || fail "cannot resolve a linux/amd64 manifest for $1"
import hashlib
import json
import re
import sys

path, reference = sys.argv[1], sys.argv[2]
with open(path, "rb") as handle:
    raw = handle.read()
own = "sha256:" + hashlib.sha256(raw).hexdigest()
if "@" in reference and reference.rsplit("@", 1)[1] != own:
    sys.exit(f"{reference} returned a manifest whose digest is {own}")
document = json.loads(raw)
if "manifests" not in document:
    print(own)
    sys.exit(0)
matches = [
    entry.get("digest", "")
    for entry in document["manifests"]
    if entry.get("platform", {}).get("os") == "linux"
    and entry.get("platform", {}).get("architecture") == "amd64"
    and entry.get("platform", {}).get("variant", "") in ("", "v1")
]
if len(matches) != 1 or not re.fullmatch(r"sha256:[0-9a-f]{64}", matches[0]):
    sys.exit(f"{reference} lists {len(matches)} linux/amd64 manifests")
print(matches[0])
PY
}

# Plan: resolve every entry and compare it with the cache before any change.
changed=false
: >"$work/plan"
: >"$work/missing"
while IFS="$tab" read -r kind source target; do
  [ "$kind" = image ] || continue
  expected=$(platform_digest "$source")
  cached=$(registry_digest "$local_registry" "$target")
  if [ -z "$cached" ]; then
    case "$source" in
      *@*) repository=${source%@*} ;;
      *) repository=${source%:*} ;;
    esac
    printf '%s\t%s\t%s\n' "$repository@$expected" "$target" "$expected" >>"$work/missing"
  elif [ "$cached" != "$expected" ]; then
    fail "cache tag $target holds $cached but this release needs $expected; refusing to overwrite it"
  fi
  printf '%s\t%s\n' "$target" "$expected" >>"$work/plan"
done <"$manifest"

rke2_version=$(awk -F "$tab" '$1 == "rke2" { print $2 }' "$manifest")
rke2_sha=$(awk -F "$tab" '$1 == "rke2" { print $3 }' "$manifest")
fetch_archive=false
if [ -n "$rke2_version" ]; then
  artifact_dir="$cache_root/artifacts/rke2/$rke2_version"
  if [ -e "$artifact_dir/rke2.linux-amd64.tar.gz" ]; then
    cached_sha=$(sha256sum "$artifact_dir/rke2.linux-amd64.tar.gz" | awk '{print $1}')
    [ "$cached_sha" = "$rke2_sha" ] ||
      fail "cached RKE2 $rke2_version archive has sha256 $cached_sha, not $rke2_sha; refusing to overwrite it"
  else
    fetch_archive=true
  fi
  if [ -e "$artifact_dir/sha256sum-amd64.txt" ]; then
    listed=$(awk '$2 == "rke2.linux-amd64.tar.gz" || $2 == "./rke2.linux-amd64.tar.gz" { print $1; exit }' "$artifact_dir/sha256sum-amd64.txt")
    [ "$listed" = "$rke2_sha" ] ||
      fail "cached RKE2 $rke2_version checksum list does not list $rke2_sha; refusing to overwrite it"
  else
    fetch_archive=true
  fi
fi

# Earlier releases aged out every RKE2 release but the bootstrap one after 30
# days; install the maintenance contract that keeps refreshed releases.
cat >"$work/inspace-cache-maintain" <<'MAINTAIN'
#!/bin/sh
set -eu
cache_root=/var/lib/inspace/bootstrap-cache
test "$(findmnt -n -o TARGET "$cache_root")" = "$cache_root"
docker container prune --force --filter until=720h >/dev/null
docker image prune --force --filter until=720h >/dev/null
available="$(df --output=avail -B1 "$cache_root" | tail -1 | tr -d ' ')"
if [ "$available" -lt 1000000000 ]; then
  rm -f "$cache_root/state/ready"
  echo "bootstrap cache has less than 1 GB free" >&2
  exit 1
fi
MAINTAIN
if ! cmp -s "$work/inspace-cache-maintain" "$maintenance_script"; then
  install -m 0700 "$work/inspace-cache-maintain" "$maintenance_script.tmp"
  mv -f "$maintenance_script.tmp" "$maintenance_script"
  changed=true
fi

if [ "$fetch_archive" = true ]; then
  ensure_capacity
  release_base="https://github.com/rancher/rke2/releases/download/$(printf '%s' "$rke2_version" | sed 's/+/%2B/g')"
  for asset in rke2.linux-amd64.tar.gz sha256sum-amd64.txt; do
    bounded curl --fail --location --silent --show-error --connect-timeout 15 --max-time 600 --retry 8 --retry-all-errors \
      --proto '=https' --proto-redir '=https' --output "$work/$asset" "$release_base/$asset" </dev/null ||
      fail "cannot download RKE2 $rke2_version $asset"
  done
  [ "$(sha256sum "$work/rke2.linux-amd64.tar.gz" | awk '{print $1}')" = "$rke2_sha" ] ||
    fail "downloaded RKE2 $rke2_version archive does not match its pinned checksum $rke2_sha"
  listed=$(awk '$2 == "rke2.linux-amd64.tar.gz" || $2 == "./rke2.linux-amd64.tar.gz" { print $1; exit }' "$work/sha256sum-amd64.txt")
  [ "$listed" = "$rke2_sha" ] || fail "RKE2 $rke2_version sha256sum-amd64.txt does not list the pinned checksum $rke2_sha"
  install -d -m 0755 "$artifact_dir"
  for asset in sha256sum-amd64.txt rke2.linux-amd64.tar.gz; do
    if [ ! -e "$artifact_dir/$asset" ]; then
      install -m 0444 "$work/$asset" "$artifact_dir/.$asset.partial"
      mv -f "$artifact_dir/.$asset.partial" "$artifact_dir/$asset"
    fi
  done
  changed=true
fi

if [ -s "$work/missing" ]; then
  writable=true
  attempt=0
  until (cd "$compose_dir" && bounded env REGISTRY_READONLY=false docker compose up -d --wait registry </dev/null); do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 9 ] || fail "cannot start the writable seed registry"
    sleep $((attempt * 5))
  done
  attempt=0
  until bounded curl --fail --silent --show-error "$local_registry/v2/" >/dev/null </dev/null; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 60 ] || fail "the writable seed registry did not become ready"
    sleep 2
  done
  while IFS="$tab" read -r pinned_source target expected; do
    ensure_capacity
    bounded skopeo copy --retry-times 8 --preserve-digests --override-os linux --override-arch amd64 \
      --dest-tls-verify=false "$pinned_source" "docker://127.0.0.1:5000/$target" </dev/null ||
      fail "cannot import $pinned_source as $target"
    [ "$(registry_digest "$local_registry" "$target")" = "$expected" ] ||
      fail "readback of $target does not hold $expected"
  done <"$work/missing"
  restore_read_only || exit 1
  changed=true
fi

# Every entry, old or new, must now be served through the private TLS front,
# and the backing registry must refuse writes again.
while IFS="$tab" read -r target expected; do
  [ "$(registry_digest "https://$front" "$target" --cacert "$ca_file")" = "$expected" ] ||
    fail "the cache front does not serve $target at $expected"
done <"$work/plan"
if [ -n "$rke2_version" ]; then
  bounded curl --fail --silent --show-error --head --cacert "$ca_file" --output /dev/null \
    "https://$front/rke2/$(printf '%s' "$rke2_version" | sed 's/+/%2B/g')/rke2.linux-amd64.tar.gz" </dev/null ||
    fail "the cache front does not serve the RKE2 $rke2_version archive"
fi
probe=$(bounded curl --silent --output /dev/null --write-out '%{http_code}' --request POST \
  "$local_registry/v2/inspace-cache-refresh-probe/blobs/uploads/" </dev/null) || probe=error
[ "$probe" = 405 ] || fail "the cache registry accepted or failed a write probe (HTTP $probe); it must be read-only"

if [ "$changed" = true ]; then
  printf 'changed\n'
else
  printf 'unchanged\n'
fi
