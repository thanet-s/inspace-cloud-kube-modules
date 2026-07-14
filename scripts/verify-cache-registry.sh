#!/bin/sh
set -eu

workspace=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cache_source=$workspace/modules/cloud-provider/pkg/bootstrap/cache_cloudinit.go
image_source=$workspace/modules/cloud-provider/pkg/bootstrap/cache.go

image=$(sed -n 's/^[[:space:]]*cacheRegistryImage = "\([^"]*\)"$/\1/p' "$image_source")
case "$image" in
  docker.io/library/registry:3.0.0@sha256:*) ;;
  *) echo "could not resolve the exact pinned cache registry image" >&2; exit 1 ;;
esac

config=$(sed -n '/^const cacheRegistryConfig = `/,/^`$/p' "$cache_source" \
  | sed '1s/^[^`]*`//; $d')
[ -n "$config" ] || { echo "could not extract the rendered cache registry configuration" >&2; exit 1; }
config_base64=$(printf '%s\n' "$config" | base64 | tr -d '\n')

container=
cleanup() {
  if [ -n "$container" ]; then
    docker rm --force --volumes "$container" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

verify_mode() {
  mode=$1
  expected=$2
  container=inspace-cache-registry-contract-$$-$mode
  docker run --detach --name "$container" \
    --entrypoint /bin/sh \
    --env "CONFIG_BASE64=$config_base64" \
    --env "REGISTRY_STORAGE_MAINTENANCE_READONLY={enabled: $mode}" \
    "$image" \
    -c 'printf %s "$CONFIG_BASE64" | base64 -d >/tmp/config.yml; exec /bin/registry serve /tmp/config.yml' \
    >/dev/null

  ready=false
  attempt=0
  while [ "$attempt" -lt 30 ]; do
    if docker exec "$container" wget -q -O /dev/null http://127.0.0.1:5000/v2/; then
      ready=true
      break
    fi
    if [ "$(docker inspect --format '{{.State.Running}}' "$container")" != true ]; then
      docker logs "$container" >&2
      echo "cache registry exited before becoming ready in mode=$mode" >&2
      exit 1
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  [ "$ready" = true ] || { docker logs "$container" >&2; echo "cache registry readiness timed out" >&2; exit 1; }

  response=$(printf 'POST /v2/inspace-contract/blobs/uploads/ HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' \
    | docker exec -i "$container" nc 127.0.0.1 5000)
  status=$(printf '%s\n' "$response" | awk 'NR == 1 { gsub("\\r", "", $2); print $2 }')
  if [ "$status" != "$expected" ]; then
    echo "cache registry mode=$mode returned HTTP $status for upload start, expected $expected" >&2
    exit 1
  fi

  docker rm --force --volumes "$container" >/dev/null
  container=
  printf 'cache registry mode=%s upload-status=%s\n' "$mode" "$status"
}

verify_mode false 202
verify_mode true 405
