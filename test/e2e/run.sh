#!/usr/bin/env bash
set -Eeuo pipefail

# This host-side entrypoint is deliberately only a Docker/Git launcher. All
# credential checks, provisioning, Ansible, SSH, Kubernetes work, and cleanup
# execute inside the release-bound E2E runner container.
script_dir=${BASH_SOURCE[0]%/*}
[[ $script_dir != "${BASH_SOURCE[0]}" ]] || script_dir=.
workspace=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
cd "$workspace"

command -v docker >/dev/null 2>&1 || {
  echo "Docker is required to run the E2E controller" >&2
  exit 2
}

env_file=${INSPACE_E2E_ENV_FILE:-$workspace/.env}
ssh_private_key=${INSPACE_E2E_SSH_PRIVATE_KEY:-$HOME/.ssh/id_rsa}
ssh_public_key=${INSPACE_E2E_SSH_PUBLIC_KEY:-$HOME/.ssh/id_rsa.pub}
state_volume=${INSPACE_E2E_STATE_VOLUME:-inspace-cloud-rke2-e2e-state}
runner_image_base=${INSPACE_E2E_RUNNER_IMAGE:-inspace-cloud-rke2-e2e:local}
runner_platform=${INSPACE_E2E_RUNNER_PLATFORM:-linux/amd64}
phase=${1:-all}

[[ $# -le 1 ]] || { echo "usage: test/e2e/run.sh [all|init|test|shell|destroy]" >&2; exit 2; }
case "$phase" in
  all | init | test | shell | destroy) ;;
  *) echo "unsupported E2E phase: $phase" >&2; exit 2 ;;
esac

[[ $runner_platform == linux/amd64 ]] || {
  echo "INSPACE_E2E_RUNNER_PLATFORM must be linux/amd64 while InSpace is x86-only" >&2
  exit 2
}
[[ ${#state_volume} -le 128 && $state_volume =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || {
  echo "INSPACE_E2E_STATE_VOLUME must be a bounded Docker volume name" >&2
  exit 2
}
[[ ${#runner_image_base} -le 200 &&
   $runner_image_base =~ ^[A-Za-z0-9][A-Za-z0-9._/:@-]*$ &&
   $runner_image_base != *@* &&
   $runner_image_base != */ &&
   $runner_image_base != *: ]] || {
  echo "INSPACE_E2E_RUNNER_IMAGE must be a bounded tagged Docker image name without a digest" >&2
  exit 2
}
for path_value in "$env_file" "$ssh_private_key" "$ssh_public_key"; do
  [[ $path_value != *','* && $path_value != *$'\n'* && $path_value == /* ]] || {
    echo "E2E bind-mount paths must be absolute and contain no comma or newline" >&2
    exit 2
  }
done

[[ -f "$env_file" && ! -L "$env_file" && -r "$env_file" ]] || {
  echo "E2E environment file is not a readable regular file: $env_file" >&2
  exit 2
}
[[ -f "$ssh_private_key" && ! -L "$ssh_private_key" && -r "$ssh_private_key" ]] || {
  echo "SSH private key is not a readable regular file: $ssh_private_key" >&2
  exit 2
}
[[ -f "$ssh_public_key" && ! -L "$ssh_public_key" && -r "$ssh_public_key" ]] || {
  echo "SSH public key is not a readable regular file: $ssh_public_key" >&2
  exit 2
}
[[ -n ${CONFIRM_INSPACE_CLUSTER_E2E:-} ]] || {
  echo "CONFIRM_INSPACE_CLUSTER_E2E must be exported" >&2
  exit 2
}
[[ -n ${INSPACE_E2E_VERSION:-} ]] || {
  echo "INSPACE_E2E_VERSION must be exported" >&2
  exit 2
}
[[ $INSPACE_E2E_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || {
  echo "INSPACE_E2E_VERSION must be an exact published SemVer tag" >&2
  exit 2
}

runner_image=${runner_image_base}-${INSPACE_E2E_VERSION}
verifier_image=${runner_image_base}-release-verifier-${INSPACE_E2E_VERSION}
release_revision=
if [[ $phase != destroy ]]; then
  command -v git >/dev/null 2>&1 || {
    echo "Git is required to bind live E2E source to the published candidate" >&2
    exit 2
  }
  release_revision=$(/bin/bash test/e2e/scripts/verify-release-source.sh "$INSPACE_E2E_VERSION") || {
    echo "live E2E could not bind the checkout to the canonical GitHub candidate" >&2
    exit 2
  }
fi

docker volume inspect "$state_volume" >/dev/null 2>&1 ||
  docker volume create "$state_volume" >/dev/null

release_version=
ccm_release_digest=
ccm_platform_digest=
csi_release_digest=
csi_platform_digest=
karpenter_release_digest=
karpenter_platform_digest=
crds_chart_digest=
modules_chart_digest=
artifact_container_root=

load_release_environment() {
  local input=$1 line name value count=0
  release_version=
  release_revision=
  ccm_release_digest=
  ccm_platform_digest=
  csi_release_digest=
  csi_platform_digest=
  karpenter_release_digest=
  karpenter_platform_digest=
  crds_chart_digest=
  modules_chart_digest=
  while IFS= read -r line; do
    [[ $line == *=* ]] || return 2
    name=${line%%=*}
    value=${line#*=}
    case "$name" in
      INSPACE_E2E_RELEASE_VERSION) [[ -z $release_version ]] || return 2; release_version=$value ;;
      INSPACE_E2E_RELEASE_REVISION) [[ -z $release_revision ]] || return 2; release_revision=$value ;;
      INSPACE_E2E_CCM_RELEASE_DIGEST) [[ -z $ccm_release_digest ]] || return 2; ccm_release_digest=$value ;;
      INSPACE_E2E_CCM_PLATFORM_DIGEST) [[ -z $ccm_platform_digest ]] || return 2; ccm_platform_digest=$value ;;
      INSPACE_E2E_CSI_RELEASE_DIGEST) [[ -z $csi_release_digest ]] || return 2; csi_release_digest=$value ;;
      INSPACE_E2E_CSI_PLATFORM_DIGEST) [[ -z $csi_platform_digest ]] || return 2; csi_platform_digest=$value ;;
      INSPACE_E2E_KARPENTER_RELEASE_DIGEST) [[ -z $karpenter_release_digest ]] || return 2; karpenter_release_digest=$value ;;
      INSPACE_E2E_KARPENTER_PLATFORM_DIGEST) [[ -z $karpenter_platform_digest ]] || return 2; karpenter_platform_digest=$value ;;
      INSPACE_E2E_CRDS_CHART_DIGEST) [[ -z $crds_chart_digest ]] || return 2; crds_chart_digest=$value ;;
      INSPACE_E2E_MODULES_CHART_DIGEST) [[ -z $modules_chart_digest ]] || return 2; modules_chart_digest=$value ;;
      *) return 2 ;;
    esac
    count=$((count + 1))
  done <<<"$input"
  [[ $count == 10 &&
     $release_version == "$INSPACE_E2E_VERSION" &&
     $release_revision =~ ^[0-9a-f]{40}$ ]] || return 2
  local digest
  for digest in \
    "$ccm_release_digest" "$ccm_platform_digest" \
    "$csi_release_digest" "$csi_platform_digest" \
    "$karpenter_release_digest" "$karpenter_platform_digest" \
    "$crds_chart_digest" "$modules_chart_digest"; do
    [[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || return 2
  done
}

runner_build_arguments=()
set_runner_build_arguments() {
  runner_build_arguments=(
    --build-arg "E2E_RELEASE_VERSION=$release_version"
    --build-arg "E2E_RELEASE_REVISION=$release_revision"
    --build-arg "E2E_CCM_RELEASE_DIGEST=$ccm_release_digest"
    --build-arg "E2E_CCM_PLATFORM_DIGEST=$ccm_platform_digest"
    --build-arg "E2E_CSI_RELEASE_DIGEST=$csi_release_digest"
    --build-arg "E2E_CSI_PLATFORM_DIGEST=$csi_platform_digest"
    --build-arg "E2E_KARPENTER_RELEASE_DIGEST=$karpenter_release_digest"
    --build-arg "E2E_KARPENTER_PLATFORM_DIGEST=$karpenter_platform_digest"
    --build-arg "E2E_CRDS_CHART_DIGEST=$crds_chart_digest"
    --build-arg "E2E_MODULES_CHART_DIGEST=$modules_chart_digest"
  )
}

build_published_runner() {
  set_runner_build_arguments
  docker build \
    --platform "$runner_platform" \
    --file test/e2e/Dockerfile \
    --target published-live \
    --build-arg "CONTROLLER_IMAGE=ghcr.io/thanet-s/inspace-cloud-controller-manager@$ccm_platform_digest" \
    "${runner_build_arguments[@]}" \
    --tag "$runner_image" \
    .
}

runner_binding() {
  docker image inspect \
    --format '{{ index .Config.Labels "io.inspace.e2e.release-version" }}|{{ index .Config.Labels "io.inspace.e2e.release-revision" }}|{{ index .Config.Labels "io.inspace.e2e.controller-platform-digest" }}|{{ index .Config.Labels "io.inspace.e2e.crds-chart-digest" }}|{{ index .Config.Labels "io.inspace.e2e.modules-chart-digest" }}' \
    "$runner_image"
}

if [[ $phase == destroy ]]; then
  docker image inspect "$runner_image" >/dev/null 2>&1 || {
    echo "destroy requires the preserved exact release runner $runner_image; refusing a newer or unbound cleanup harness" >&2
    exit 2
  }
  release_environment=$(docker run --rm \
    --platform "$runner_platform" \
    --entrypoint /opt/e2e/scripts/verify-release-images.py \
    --mount "type=volume,src=$state_volume,dst=/state,readonly" \
    "$runner_image" \
    --persisted-state-root /state \
    --run-id "${INSPACE_E2E_RUN_ID:-}" \
    --output /tmp/release-images.json \
    --format env \
    --expect-environment-prefix INSPACE_E2E_BUILT_) || {
      echo "destroy could not validate the persisted exact release manifest with its preserved runner" >&2
      exit 2
    }
  load_release_environment "$release_environment" || {
    echo "persisted release verifier returned an incomplete or malformed binding" >&2
    exit 2
  }
  expected_binding="$release_version|$release_revision|$ccm_platform_digest|$crds_chart_digest|$modules_chart_digest"
  actual_binding=$(runner_binding) || {
    echo "cannot inspect the preserved destroy runner binding" >&2
    exit 2
  }
  [[ $actual_binding == "$expected_binding" ]] || {
    echo "preserved destroy runner does not match the persisted release artifact set" >&2
    exit 2
  }
else
  docker build \
    --platform "$runner_platform" \
    --file test/e2e/Dockerfile \
    --target base \
    --tag "$verifier_image" \
    .
  artifact_container_root="/state/release-preflight/v$INSPACE_E2E_VERSION-$release_revision"
  release_environment=$(docker run --rm \
    --platform "$runner_platform" \
    --entrypoint /opt/e2e/scripts/verify-release-images.py \
    --mount "type=volume,src=$state_volume,dst=/state" \
    "$verifier_image" \
    --version "$INSPACE_E2E_VERSION" \
    --revision "$release_revision" \
    --artifact-dir "$artifact_container_root" \
    --output "$artifact_container_root/release-images.json" \
    --format env)
  load_release_environment "$release_environment" || {
    echo "release artifact verifier returned an incomplete or malformed binding" >&2
    exit 2
  }
  build_published_runner
  expected_binding="$release_version|$release_revision|$ccm_platform_digest|$crds_chart_digest|$modules_chart_digest"
  actual_binding=$(runner_binding) || {
    echo "cannot inspect the newly built release runner binding" >&2
    exit 2
  }
  [[ $actual_binding == "$expected_binding" ]] || {
    echo "newly built release runner does not match the verified artifact set" >&2
    exit 2
  }
fi

interactive_arg=
if [[ $phase == shell ]]; then
  interactive_arg=-it
fi
docker run --rm ${interactive_arg:+"$interactive_arg"} \
  --platform "$runner_platform" \
  --env "CONFIRM_INSPACE_CLUSTER_E2E=$CONFIRM_INSPACE_CLUSTER_E2E" \
  --env "INSPACE_E2E_VERSION=$INSPACE_E2E_VERSION" \
  --env "INSPACE_E2E_RELEASE_REVISION=$release_revision" \
  --env "INSPACE_E2E_RELEASE_ARTIFACT_ROOT=$artifact_container_root" \
  --env "INSPACE_E2E_KEEP_RESOURCES=${INSPACE_E2E_KEEP_RESOURCES:-false}" \
  --env "INSPACE_E2E_RUN_ID=${INSPACE_E2E_RUN_ID:-}" \
  --env "INSPACE_E2E_RECOVER_RETAINED=${INSPACE_E2E_RECOVER_RETAINED:-false}" \
  --env "INSPACE_E2E_CCM_RELEASE_DIGEST=$ccm_release_digest" \
  --env "INSPACE_E2E_CCM_PLATFORM_DIGEST=$ccm_platform_digest" \
  --env "INSPACE_E2E_CSI_RELEASE_DIGEST=$csi_release_digest" \
  --env "INSPACE_E2E_CSI_PLATFORM_DIGEST=$csi_platform_digest" \
  --env "INSPACE_E2E_KARPENTER_RELEASE_DIGEST=$karpenter_release_digest" \
  --env "INSPACE_E2E_KARPENTER_PLATFORM_DIGEST=$karpenter_platform_digest" \
  --env "INSPACE_E2E_CRDS_CHART_DIGEST=$crds_chart_digest" \
  --env "INSPACE_E2E_MODULES_CHART_DIGEST=$modules_chart_digest" \
  --mount "type=bind,src=$env_file,dst=/run/config/workspace.env,readonly" \
  --mount "type=bind,src=$ssh_private_key,dst=/run/secrets/e2e_ssh_key,readonly" \
  --mount "type=bind,src=$ssh_public_key,dst=/run/secrets/e2e_ssh_key.pub,readonly" \
  --mount "type=volume,src=$state_volume,dst=/state" \
  "$runner_image" \
  "$phase"
