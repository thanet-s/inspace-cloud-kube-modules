#!/bin/bash
set -Eeuo pipefail

version=${1:?usage: verify-release-source.sh VERSION}
repository=https://github.com/thanet-s/inspace-cloud-kube-modules.git

if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "version must be an exact published SemVer without a v prefix" >&2
  exit 2
fi

tag=v$version
tag_ref=refs/tags/$tag
local_type=$(git cat-file -t "$tag_ref") || {
  echo "cannot read local release tag $tag" >&2
  exit 1
}
[[ $local_type == tag ]] || {
  echo "live E2E requires the local annotated release tag $tag" >&2
  exit 1
}
local_tag_object=$(git rev-parse --verify "$tag_ref")
local_commit=$(git rev-parse --verify "$tag_ref^{commit}")
head_commit=$(git rev-parse --verify HEAD)
[[ $head_commit == "$local_commit" ]] || {
  echo "live E2E checkout $head_commit does not equal $tag commit $local_commit" >&2
  exit 1
}

status=
if ! status=$(git status --porcelain=v1 --untracked-files=all); then
  echo "cannot prove that the live E2E checkout is clean" >&2
  exit 1
fi
[[ -z $status ]] || {
  echo "live E2E requires a clean checkout of $tag" >&2
  exit 1
}

remote_output=
if ! remote_output=$(git ls-remote "$repository" "$tag_ref" "$tag_ref^{}"); then
  echo "cannot read canonical GitHub tag $tag" >&2
  exit 1
fi

remote_tag_object=
remote_commit=
remote_count=0
while IFS=$'\t' read -r object ref; do
  [[ -n $object && -n $ref ]] || {
    echo "canonical GitHub returned a malformed tag record for $tag" >&2
    exit 1
  }
  [[ $object =~ ^[0-9a-f]{40}$ ]] || {
    echo "canonical GitHub returned an invalid object ID for $tag" >&2
    exit 1
  }
  case "$ref" in
    "$tag_ref")
      [[ -z $remote_tag_object ]] || {
        echo "canonical GitHub returned duplicate tag objects for $tag" >&2
        exit 1
      }
      remote_tag_object=$object
      ;;
    "$tag_ref^{}")
      [[ -z $remote_commit ]] || {
        echo "canonical GitHub returned duplicate peeled commits for $tag" >&2
        exit 1
      }
      remote_commit=$object
      ;;
    *)
      echo "canonical GitHub returned an unexpected ref for $tag: $ref" >&2
      exit 1
      ;;
  esac
  remote_count=$((remote_count + 1))
done <<<"$remote_output"

[[ $remote_count == 2 && -n $remote_tag_object && -n $remote_commit ]] || {
  echo "canonical GitHub must expose one annotated tag object and one peeled commit for $tag" >&2
  exit 1
}
[[ $local_tag_object == "$remote_tag_object" && $local_commit == "$remote_commit" ]] || {
  echo "local tag $tag does not exactly match the canonical GitHub tag object and peeled commit" >&2
  exit 1
}

printf '%s\n' "$local_commit"
