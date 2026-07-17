#!/usr/bin/env bash
set -Eeuo pipefail

tag=${1:?usage: verify-release-tag.sh TAG [MAIN_REF] [EXPECTED_COMMIT]}
main_ref=${2:-refs/remotes/origin/main}
expected_commit=${3:-}

if [[ ! $tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "release tag must be SemVer prefixed with v and without build metadata: $tag" >&2
  exit 2
fi
tag_ref="refs/tags/$tag"
[[ $(git cat-file -t "$tag_ref" 2>/dev/null || true) == tag ]] || {
  echo "release tag must be an annotated tag: $tag" >&2
  exit 1
}
tag_commit=$(git rev-parse --verify "$tag_ref^{commit}")
head_commit=$(git rev-parse --verify HEAD)
if [[ -n $expected_commit ]]; then
  [[ $expected_commit =~ ^[0-9a-f]{40}$ ]] || {
    echo "expected event commit must be a lowercase 40-hex object ID" >&2
    exit 2
  }
  if [[ $tag_commit != "$expected_commit" || $head_commit != "$expected_commit" ]]; then
    echo "release tag, checked-out HEAD, and expected event commit must be identical" >&2
    exit 1
  fi
fi
git rev-parse --verify "$main_ref^{commit}" >/dev/null
if ! git merge-base --is-ancestor "$tag_commit" "$main_ref"; then
  echo "release tag target must be reachable from $main_ref" >&2
  exit 1
fi

if [[ $tag == *-* ]]; then
  exit 0
fi

base=$tag
rc_like_tags=()
while IFS= read -r candidate; do
  [[ -z $candidate ]] || rc_like_tags[${#rc_like_tags[@]}]=$candidate
done < <(git for-each-ref --format='%(refname:strip=2)' "refs/tags/$base-rc*" | LC_ALL=C sort)
if (( ${#rc_like_tags[@]} == 0 )); then
  echo "stable release $tag requires at least one same-base vX.Y.Z-rc.N tag" >&2
  exit 1
fi

highest_number=
highest_tag=
for candidate in "${rc_like_tags[@]}"; do
  if [[ ! $candidate =~ ^${base//./\\.}-rc\.(0|[1-9][0-9]*)$ ]]; then
    echo "ambiguous same-base RC tag is not canonical vX.Y.Z-rc.N: $candidate" >&2
    exit 1
  fi
  number=${BASH_REMATCH[1]}
  if [[ -z $highest_number ]] ||
    (( ${#number} > ${#highest_number} )) ||
    { (( ${#number} == ${#highest_number} )) && [[ $number > $highest_number ]]; }; then
    highest_number=$number
    highest_tag=$candidate
  elif [[ $number == "$highest_number" ]]; then
    echo "ambiguous highest same-base release candidate: $highest_tag and $candidate" >&2
    exit 1
  fi
done

[[ -n $highest_tag ]] || {
  echo "stable release $tag has no canonical same-base release candidate" >&2
  exit 1
}
[[ $(git cat-file -t "refs/tags/$highest_tag" 2>/dev/null || true) == tag ]] || {
  echo "release candidate must be an annotated tag: $highest_tag" >&2
  exit 1
}
rc_commit=$(git rev-parse --verify "refs/tags/$highest_tag^{commit}")
if [[ $tag_commit != "$rc_commit" ]]; then
  echo "stable release $tag targets $tag_commit, but newest $highest_tag targets $rc_commit" >&2
  exit 1
fi
printf 'stable release %s exactly promotes %s at %s\n' "$tag" "$highest_tag" "$tag_commit"
