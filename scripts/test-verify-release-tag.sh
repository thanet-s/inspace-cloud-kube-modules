#!/usr/bin/env bash
set -Eeuo pipefail

workspace=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
verifier=$workspace/scripts/verify-release-tag.sh
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT

new_repository() {
  local directory=$1
  git init -q -b main "$directory"
  git -C "$directory" config user.name 'Release Contract Test'
  git -C "$directory" config user.email 'release-contract@example.invalid'
  printf 'one\n' >"$directory/content"
  git -C "$directory" add content
  git -C "$directory" commit -qm one
}

expect_failure() {
  local directory=$1
  local tag=$2
  local expected=${3:-}
  if (cd "$directory" && "$verifier" "$tag" refs/heads/main "$expected" >/dev/null 2>&1); then
    echo "release-tag verifier unexpectedly accepted $tag in $directory" >&2
    exit 1
  fi
}

same_commit=$temporary/same-commit
new_repository "$same_commit"
git -C "$same_commit" tag -am rc.1 v1.2.3-rc.1
git -C "$same_commit" tag -am stable v1.2.3
(cd "$same_commit" && "$verifier" v1.2.3 refs/heads/main >/dev/null)
(cd "$same_commit" && "$verifier" v1.2.3-rc.1 refs/heads/main >/dev/null)
same_commit_sha=$(git -C "$same_commit" rev-parse HEAD)
(cd "$same_commit" && "$verifier" v1.2.3 refs/heads/main "$same_commit_sha" >/dev/null)
expect_failure "$same_commit" v1.2.3 0000000000000000000000000000000000000000

head_mismatch=$temporary/head-mismatch
new_repository "$head_mismatch"
git -C "$head_mismatch" tag -am rc.1 v1.2.3-rc.1
tagged_commit=$(git -C "$head_mismatch" rev-parse HEAD)
printf 'two\n' >>"$head_mismatch/content"
git -C "$head_mismatch" commit -qam two
expect_failure "$head_mismatch" v1.2.3-rc.1 "$tagged_commit"

highest_rc=$temporary/highest-rc
new_repository "$highest_rc"
git -C "$highest_rc" tag -am rc.1 v1.2.3-rc.1
printf 'two\n' >>"$highest_rc/content"
git -C "$highest_rc" commit -qam two
git -C "$highest_rc" tag -am rc.10 v1.2.3-rc.10
git -C "$highest_rc" tag -am stable v1.2.3
(cd "$highest_rc" && "$verifier" v1.2.3 refs/heads/main >/dev/null)

different_commit=$temporary/different-commit
new_repository "$different_commit"
git -C "$different_commit" tag -am rc.1 v1.2.3-rc.1
printf 'two\n' >>"$different_commit/content"
git -C "$different_commit" commit -qam two
git -C "$different_commit" tag -am stable v1.2.3
expect_failure "$different_commit" v1.2.3

missing_rc=$temporary/missing-rc
new_repository "$missing_rc"
git -C "$missing_rc" tag -am stable v1.2.3
expect_failure "$missing_rc" v1.2.3

ambiguous_rc=$temporary/ambiguous-rc
new_repository "$ambiguous_rc"
git -C "$ambiguous_rc" tag -am rc.2 v1.2.3-rc.2
git -C "$ambiguous_rc" tag -am noncanonical v1.2.3-rc.02
git -C "$ambiguous_rc" tag -am stable v1.2.3
expect_failure "$ambiguous_rc" v1.2.3

ambiguous_rc_prefix=$temporary/ambiguous-rc-prefix
new_repository "$ambiguous_rc_prefix"
git -C "$ambiguous_rc_prefix" tag -am rc.2 v1.2.3-rc.2
git -C "$ambiguous_rc_prefix" tag -am noncanonical v1.2.3-rc
git -C "$ambiguous_rc_prefix" tag -am stable v1.2.3
expect_failure "$ambiguous_rc_prefix" v1.2.3

unreachable=$temporary/unreachable
new_repository "$unreachable"
git -C "$unreachable" checkout -qb release-side
printf 'side\n' >>"$unreachable/content"
git -C "$unreachable" commit -qam side
git -C "$unreachable" tag -am rc.1 v1.2.3-rc.1
expect_failure "$unreachable" v1.2.3-rc.1

echo "release tag promotion contract verified"
