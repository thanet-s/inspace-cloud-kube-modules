#!/bin/sh
set -eu

workspace=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
filter=$workspace/scripts/filter-release-notes.awk
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT INT TERM

check_case() {
  name=$1
  input=$tmpdir/$name.input
  expected=$tmpdir/$name.expected
  actual=$tmpdir/$name.actual
  repeated=$tmpdir/$name.repeated

  awk -f "$filter" "$input" >"$actual"
  if ! cmp -s "$expected" "$actual"; then
    echo "release-note filter failed case: $name" >&2
    diff -u "$expected" "$actual" >&2 || true
    exit 1
  fi

  awk -f "$filter" "$actual" >"$repeated"
  if ! cmp -s "$actual" "$repeated"; then
    echo "release-note filter is not idempotent for case: $name" >&2
    diff -u "$actual" "$repeated" >&2 || true
    exit 1
  fi
}

cat >"$tmpdir/github-footer.input" <<'EOF'
## What's Changed
* fix: keep every pull request by @owner
* docs: explain ## New Contributors behavior

## New Contributors
* @owner made their first contribution in https://example.test/pull/1
* @dependabot[bot] made their first contribution in https://example.test/pull/2

**Full Changelog**: https://example.test/compare/v1.0.0...v1.1.0
EOF
cat >"$tmpdir/github-footer.expected" <<'EOF'
## What's Changed
* fix: keep every pull request by @owner
* docs: explain ## New Contributors behavior

**Full Changelog**: https://example.test/compare/v1.0.0...v1.1.0
EOF
check_case github-footer

cat >"$tmpdir/next-heading.input" <<'EOF'
# Release notes

## New Contributors
* @owner made their first contribution

## Installation
Install the chart.
EOF
cat >"$tmpdir/next-heading.expected" <<'EOF'
# Release notes

## Installation
Install the chart.
EOF
check_case next-heading

cat >"$tmpdir/end-of-file.input" <<'EOF'
# Release notes

## New Contributors
* @owner made their first contribution
EOF
cat >"$tmpdir/end-of-file.expected" <<'EOF'
# Release notes

EOF
check_case end-of-file

cat >"$tmpdir/no-section.input" <<'EOF'
# Release notes

### New Contributors
This lower-level heading is project content.

The phrase ## New Contributors is preserved inline.
EOF
cp "$tmpdir/no-section.input" "$tmpdir/no-section.expected"
check_case no-section

printf '# Notes\r\n\r\n## New Contributors\r\n* @owner\r\n\r\n**Full Changelog**: https://example.test/compare/a...b\r\n' \
  >"$tmpdir/crlf.input"
printf '# Notes\r\n\r\n**Full Changelog**: https://example.test/compare/a...b\r\n' \
  >"$tmpdir/crlf.expected"
check_case crlf

composer=$workspace/scripts/compose-release-notes.sh
generated=$tmpdir/composer-generated.md
composed=$tmpdir/composer-composed.md
recomposed=$tmpdir/composer-recomposed.md
cat >"$generated" <<'EOF'
## What's Changed
* fix: exclude control-plane nodes from public NLB targets

## New Contributors
* @owner made their first contribution

**Full Changelog**: https://example.test/compare/v0.3.0...v0.3.1
EOF

"$composer" v0.3.1 "$generated" "$composed"
grep -Fx '<!-- inspace-project-release-notes:v0.3.1 -->' "$composed" >/dev/null
grep -Fx '## Breaking change' "$composed" >/dev/null
grep -F 'InSpaceNodeClass.spec.hostPoolSelector' "$composed" >/dev/null
grep -Fx '## Cloud load balancer improvements' "$composed" >/dev/null
grep -Fx "## What's Changed" "$composed" >/dev/null
grep -F 'New Contributors' "$composed" >/dev/null && {
  echo 'release-note composer retained New Contributors' >&2
  exit 1
}

"$composer" v0.3.1 "$composed" "$recomposed"
if ! cmp -s "$composed" "$recomposed"; then
  echo 'release-note composer is not idempotent' >&2
  diff -u "$composed" "$recomposed" >&2 || true
  exit 1
fi

without_project_notes=$tmpdir/composer-without-project-notes.md
"$composer" v9.9.9 "$generated" "$without_project_notes"
if grep -F 'inspace-project-release-notes' "$without_project_notes" >/dev/null; then
  echo 'release-note composer added a marker without project notes' >&2
  exit 1
fi
