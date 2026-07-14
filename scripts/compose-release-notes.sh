#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <tag> <generated-notes> <output>" >&2
  exit 2
fi

tag=$1
generated_notes=$2
output=$3
workspace=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
filter=$workspace/scripts/filter-release-notes.awk
project_notes=$workspace/release-notes/$tag.md
marker="<!-- inspace-project-release-notes:$tag -->"
combined=$(mktemp)
trap 'rm -f "$combined"' EXIT INT TERM

if [ -f "$project_notes" ] && ! grep -Fqx "$marker" "$generated_notes"; then
  {
    printf '%s\n' "$marker"
    cat "$project_notes"
    printf '\n'
    cat "$generated_notes"
  } >"$combined"
else
  cp "$generated_notes" "$combined"
fi

awk -f "$filter" "$combined" >"$output"
