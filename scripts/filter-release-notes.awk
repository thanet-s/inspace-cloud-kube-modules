{
  normalized = $0
  sub(/\r$/, "", normalized)
}

normalized ~ /^## New Contributors[[:space:]]*$/ {
  dropping = 1
  next
}

dropping && (normalized ~ /^#(#)?[[:space:]]/ || normalized ~ /^\*\*Full Changelog\*\*:/) {
  dropping = 0
}

!dropping {
  print
}
