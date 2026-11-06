#!/bin/sh
set -eu

percent=$(printf '%s' "${1:-}" | tr -d '[:space:]')
if ! printf '%s' "$percent" | grep -Eq '^[0-9]+([.][0-9]+)?$'; then
  echo "coverage percent is not a number" >&2
  exit 1
fi

color=$(awk -v p="$percent" 'BEGIN {
  p += 0
  if (p >= 90) print "brightgreen"
  else if (p >= 80) print "green"
  else if (p >= 60) print "yellow"
  else print "red"
}')
message=$(awk -v p="$percent" 'BEGIN { printf "%.1f%%", p+0 }')

dir=$(mktemp -d)
repo="https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"
if git ls-remote --heads "$repo" badges | grep -q 'refs/heads/badges'; then
  git clone --depth 1 --branch badges "$repo" "$dir"
else
  git init -b badges "$dir"
fi

cat > "$dir/coverage.json" <<EOF
{
  "schemaVersion": 1,
  "label": "coverage",
  "message": "${message}",
  "color": "${color}",
  "cacheSeconds": 300
}
EOF

if git -C "$dir" rev-parse --verify HEAD >/dev/null 2>&1; then
  current=$(mktemp)
  git -C "$dir" show HEAD:coverage.json > "$current" 2>/dev/null || true
  if cmp -s "$dir/coverage.json" "$current"; then
    exit 0
  fi
fi

git -C "$dir" add coverage.json
git -C "$dir" -c user.name='github-actions[bot]' -c user.email='41898282+github-actions[bot]@users.noreply.github.com' commit -m "Update the coverage badge."
if git -C "$dir" remote get-url origin >/dev/null 2>&1; then
  git -C "$dir" push origin HEAD:badges
else
  git -C "$dir" push "$repo" HEAD:badges
fi
