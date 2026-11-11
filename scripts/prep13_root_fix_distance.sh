#!/bin/bash
# Prints the facts of the root_fix_distance field of libredwg.cve-2021-28237:
# the developer fix ea0b9522 and the upstream commits on master that remove
# its PREP_TABLE guard or change the realloc of dwg->object in the pre-R13
# decoder (src/decode.c, later src/decode_r11.c): author, dates, distance in
# days and commits, first tags, the tags that hold the developer fix but not
# the commit, the pull requests that contain each commit (GitHub API), and
# the changed guard and realloc lines.
#
# Usage: scripts/prep13_root_fix_distance.sh <clone>
#   <clone>  a full clone of https://github.com/LibreDWG/libredwg (all tags)
set -u
cl=$1
dev=ea0b9522f63d049ded2c3cff8d9a8c360119951c
g() { git -C "$cl" "$@"; }
days() { python3 -c 'import sys; from datetime import datetime as d; print((d.fromisoformat(sys.argv[2]) - d.fromisoformat(sys.argv[1])).days)' "$1" "$2"; }
prs() { gh api "repos/LibreDWG/libredwg/commits/$1/pulls" --jq '[.[].number] | map(tostring) | join(",")' 2>&1; }
echo "--- clone origin/master $(g rev-parse origin/master) committed $(g log -1 --format=%cI origin/master)"
devdate=$(g log -1 --format=%aI $dev)
echo "--- developer fix $(g log -1 --format='%H, author %an, %aI, subject: %s' $dev)"
echo "pull requests containing it: [$(prs $dev)]"
echo "first tags containing it: $(g tag --contains $dev --sort=creatordate | head -3 | tr '\n' ' ')"
echo "--- commits on origin/master that change the number of occurrences of '(num + i) >= dwg->num_objects' (the guard), oldest first"
g log --reverse --format='%H %aI %an | %s' -S'(num + i) >= dwg->num_objects' origin/master -- src/decode.c src/decode_r11.c
echo "--- commits on origin/master that change the number of occurrences of 'num_objects % REFS_PER_REALLOC', oldest first"
g log --reverse --format='%H %aI %an | %s' -S'num_objects % REFS_PER_REALLOC' origin/master -- src/decode.c src/decode_r11.c
for c in fc817fc8 ce1caa61 7c7fd50a cdd1bd00; do
  full=$(g rev-parse --verify -q "$c^{commit}") || { echo "=== $c: not in the clone"; continue; }
  if g merge-base --is-ancestor "$full" origin/master; then on=yes; else on=no; fi
  echo "=== $full (on origin/master: $on)"
  echo "author $(g log -1 --format='%an <%ae>, %aI; committer date %cI' "$full")"
  echo "subject: $(g log -1 --format=%s "$full")"
  echo "body: $(g log -1 --format=%b "$full" | tr '\n' ' ' | cut -c1-400)"
  [ $on = yes ] || continue
  d=$(g log -1 --format=%aI "$full")
  echo "days after the developer fix (author dates): $(days "$devdate" "$d")"
  echo "commits $dev..$full: $(g rev-list --count $dev..$full)"
  echo "first tags containing it: $(g tag --contains "$full" --sort=creatordate | head -3 | tr '\n' ' ')"
  echo "tags with the developer fix and without it: $(g tag --contains $dev --no-contains "$full" --sort=creatordate | tr '\n' ' ')"
  echo "pull requests containing it: [$(prs "$full")]"
  echo "changed guard and realloc lines (src/decode.c, src/decode_r11.c):"
  g show --format= "$full" -- src/decode.c src/decode_r11.c | grep -E '^[-+][^-+]' | grep -E 'realloc \(dwg->object|REFS_PER_REALLOC|\(num \+ i\) >= dwg->num_objects' | head -12
done
echo "--- end"
