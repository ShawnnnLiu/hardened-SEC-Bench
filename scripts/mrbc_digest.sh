#!/bin/bash
# Compiles every Ruby file in the mruby source tree with the given mrbc and
# prints the sha256 of each compiled .mrb, so that compiler output can be
# compared between builds.
# Usage (inside the instance container): mrbc_digest.sh <mrbc binary>
set -u
MRBC=$1
O=$(mktemp -d)
cd /src/mruby
find . -path ./build -prune -o -name '*.rb' -type f -print | LC_ALL=C sort | while read -r f; do
  if "$MRBC" -o "$O/out.mrb" "$f" >/dev/null 2>&1; then
    printf '%s  %s\n' "$(sha256sum < "$O/out.mrb" | cut -c1-64)" "$f"
  else
    printf '%-64s  %s\n' "COMPILE-ERROR" "$f"
  fi
done
rm -rf "$O"
