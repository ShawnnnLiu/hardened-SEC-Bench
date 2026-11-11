#!/bin/bash
# Run WAVE inputs through four gpac consumers and report, per run, the exit
# status, timeout, sanitizer report and a hash of the output.
#
# Usage, inside a SEC-bench gpac container after "secb build":
#   gpac_wav_cases.sh FILE...
#
# Consumers:
#   poc      the SEC-bench repro command line (MP4Box -dash 1000 -out /dev/null)
#   add      MP4Box -add FILE -new out.mp4
#   inspect  gpac -i FILE inspect:deep (packet and property dump)
#   pcm      gpac -i FILE -o out.pcm
# All but poc run with -for-test, so outputs carry no version or time
# strings, and with -noprog, so stderr carries no progress bars.
# Inputs named bad_* and valid_* form two classes; any other input counts
# as poc. The sanitizer field holds the error type only (no addresses), so
# result lines are comparable across runs. The last line is
#   summary: N runs; memory errors E (poc a, bad b, valid c); leaks L (...); timeouts T (...); valid outputs D
# where memory errors are AddressSanitizer or UBSan reports, leaks are
# LeakSanitizer reports, and D is the first 12 hex digits of the sha256
# over the result lines of the valid_* inputs.
# Environment: CASE_TIMEOUT (seconds, default 120).
set -u
BIN=/src/gpac/bin/gcc
T=${CASE_TIMEOUT:-120}

n=0; valid=""
declare -A cnt
cd /src/gpac
echo "HEAD $(git rev-parse HEAD)"
echo "--- git diff --stat"
git diff --stat
echo "ASAN_OPTIONS=${ASAN_OPTIONS-<unset>}"
echo "UBSAN_OPTIONS=${UBSAN_OPTIONS-<unset>}"
echo "timeout=${T}s"

for f in "$@"; do
  name=$(basename "$f")
  echo
  echo "=== $name sha256=$(sha256sum "$f" | cut -d' ' -f1)"
  for c in poc add inspect pcm; do
    w=$(mktemp -d)
    case $c in
      poc)     cmd=("$BIN/MP4Box" -dash 1000 -out /dev/null "$f") ;;
      add)     cmd=("$BIN/MP4Box" -for-test -noprog -add "$f" -new "$w/out/o.mp4") ;;
      inspect) cmd=("$BIN/gpac" -for-test -noprog -i "$f" "inspect:deep:log=$w/out/o.txt") ;;
      pcm)     cmd=("$BIN/gpac" -for-test -noprog -i "$f" -o "$w/out/o.pcm") ;;
    esac
    mkdir -p "$w/out"
    (cd "$w" && timeout -k 5 "$T" "${cmd[@]}" > "$w/stdout" 2> "$w/stderr")
    rc=$?
    if [ $rc -eq 124 ] || [ $rc -eq 137 ]; then hang=yes; else hang=no; fi
    san=$(grep -m1 -E "ERROR: (Address|Leak|Memory|Thread)Sanitizer|runtime error:" "$w/stderr" |
      sed -E 's/^==[0-9]+==//; s/ on (unknown )?address .*//; s/ \(pc .*//; s/ in [0-9]+ object.*//')
    files=$(cd "$w/out" && find . -type f | sort)
    if [ -n "$files" ]; then
      out=$(cd "$w/out" && echo "$files" | xargs sha256sum | sha256sum | cut -d' ' -f1)
    else
      out=none
    fi
    line="--- $name $c exit=$rc timeout=$hang sanitizer=${san:-none} output=$out"
    echo "$line"
    n=$((n+1))
    case $name in bad_*) cls=bad ;; valid_*) cls=valid; valid="$valid$line"$'\n' ;; *) cls=poc ;; esac
    case $san in "") ;; *LeakSanitizer*) cnt[leak,$cls]=$((${cnt[leak,$cls]:-0}+1)) ;; *) cnt[mem,$cls]=$((${cnt[mem,$cls]:-0}+1)) ;; esac
    [ $hang = yes ] && cnt[hang,$cls]=$((${cnt[hang,$cls]:-0}+1))
    echo "\$ ${cmd[*]}" | sed "s#$w#\$W#g"
    sed "s#$w#\$W#g" "$w/stderr"
    # keep the next result line on its own line
    [ -s "$w/stderr" ] && [ -n "$(tail -c1 "$w/stderr")" ] && echo
    rm -rf "$w"
  done
done
echo
part() { # kind label
  local a=${cnt[$1,poc]:-0} b=${cnt[$1,bad]:-0} c=${cnt[$1,valid]:-0}
  echo "$2 $((a+b+c)) (poc $a, bad $b, valid $c)"
}
echo "summary: $n runs; $(part mem 'memory errors'); $(part leak leaks); $(part hang timeouts); valid outputs $(printf '%s' "$valid" | sha256sum | cut -c1-12)"
