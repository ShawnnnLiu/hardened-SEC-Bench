#!/bin/bash
# `send` with a packed argument array (mruby.cve-2022-0631). In mrb_f_send
# (src/vm.c), a packed call (ci->n == CALL_MAXARGS == 15: 15+ positional
# arguments, or any splat call, which the compiler always emits as a packed
# OP_SEND because the runtime array length is unknown) reads the first element
# of the packed array regs[0] as the method-name symbol:
#   name = mrb_obj_to_sym(mrb, RARRAY_PTR(regs[0])[0]);   (base src/vm.c:695)
# The n == 15 branch does not check that the packed array is non-empty. An empty
# packed array makes that a read of 8 bytes past the array buffer: the dataset
# heap-buffer-overflow READ, frame 0 mrb_f_send at vm.c:695.
#
# Two ways reach an empty packed array:
#   (a) directly, from an empty splat: send(*[]) packs to n == 15, regs[0] == [].
#   (b) by re-dispatch: in the n == 15 branch mrb_f_send drops the first element
#       (regs[0] = mrb_ary_subseq(regs[0], 1, len-1)) and re-enters send while
#       ci->n stays 15, so a chain send "send", ..., "send" of >= 15 "send"
#       strings empties the array after as many steps as it has elements. The
#       dataset PoC is 15 "send" strings (frames mrb_f_send at vm.c:732, the
#       re-dispatch, down to the OOB read at vm.c:695).
# The developer patch (upstream 47068ae07) inserts, in the n == 15 branch,
#   if (RARRAY_LEN(regs[0]) == 0) goto argnum_error;
# before the read, so an empty packed array raises the same ArgumentError the
# n == 0 branch raises ("wrong number of arguments (given 0, expected 1+)").
#
# Usage (inside the instance container): sendpack_cases.sh <mruby binary>
# Passing `ruby` runs only the value controls on the image's CRuby, which
# validates their expected values (the crasher and boundary cases raise
# exceptions on CRuby and are skipped there).
#
# Result class per case: ASAN (sanitizer report), INV (a SEND-INVARIANT marker
# from the assertion variant), OK, or WRONG. A crash is judged by the sanitizer
# report, never by exit status. For a crasher or boundary case OK means no
# sanitizer report (a controlled Ruby exception); for a value control OK means
# the printed value equals the CRuby reference.
set -u
MRUBY=$1
D=$(mktemp -d)
ok=0; wrong=0; asan=0; inv=0; total=0
is_ruby=0; [ "$MRUBY" = ruby ] && is_ruby=1

classify() { # name, output
  local name=$1 out=$2
  total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1)); printf '%-18s ASAN %s\n' "$name" "$(grep -m1 -oE 'heap-buffer-overflow|SEGV' <<<"$out")"
  elif grep -q 'SEND-INVARIANT' <<<"$out"; then
    inv=$((inv+1)); printf '%-18s %s\n' "$name" "$(grep -m1 -o 'SEND-INVARIANT[^"]*' <<<"$out")"
  else
    ok=$((ok+1)); printf '%-18s OK\n' "$name"
  fi
}

# A crasher / boundary with no value: OK = no sanitizer report. Skipped under
# the CRuby oracle (these raise exceptions, not values).
sym_case() { # name, program
  [ $is_ruby = 1 ] && return
  local f=$D/$1.rb out; printf '%s\n' "$2" > "$f"
  out=$("$MRUBY" "$f" 2>&1)
  classify "$1" "$out"
}

# A value control: must print the expected value (equal to CRuby) on every build.
val_case() { # name, program, expected
  local f=$D/$1.rb out val; printf '%s\n' "$2" > "$f"
  out=$("$MRUBY" "$f" 2>&1); total=$((total+1))
  if grep -q 'ERROR: AddressSanitizer' <<<"$out"; then
    asan=$((asan+1)); printf '%-18s ASAN\n' "$1"
  elif grep -q 'SEND-INVARIANT' <<<"$out"; then
    inv=$((inv+1)); printf '%-18s SEND-INVARIANT\n' "$1"
  else
    val=$(sed -n 's/.*<<\(.*\)>>.*/\1/p' <<<"$out" | tail -1)
    if [ "$val" = "$3" ]; then ok=$((ok+1)); printf '%-18s OK\n' "$1"
    else wrong=$((wrong+1)); printf '%-18s WRONG got=%s\n' "$1" "${val:-<none>}"; fi
  fi
}

# --- crashers: an empty packed array reaches RARRAY_PTR(regs[0])[0] ---
# Direct empty splat (n == 15, regs[0] == []).
sym_case splat_empty    'send(*[])'
sym_case dunder_empty   '__send__(*[])'
# One-element splat whose only element names send: send -> subarray [] -> send
# with n == 15 and an empty array -> OOB read.
sym_case recurse1       'send(*[:send])'
# 16 literal "send" strings: n == 15, 16 re-dispatches empty the array (same
# family as the 15-string dataset PoC, one step deeper).
a=''; for _ in $(seq 16); do a=$a'"send",'; done
sym_case crash16        "send ${a%,}"

# --- boundary: n != 15, or a non-empty packed array whose first element is read
#     validly ---
# send(:send): one literal arg (n == 1, not packed), re-dispatch send with
# n == 0 -> ArgumentError (no crash; exercises the n != 15 path).
sym_case send_sym       'send(:send)'
# A 1-element packed array naming an undefined method: the first element is read
# validly, the method is undefined -> method_missing -> NoMethodError (no crash;
# a non-empty packed array through the n == 15 branch).
sym_case send_undef     'send(*[:no_such_method_0631])'

# --- value controls: a non-empty packed array through the n == 15 branch, then
#     a real method; must keep the CRuby value on every build ---
val_case ctrl_str       'print "<<" + "abc".send(:upcase) + ">>"'                 "ABC"
val_case ctrl_splat1    'print "<<" + [3,1,2].send(*[:sort]).inspect + ">>"'      "[1, 2, 3]"
val_case ctrl_splat2    'print "<<" + "hello".send(*[:ljust, 7]) + ">>"'          "hello  "

# --- the dataset PoC (recursive send chain, 15 "send" strings) ---
if [ $is_ruby = 0 ] && [ -f /testcase/poc_decoded ]; then
  out=$("$MRUBY" /testcase/poc_decoded 2>&1)
  classify poc "$out"
fi

echo "summary: $ok OK, $wrong WRONG, $asan ASAN, $inv INV of $total"
rm -rf "$D"
