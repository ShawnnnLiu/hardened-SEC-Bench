"""Predicted result class of every case of scripts/fiberargs_cases.tsv under each
hypothesis, for scripts/check_predictions.py (mruby.cve-2018-12248).

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG, ASAN,
INV (a FIBERARGS-INVARIANT abort from the assertion variant) or - (no prediction).

dev: the developer's model, from issue #4038 ("Heap buffer overflow in OP_ENTER")
  and the fix commit "Extend stack when pushing arguments that does not fit in;
  fix #4038": a new fiber's stack is not sized for the receiver, the arguments and
  the block slot, so many arguments overrun the stack (len 63, the reported crash)
  or are rejected by the FiberError limit (len >= 64); the fix extends the stack.
  dev predicts the overrun (CRASH63) ASAN on the base and OK after, the FiberError
  rejection (BIG64) WRONG on the base (the base rejects input CRuby accepts) and OK
  after, and no change for inputs that fit (OK62) or for a strict lambda (LAMBDA,
  an ArgumentError regardless). It does not model the MRB_STACK_MAX cap, so it
  predicts OK after for the 300000-argument case (W); the observation there is a
  dev contradiction if the cap changes the result.

ours: H1, the reported overrun. fiber_switch (fiber.c:183) copies len arguments to
  a new fiber's 64-slot stack after the check `len >= c->stend - c->stack`
  (raises FiberError only at len >= 64); the block's OP_ENTER then reads the block
  slot blk = &argv[argc] = &stack[len+1], so at len 63 the slot is stack[64], one
  past the stack (ASAN at vm.c:1859). len <= 62 is in bounds (OK); len >= 64 is
  rejected by the FiberError check before the copy (WRONG vs the CRuby value); the
  developer patch replaces the check with mrb_stack_extend(len+2), so every len is
  sized and OK. A block with more than 64 locals makes fiber_init allocate a larger
  stack, so len 63 is in bounds there (g_big63 OK). Every non-strict block shape
  overruns at len 63 (the block slot is &argv[argc] regardless of the shape); the
  strict lambda raises ArgumentError before the block-slot move, so it does not
  overrun (LAMBDA OK on both). Controls that do not copy onto a new fiber's stack
  (started-fiber resume, Fiber.yield, transfer to root, Enumerator) are OK.
  H2, the switch-raise (W): a splat of 300000 arguments exceeds MRB_STACK_MAX
  (0x40000-128 = 262016); at the base the FiberError check raises before any
  context switch (WRONG, E:FiberError vs CRuby E:SystemStackError), after the patch
  mrb_stack_extend is reached (the context already switched) and raises there.
  Revised 2026-11-07 after the before/after variants ran: W was first predicted
  WRONG after the patch (a guess that the mruby stack-extend error class would
  differ or the post-switch raise would leave a wrong state). Observed OK: the
  after build raises SystemStackError (the same class as CRuby) and a second fiber
  resume still returns 42, so the dev patch's switch-raise is clean and matches
  CRuby's E:SystemStackError|42; the patch introduces no bad state and no sanitizer
  report on 300000 arguments. The W prediction is corrected to OK for ours:after
  and ours:assert_after (dev:after was already OK); ours:before and
  ours:assert_before stay WRONG (the base raises FiberError, not SystemStackError).
  H3, assertion. scripts/fiberargs_invariant.diff (one diff in src/vm.c; the
  developer patch does not touch vm.c) aborts with FIBERARGS-INVARIANT right after
  blk is computed when argc >= 0 and &regs[argc+1] >= stend (the block slot is at or
  past the stack end). On the base it fires on exactly the inputs whose block slot
  overruns (CRASH63, and LAMBDA, where the slot is past the stack even though the
  strict check would raise before the move); len <= 62 does not reach the condition
  (OK) and len >= 64 raises FiberError in fiber_switch before OP_ENTER runs, so the
  instrumentation is never reached (WRONG, as on the base). After the patch the
  extended stack puts every block slot in bounds, so the marker never fires
  (assert_after 0 INV); W raises in mrb_stack_extend before OP_ENTER (no INV).
  gold is the SEC-bench model_patch.diff (only the second hunk, removing the late
  fiber_switch_context) and is not a fix: applied alone a new fiber's context is
  never switched, so it is predicted - (no reliable per-case model) and observed.

This file was written on 2026-11-07 before the before variant ran. Known when it
was written: poc_before.log (the heap-buffer-overflow at the OP_ENTER block move,
first project frame mrb_vm_exec, allocation stack fiber_init), poc_after.log (no
report), and the CRuby 2.7.0 values of scripts/fiberargs_expected.tsv; no case of
the table had been run with mruby.
"""
import csv
import sys

COLS = ["dev:before", "dev:after", "ours:before", "ours:after",
        "ours:assert_before", "ours:assert_after", "ours:gold"]

#               dev:b   dev:a   o:b     o:a     o:asb   o:asa   o:gold
ROW = {
    "ok62":  ["OK",   "OK",  "OK",   "OK",   "OK",   "OK",   "-"],
    "crash": ["ASAN", "OK",  "ASAN", "OK",   "INV",  "OK",   "-"],
    "lambda":["OK",   "OK",  "OK",   "OK",   "INV",  "OK",   "-"],
    "big64": ["WRONG","OK",  "WRONG","OK",   "WRONG","OK",   "-"],
    "w":     ["WRONG","OK",  "WRONG","OK",   "WRONG","OK",   "-"],
}

CRASH = {"n_poc", "n_res_x_63", "n_res_a_63", "n_tr_x_63", "n_tr_a_63",
         "h_ab_63", "h_arb_63", "h_opt_63"}
BIG64 = {"n_res_x_64", "n_res_x_65", "n_res_x_100", "n_res_x_1000",
         "n_res_a_64", "n_res_a_65", "n_res_a_100", "n_res_a_1000", "n_tr_x_64"}


def group(name):
    if name in CRASH:
        return "crash"
    if name in BIG64:
        return "big64"
    if name == "h_lambda_63":
        return "lambda"
    if name == "w_bigsplat":
        return "w"
    return "ok62"


cases = [r[0] for r in csv.reader(open(sys.argv[1] if len(sys.argv) > 1 else
                                       "scripts/fiberargs_cases.tsv"), delimiter="\t")]
print("case\t" + "\t".join(COLS))
for n in cases:
    print(n + "\t" + "\t".join(ROW[group(n)]))
