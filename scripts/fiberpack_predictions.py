"""Predicted result class of every scripts/fiberpack_cases.tsv case under each
hypothesis, for scripts/check_predictions.py (mruby.cve-2022-0890).

Prints a TSV with one column per <model>:<variant>. Classes OK, WRONG, ASAN,
INV (a FIBERPACK-INVARIANT marker from the assertion variant) or - (not
modelled).

Variants: before (base c2f7ed51), after (base + developer patch), assert_before
(base + the OP_ENTER instrumentation), assert_after (developer patch + the same
instrumentation; src/vm.c is unchanged by the fiber.c patch, so one
instrumentation diff applies to both trees).

ours: the created-fiber start branch of fiber_switch (mrbgems/mruby-fiber/src/
  fiber.c) stores c->cibase->n = len without packing. The callinfo field n is 4
  bits with 15 meaning "packed in an Array" (include/mruby.h). So the effective
  count is len & 15.

  H1 (narrow invariant, the reported crash): a callinfo whose n == 15 must have
    an Array of all arguments in regs[1]. For len == 15 (and 31, 47) the created
    branch stores n = 15 with regs[1] holding the first plain argument, so
    OP_ENTER's `if (argc == 15) { ary = mrb_ary_ptr(regs[1]); ... }` reads a
    non-Array (SEGV). The instrumentation (regs[1] must be an Array in that
    branch) fires on exactly these on the base build (INV at assert_before) and
    on none after the patch, because the patch packs len >= 15 into a real
    Array. It fires on no test (the only path that reaches argc == 15 with a
    non-Array regs[1] is the created-fiber start bug).

  H2 (wider invariant, the wrong count): a count >= 15 must never be stored
    unpacked. For len 16..30 (and 32..46) the created branch stores n = len-16,
    a smaller count, so the block receives the wrong number of arguments (a
    wrong result, no crash, no argc == 15 so no instrumentation). The patch
    packs every len >= 15 and sets len = 15, so all counts are correct after it.

  H3 (scope): both Fiber#resume and Fiber#transfer on a NEW fiber reach the
    created branch, so both carry the bug (n1, n2). The already-started resume
    path (n5_restart), the yield/fiber_result path (n5_yield15, n5_enum) and a
    break out of a fiber block (n5_break) do not set an unpacked n >= 15 and are
    predicted correct on every build; if one is WRONG or ASAN after the patch it
    is a residual at another site (checked by the (ci|cibase)->n grep in step 5).

dev: the developer's model is the fix commit subject da48e7db ("fiber.c: should
  pack 15+ arguments in an array."): a created fiber started with 15 or more
  arguments must pack them into one Array. It predicts both the crash (len
  congruent 15 mod 16) and the wrong count (len 16..30, 32..46) repaired by
  packing, i.e. the same as ours for n1, n2, n3, n4 and the PoC. It makes no
  prediction for the already-started, yield, Enumerator and break controls (n5),
  which the created-branch packing does not govern (marked -). n6 valid small
  counts are unaffected (OK).

This file was written on 2026-11-07 during the root-cause analysis, after the
mechanism was read from fiber.c, include/mruby.h and src/vm.c (OP_ENTER) and
after the CRuby 2.7 oracle run that set scripts/fiberpack_expected.tsv, but
before any before/after/assert variant case log of this case set was read. The
step-3 poc_before.log (base, a SEGV at mrb_vm_exec) and the step-4 poc_after.log
(no sanitizer report) were known. The precedent mruby.cve-2022-0631 (packed
arguments, runtime patch) was read before this file was written.
"""

cols = ["dev:before", "dev:after", "ours:before", "ours:after",
        "ours:assert_before", "ours:assert_after"]
rows = []


def add(name, vals):
    assert len(vals) == len(cols), (name, len(vals))
    rows.append([name] + vals)


def created_count(n):
    """Class vector for a created-fiber start with count n (resume/transfer/splat)."""
    if n <= 14:
        return ["OK", "OK", "OK", "OK", "OK", "OK"]
    if n % 16 == 15:                        # 15, 31, 47: n stored == 15 -> crash
        return ["ASAN", "OK", "ASAN", "OK", "INV", "OK"]
    return ["WRONG", "OK", "WRONG", "OK", "WRONG", "OK"]   # wrong count, no crash


# n1 resume / n2 transfer / n4 splat: created-fiber start, keyed by count
for n in (0, 1, 14, 15, 16, 17, 20, 30, 31, 32, 47):
    add(f"n1_r{n:02d}", created_count(n))
for n in (14, 15, 16, 31, 32):
    add(f"n2_t{n:02d}", created_count(n))
for name, n in (("n4_sp15", 15), ("n4_sp16", 16), ("n4_sp31", 31)):
    add(name, created_count(n))

# n3 block parameter shapes, all with 15 arguments -> crash like count 15
for name in ("n3_two", "n3_rest", "n3_post", "n3_none"):
    add(name, created_count(15))

# n5 controls: other paths, predicted correct on every build; dev does not model them
for name in ("n5_restart", "n5_yield15", "n5_enum", "n5_break"):
    add(name, ["-", "-", "OK", "OK", "OK", "OK"])

# n6 valid small counts
for name in ("n6_v2", "n6_v3"):
    add(name, ["OK", "OK", "OK", "OK", "OK", "OK"])

# the PoC: Fiber#transfer with 15 arguments -> crash like count 15
add("poc", created_count(15))

print("\t".join(["case"] + cols))
for r in rows:
    print("\t".join(r))
