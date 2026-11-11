"""Predicted result class of every scripts/fncopy_cases.py case under each
model, for scripts/check_predictions.py (njs.cve-2022-43284).

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG,
ASAN, INV (the FNCOPY-INVARIANT check fired) or - (not modelled).

dev: the developer's model, from the commit message of 04f59f9d, "Fixed
  function value initialization." (closes issue #470). The message names
  the mechanism (function value initialization re-runs wrongly) but states
  only the single reported symptom, a crash. Read literally, dev predicts a
  sanitizer report for every input that reaches the wrong re-initialization
  (the value-undefined cases and the PoC) on the base build, and the fix
  removes it (dev:after OK everywhere). The mismatches of dev:before are the
  value-undefined cases whose base symptom is a wrong result, not a crash.

ours: H1, the invariant. njs_vmcode_function_copy() (NJS_VMCODE_FUNCTION_COPY,
  the lazy materialization of a function-declaration binding) must store the
  function value only while the target binding is NJS_INVALID. The base
  reads the slot with njs_scope_valid_value(), which turns an NJS_INVALID
  var slot into NJS_UNDEFINED, and re-initializes when njs_is_undefined() is
  true; so a binding the program assigned the value undefined is wrongly
  re-materialized on its next use. H1 therefore predicts, per case:
    value != undef (null, num, str, obj): the base guard njs_is_undefined()
      is false, no re-initialization, so base and patch agree (OK).
    value == undef, structure self, retrigger call: the re-materialized
      function has a NULL closure slot for its self-name, so re-entering it
      (the retrigger call) reads njs_scope_value() = NULL and faults (ASAN).
    value == undef, otherwise (ref retrigger, or local/global structure):
      the binding is re-materialized into the function where the reference
      engine leaves undefined or a non-function, a wrong result (WRONG).
  ours:after predicts OK for every case (the patch leaves an assigned
  undefined in place; calling it then throws TypeError as the reference).
  ours:assert_before predicts INV on exactly the cases where the base
  re-initializes a slot that was not NJS_INVALID (every value-undefined case,
  masked_reassign_back, and the PoC); ours:assert_after predicts OK
  everywhere (the patch never re-initializes a valid slot, so the check
  never fires), 0 INV.

masked_reassign_back: the invariant is violated (the base re-initializes an
  undefined slot at the `a0 = function` assignment target) but the wrong
  value is overwritten by the new function, so the observable output is OK
  on both builds (ours:before OK) while assert_before still fires (INV).
poc: the dataset PoC (self structure, call retrigger, undefined), ASAN on
  base, OK after, INV under assert_before.

This file was written on 2026-10-28 before the before variant of the
fncopy cases ran. The confirming probes used first (njs -d disassembly of
the dataset PoC and of the self/local/global ref cases, to see that each
retrigger re-emits FUNCTION_COPY and that only the self structure emits a
FUNCTION_COPY inside the callee) are named in scripts/fncopy_cases.py.
"""
cols = ["dev:before", "dev:after", "ours:before", "ours:after",
        "ours:assert_before", "ours:assert_after"]
rows = []

STRUCT = ("self", "local", "global")
RETR = ("ref", "call")
VAL = ("undef", "null", "num", "str", "obj")

for structure in STRUCT:
    for retr in RETR:
        for value in VAL:
            name = "%s_%s_%s" % (structure, retr, value)
            if value != "undef":
                rows.append([name, "OK", "OK", "OK", "OK", "OK", "OK"])
                continue
            # value == undef: base reaches the wrong re-initialization
            if structure == "self" and retr == "call":
                ours_before = "ASAN"
            else:
                ours_before = "WRONG"
            rows.append([name, "ASAN", "OK", ours_before, "OK", "INV", "OK"])

# valid controls: no undefined ever assigned to a live function binding
for name in ("valid_self_defined_twice", "valid_self_readonly_call",
             "valid_local_call_normal", "valid_local_ref_normal",
             "valid_global_call_normal", "valid_global_ref_normal"):
    rows.append([name, "OK", "OK", "OK", "OK", "OK", "OK"])

# masked: invariant violated, symptom overwritten
rows.append(["masked_reassign_back", "OK", "OK", "OK", "OK", "INV", "OK"])

# the dataset PoC (added by the variant runner as case "poc")
rows.append(["poc", "ASAN", "OK", "ASAN", "OK", "INV", "OK"])

print("\t".join(["case"] + cols))
for r in rows:
    print("\t".join(r))
