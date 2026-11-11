"""Per-case predictions for njs.cve-2020-24348 (JSON.stringify of a fast array
whose backing store is freed by a callback during the stringify iteration).

Usage: python3 jsonfast_predictions.py > scripts/jsonfast_predictions.tsv

dev model (commit 63aa001e, closes #322): njs_json_stringify_iterator read the
fast-array backing store unconditionally; a getter/callback that converts the
array to a slow array during the iteration leaves that read out of bounds. The
fix adds an njs_is_fast_array check and a slow-path read. The developer's own
test uses a getter that runs Object.defineProperty on a later index. The model
names the construct (the array converted during the iteration), so it predicts
an out-of-bounds read on the base build for every case whose callback converts
the array (the conv_ family and the PoC) and OK after the patch, OK otherwise.
  dev:before = ASAN on conv_*, poc; OK otherwise.
  dev:after  = OK on every case.

ours (the invariant the reported failure requires): at the array-state backing-
store read (src/njs_json.c:njs_json_stringify_iterator) the receiver must still
be a fast array, so njs_array_start(&state->value) points to a live buffer. A
callback (an element's toJSON or a getter read during its serialization) that
converts the array to a slow array (index >= 32768, length > 32768, freeze/seal,
defineProperty accessor) frees array->start; the iterator then reads the freed
pointer, an out-of-bounds read.
  ours:before = ASAN on conv_* and poc; OK on keep_* (stays fast), pre_* (slow
      before the stringify) and ctl_* (no conversion).
  ours:after  = OK on every case (the read is guarded by njs_is_fast_array; a
      converted array takes the slow-path njs_value_property_i64 read).
  ours:assert_before = INV on exactly the cases that reach the unconditional
      backing-store read while the array is not fast on the base build (conv_*,
      poc); OK otherwise. The instrumentation (scripts/jsonfast_invariant.diff)
      aborts with JSONFAST-INVARIANT when the read is reached with
      !njs_is_fast_array(&state->value). There is no single-diff assert_after:
      the patch rewrites the instrumented read line into an if/else, so the base
      instrumentation does not apply to the patched tree; the post-patch
      guarantee is the njs_is_fast_array guard itself plus ours:after and
      ours:upstream_master (0 ASAN).
  ours:upstream_master = OK on every case (the fix is retained upstream).

This file was written on 2026-10-28 before any variant run of the jsonfast
case set. The only prior observation was the dataset PoC on the base build
(poc_before.log: an out-of-bounds read in njs_json_stringify_iterator).

Revised 2026-10-28 after the first before run (kept under
logs/njs.cve-2020-24348/variants_run1/): two cases were corrected in the
generator, not fitted here. conv_freeze was dropped (Object.freeze does not
convert the array to a slow array at this base, so it did not reach the
faulty state: observed OK, not the predicted ASAN). keep_idxedge was
replaced by keep_set2 (array[32767]=9 grows the array to length 32768 and
changed the loop bound, a wrong result, not the predicted OK; that effect is
the resize residual, moved to scripts/jsonfast_residual_cases.py). The
remaining ten cases are re-run with the corrected generator; the
predictions for them are unchanged from the pre-run version.

Column ours:root added 2026-11-06, before the root variant ran, after the
user's review of 2026-11-06 adopted the loop-bound residual into scope. The
root patch (patches/njs.cve-2020-24348.root.diff) is the developer patch plus
upstream e4e2a809, which captures state->length at state push and leaves the
developer patch's njs_is_fast_array read guard unchanged, so it is predicted
OK on every case of this set, as ours:after.
Revised 2026-11-06 after root run 1 (logs/njs.cve-2020-24348/root_run1/,
11 of 11 matched): the root patch of run 2 also adds the element read of
upstream 3f3bc1fa (an index at or past the current length of a fast array
reads null); no case of this set shrinks the array, so the predictions are
unchanged.
"""
CONV = ["conv_defprop", "conv_getter", "conv_idx", "conv_len"]
OK_CASES = ["keep_set0", "keep_set2", "pre_idx", "ctl_plain", "ctl_tojson", "ctl_nested"]
COLUMNS = ["dev:before", "dev:after", "ours:before", "ours:after",
           "ours:assert_before", "ours:upstream_master", "ours:root"]

def row(name, faulty):
    if faulty:
        return [name, "ASAN", "OK", "ASAN", "OK", "INV", "OK", "OK"]
    return [name, "OK", "OK", "OK", "OK", "OK", "OK", "OK"]

print("\t".join(["case"] + COLUMNS))
rows = [row(n, True) for n in CONV] + [row(n, False) for n in OK_CASES] + [row("poc", True)]
for r in sorted(rows):
    print("\t".join(r))
