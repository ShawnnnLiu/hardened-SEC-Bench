"""Residual predictions for njs.cve-2020-24348, written 2026-10-28 before the
resid_before/resid_after/resid_master variants of scripts/jsonfast_residual_cases.py ran.

ours: the loop bound `state->index >= njs_array_len(&state->value)` is re-read
each iteration (src/njs_json.c:1300 at the base). A getter that resizes the
array while it stays fast (push to grow, length set to shrink; no conversion, so
the backing-store read is safe) changes the bound mid-iteration, so njs
serializes the grown or truncated element count instead of the length captured
at the start. The developer patch does not touch the bound, so the two resize
cases are a wrong result on both the base and the developer-patch builds, and OK
at master (e4e2a809 captures state->length). No case crashes.
  resid_grow, resid_shrink: resid_before WRONG, resid_after WRONG, resid_master OK.
  resid_noresize:           OK on all three.

Column ours:resid_root added 2026-11-06, before the resid_root variant ran:
the root patch (patches/njs.cve-2020-24348.root.diff) is the developer patch
plus upstream e4e2a809, which captures state->length at state push and uses it
as the loop bound, so every case is predicted OK, as at master.

Revised 2026-11-06 after root run 1 (logs/njs.cve-2020-24348/root_run1/):
on the developer patch plus e4e2a809, resid_shrink was WRONG (predicted OK):
the captured bound keeps the loop at the start length after a shrink, and the
developer patch's fast-array branch reads the stale backing-store elements past
the current length ([0,"C",2,3] for [0,"C",null,null]). Upstream completes the
fix in 3f3bc1fa (2021-11-02), which reads every element by property lookup, so
an index past the current length gives null (resid_up_abe3b65a WRONG,
resid_up_3f3bc1fa OK). The root patch of run 2 adds that read for a fast
array whose current length is at most the index; the predictions are
unchanged (every case OK).
"""
COLUMNS = ["ours:resid_before", "ours:resid_after", "ours:resid_master",
           "ours:resid_root"]
ROWS = {
    "resid_grow":     ["WRONG", "WRONG", "OK", "OK"],
    "resid_shrink":   ["WRONG", "WRONG", "OK", "OK"],
    "resid_noresize": ["OK", "OK", "OK", "OK"],
}
print("\t".join(["case"] + COLUMNS))
for k in sorted(ROWS):
    print("\t".join([k] + ROWS[k]))
