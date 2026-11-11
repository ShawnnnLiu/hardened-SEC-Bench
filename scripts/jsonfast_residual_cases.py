"""Residual case set for njs.cve-2020-24348: JSON.stringify of a fast array
whose LENGTH (the loop bound), not its backing store, is changed by a getter
during the iteration.

Usage: python3 jsonfast_residual_cases.py OUTDIR

The developer patch (63aa001e) guards the backing-store READ with
njs_is_fast_array, which fixes the reported out-of-bounds read when a callback
converts the array to a slow array. It does not touch the loop bound
`if (state->index >= njs_array_len(&state->value))` (src/njs_json.c:1300 at the
image base c3da13fb), which is re-read on every iteration. A getter/toJSON that
resizes the array while it stays a fast array (push to grow, length set to
shrink; no conversion, so the read stays safe) changes the bound mid-iteration,
so njs serializes a different number of elements than the length captured at the
start. The spec (and Node.js) captures the array length once, so this is a wrong
result, not a crash. Upstream commit e4e2a809 ("Fixed JSON.stringify() for
arrays resizable via getters.", 2020-10-06, after the dev fix) captures
state->length at state push and uses it as the bound, fixing it.

Observable: JSON.stringify(a). On the base and developer-patch builds the fast
resize gives a wrong result (no sanitizer report); at master it matches Node.

Cases:
  resid_grow    element 1 toJSON pushes two elements (a.push(7,8)); stays fast;
                njs reads the grown length, Node stops at the captured length.
  resid_shrink  element 1 toJSON sets a.length=1; stays fast; njs truncates,
                Node reads the captured length (holes -> null).
  resid_noresize  element 1 toJSON does not resize (control); OK everywhere.
"""
import sys
from pathlib import Path

PRELUDE = r"""
function show(v) { return typeof v + ':' + String(v); }
function out(f) { var r; try { r = show(f()); } catch (e) { r = 'E:' + e.name; } console.log(r); }
"""

CASES = {
    "resid_grow":
        "var a=[0,null,2,3]; a[1]={toJSON:function(){ a.push(7,8); return 'C'; }}; "
        "return JSON.stringify(a);",
    "resid_shrink":
        "var a=[0,null,2,3]; a[1]={toJSON:function(){ a.length=1; return 'C'; }}; "
        "return JSON.stringify(a);",
    "resid_noresize":
        "var a=[0,null,2,3]; a[1]={toJSON:function(){ return 'C'; }}; "
        "return JSON.stringify(a);",
}


def main(outdir):
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    rows = ["\t".join(["case", "absent"])]
    for name in sorted(CASES):
        (out / (name + ".js")).write_text(PRELUDE + "out(function() { " + CASES[name] + " });\n")
        rows.append("\t".join([name, "none"]))
    (out / "cases.tsv").write_text("\n".join(rows) + "\n")
    print(f"{len(CASES)} residual cases written to {outdir}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python3 jsonfast_residual_cases.py OUTDIR")
    main(sys.argv[1])
