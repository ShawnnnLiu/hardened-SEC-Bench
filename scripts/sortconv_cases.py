"""Write the JavaScript case files for njs.cve-2022-29780 (Array.prototype.sort
with a comparator that converts the receiving fast array to a slow array
during the sort).

Usage: python3 sortconv_cases.py OUTDIR

Writes OUTDIR/<case>.js and OUTDIR/cases.tsv with the columns case,
family, how (the mutation the comparator performs, or "none"), slow (1
when the array is a slow array at the write-back, 0 otherwise), viol (1
when the case reaches the faulty state: the write-back dereferences a
freed element buffer), absent (the key scripts/njs_cases.py uses for its
valid-output digest: "none" for a case that does not reach the faulty
state, "conv" for one that does).
Each script defines a printer (show() normalizes a value as
typeof:String(value); a thrown error as E:name) and prints one line.
The expected output of each case is the reference engine's output on the
same file (scripts/njs_cases.py --oracle).

Mechanism under test (src/njs_array.c:njs_array_prototype_sort at the
base commit 675049dc):

The invariant that the reported failure requires: at the write-back loop
(src/njs_array.c:2704, `start[i] = slots[i].value`) the local flag
fast_path must still describe the receiver.  fast_path is computed once
near the top (`fast_path = njs_is_fast_array(this)`) before the elements
are read into the local `slots` buffer and before njs_qsort() calls the
user comparator.  When the comparator runs it can convert the receiver
from a fast array to a slow array: njs_array_convert_to_slow_array()
frees array->start and sets it to NULL and clears array->fast_array.
The write-back block re-reads `array = njs_array(this); start =
array->start;` but still enters the fast branch on the stale fast_path,
so `start` is NULL and the struct assignment `start[i] = slots[i].value`
(emitted as a memcpy) writes at address 0: a SEGV, WRITE at 0x0, top
frames memcpy / __asan_memcpy / njs_array_prototype_sort
(src/njs_array.c:2704).

A fast array is converted to a slow array by:
  - a length set above NJS_ARRAY_LARGE_OBJECT_LENGTH (32768):
    njs_array_length() converts when `length > 32768`
    (src/njs_array.c, the else of `length <= NJS_ARRAY_LARGE_OBJECT_LENGTH`);
  - an index assignment with index >= 32768:
    njs_value property-set converts when `!(index < 32768)`
    (src/njs_value.c:756 and :779).
Below the threshold the array stays fast (the buffer is only expanded),
so the write-back buffer is valid.

The comparator runs only through njs_qsort(), which needs a JavaScript
comparefn and at least two non-undefined elements; the default (no
comparefn) string comparison does not call back into JavaScript, so it
cannot convert the array.  A slow array at read-in takes the slow branch
throughout (fast_path is 0), so the conversion is moot.

Families (case name prefix):
  conv_*  a fast array of two numbers, a comparator that converts it to a
          slow array and returns 0 (no reorder); the faulty state.
            conv_len_big  comparator sets a.length = 65535 (the developer's
                          added unit test shape)
            conv_idx_big  comparator sets a[65535] = 9 (the issue #486 PoC
                          shape, which uses a[0xffff] *= arg)
            conv_len_edge comparator sets a.length = 32769 (one above the
                          threshold)
            conv_idx_edge comparator sets a[32768] = 9 (the threshold index)
  keep_*  a fast array of two numbers, a comparator that mutates it but
          leaves it a fast array; no faulty state.
            keep_set0     comparator sets a[0] = 9 (a small index)
            keep_len_edge comparator sets a.length = 32768 (the threshold,
                          stays fast)
            keep_idx_edge comparator sets a[32767] = 9 (one below the
                          threshold, stays fast)
  pre_*   the array is already a slow array before the sort, so fast_path
          is 0 at read-in; the comparator does not mutate.  No faulty state.
            pre_len       a.length is set to 65535 before the sort
            pre_idx       a[65535] is set before the sort
  ctl_*   no comparator or no mutation; no faulty state.
            ctl_nocmp     [3,1,2].sort() (no comparefn: no JavaScript call)
            ctl_cmp       [3,1,2].sort((x,y)=>x-y) (a comparator, no mutation)
            ctl_like      Array.prototype.sort.call on an array-like object
                          (not a fast array)

The observable returned to out() is the post-sort receiver length (a
number) for the conv_, keep_ and pre_ families, chosen because it is
deterministic and engine-independent under a mutating sort (the element
order a comparator that returns 0 leaves is not); for the ctl_ family it
is the joined elements (the sort order itself is the observable there).
The two large-length rows are conv_len_big / conv_idx_big and pre_*; the
32768/32769/32767 rows are the threshold boundary.  Every other row uses
a two-element array.

The dataset PoC (/testcase/poc.js, run as the extra case "poc" by
scripts/njs_cases.py) is the conv_idx_big shape with object elements and
`*=`; it prints nothing and is expected to end without a sanitizer report.
"""
import sys
from pathlib import Path

PRELUDE = r"""
function show(v) { return typeof v + ':' + String(v); }
function out(f) { var r; try { r = show(f()); } catch (e) { r = 'E:' + e.name; } console.log(r); }
"""

# case -> (family, how, slow_at_writeback, viol, absent, body)
# body is the JavaScript that builds the receiver, sorts it and returns the
# observable; it runs inside out(function() { <body> }).
CASES = {}


def add(name, family, how, slow, viol, body):
    CASES[name] = (family, how, slow, viol, "conv" if viol else "none", body)


# conv_*: the comparator converts the fast array to a slow array.
add("conv_len_big", "conv", "a.length=65535", 1, 1,
    "var a=[2,1]; a.sort(function(x,y){ a.length=65535; return 0; }); return a.length;")
add("conv_idx_big", "conv", "a[65535]=9", 1, 1,
    "var a=[2,1]; a.sort(function(x,y){ a[65535]=9; return 0; }); return a.length;")
add("conv_len_edge", "conv", "a.length=32769", 1, 1,
    "var a=[2,1]; a.sort(function(x,y){ a.length=32769; return 0; }); return a.length;")
add("conv_idx_edge", "conv", "a[32768]=9", 1, 1,
    "var a=[2,1]; a.sort(function(x,y){ a[32768]=9; return 0; }); return a.length;")

# keep_*: the comparator mutates but the array stays fast.
add("keep_set0", "keep", "a[0]=9", 0, 0,
    "var a=[2,1]; a.sort(function(x,y){ a[0]=9; return 0; }); return a.length;")
add("keep_len_edge", "keep", "a.length=32768", 0, 0,
    "var a=[2,1]; a.sort(function(x,y){ a.length=32768; return 0; }); return a.length;")
add("keep_idx_edge", "keep", "a[32767]=9", 0, 0,
    "var a=[2,1]; a.sort(function(x,y){ a[32767]=9; return 0; }); return a.length;")

# pre_*: the array is slow before the sort (fast_path is 0 at read-in).
add("pre_len", "pre", "pre a.length=65535", 1, 0,
    "var a=[2,1]; a.length=65535; a.sort(function(x,y){ return 0; }); return a.length;")
add("pre_idx", "pre", "pre a[65535]=9", 1, 0,
    "var a=[2,1]; a[65535]=9; a.sort(function(x,y){ return 0; }); return a.length;")

# ctl_*: no comparator or no mutation.
add("ctl_nocmp", "ctl", "none", 0, 0,
    "var a=[3,1,2]; a.sort(); return a.join(',');")
add("ctl_cmp", "ctl", "none", 0, 0,
    "var a=[3,1,2]; a.sort(function(x,y){ return x-y; }); return a.join(',');")
add("ctl_like", "ctl", "none", 0, 0,
    "var o={0:2,1:1,length:2}; Array.prototype.sort.call(o, function(x,y){ return x-y; }); "
    "return o[0]+','+o[1];")


def main(outdir):
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    rows = ["\t".join(["case", "family", "how", "slow", "viol", "absent"])]
    for name in sorted(CASES):
        family, how, slow, viol, absent, body = CASES[name]
        (out / (name + ".js")).write_text(PRELUDE + "out(function() { " + body + " });\n")
        rows.append("\t".join([name, family, how, str(slow), str(viol), absent]))
    (out / "cases.tsv").write_text("\n".join(rows) + "\n")
    print(f"{len(CASES)} cases written to {outdir}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python3 sortconv_cases.py OUTDIR")
    main(sys.argv[1])
