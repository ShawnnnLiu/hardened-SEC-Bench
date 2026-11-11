"""Write the JavaScript case files for njs.cve-2022-28049 (large array
literals and the slow-array boundary of njs_array_alloc).

Usage: python3 arraylit_cases.py OUTDIR

Writes OUTDIR/<case>.js and OUTDIR/cases.tsv with the columns case,
shape, n, slow (whether the literal's size exceeds the fast-array
capacity), has_element (whether the literal has an actual element).
Each script builds the literal with `new Function('return ' + literal)()`
so a large literal needs no long source line, then prints one line with a
printer defined in the file (length, 0-in, last-in, a[0], a[last], the
number of own enumerable indices), so njs and the reference engine print
the same text for the same array. scripts/njs_cases.py keys its
valid-output digest on a column named absent, which these cases do not
have, so that digest stays constant (empty); the per-case OK
classification over the fast and control cases is the corpus check here. The expected output is the reference
engine's output on the same file (scripts/njs_cases.py --oracle).

njs_array_alloc(vm, flat=0, length, spare=8) returns a flat (fast) array
when length + 8 <= NJS_ARRAY_LARGE_OBJECT_LENGTH (32768), that is length
<= 32760, and a slow array (start NULL) otherwise. Two array-literal
instructions assume a flat array:
- NJS_VMCODE_ARRAY with ctor set (a literal with a trailing hole or a
  leading element before holes, e.g. [,,], [1,,]) fills every slot with
  the absent-element marker through array->start; on a slow array this
  writes through NULL (the CVE crash, njs_vmcode.c:1062 after the base
  checkout, :1049 in the reporter's tree);
- NJS_VMCODE_PROPERTY_INIT writes each element to array->start[index]; on
  a slow array the element value is lost (the array keeps its length but
  the indexed value reads undefined), without a crash.
The developer patch guards only the first with a fast_array check.

Shapes (case <shape>_<n>):
  elision   [ ,-repeated n ]            pure elision, ctor, no element
  ctorlead  [ 1, ,-repeated n ]         leading element then holes, ctor
  element   [ (1,)-repeated n 1 ]       n+1 elements, no hole, not ctor
  tailval   [ ,-repeated n 1 ]          n holes then a value, not ctor
  mixed     [ 1, , repeated to n ]      alternating value and hole
Sizes n: 3 (tiny, fast), 32760 (largest fast), 32761 (smallest slow),
40348 (the PoC elision count), 65536 (the developer test count).
Controls (no large array-literal allocation): a small dense array, a
small elision array, Array(n) (the constructor, not a literal), and the
dataset PoC shape ([ ,-repeated 40348 ] >> []).

Syntax is limited to what njs at the base commit parses.
"""
import sys
from pathlib import Path

PRELUDE = r"""
function brief(a) {
    if (!Array.isArray(a)) return typeof a + ':' + String(a);
    var last = a.length - 1;
    var keys = 0; for (var k in a) { if (a.hasOwnProperty(k) && String(+k) === k) keys++; }
    function slot(i) { return (i in a) ? ('v:' + a[i]) : 'hole'; }
    return 'len=' + a.length + ' first=' + slot(0) + ' last=' + slot(last) + ' keys=' + keys;
}
function out(s) { console.log(s); }
function build(src) {
    try { return (new Function('return ' + src))(); }
    catch (e) { return e.name + ':' + e.message.slice(0, 40); }
}
"""

SIZES = [3, 32760, 32761, 40348, 65536]


def literal(shape, n):
    if shape == "elision":
        return "[" + "," * n + "]"
    if shape == "ctorlead":
        return "[1" + "," * n + "]"
    if shape == "element":
        return "[" + "1,".ljust(0).join([]) + "1," * n + "1]"
    if shape == "tailval":
        return "[" + "," * n + "1]"
    if shape == "mixed":
        return "[" + "1,," * (n // 2) + "1]"
    raise AssertionError(shape)


def is_ctor(shape):
    # ctor is set for a literal whose last element position is a hole, or a
    # leading value before holes; element and tailval end with a value.
    return shape in ("elision", "ctorlead")


def has_element(shape):
    return shape != "elision"


def approx_length(shape, n):
    # the number of elements of the built literal (used only to decide slow);
    # exact for elision/ctorlead/element/tailval, an upper bound for mixed
    # (enough to classify the fast/slow boundary for the sizes used).
    if shape in ("element", "tailval"):
        return n + 1
    if shape == "mixed":
        return (n // 2) * 3 + 1
    return n


def cases():
    """Yields (case, shape, n, slow, has_element, body)."""
    for shape in ("elision", "ctorlead", "element", "tailval", "mixed"):
        for n in SIZES:
            length = approx_length(shape, n)
            slow = length + 8 > 32768
            lit = literal(shape, n)
            body = f"var a = build({lit!r}); out(brief(a));\n"
            yield (f"{shape}_{n}", shape, n, int(slow), int(has_element(shape)), body)
    # controls
    yield ("ctl_dense", "control", 3, 0, 1, "var a = [10, 20, 30]; out(brief(a));\n")
    yield ("ctl_elision3", "control", 3, 0, 0, "var a = [,,,]; out(brief(a));\n")
    yield ("ctl_ctor_big", "control", 40000, 1, 0,
           "var a = Array(40000); out(brief(a));\n")
    yield ("ctl_trailhole", "control", 1, 0, 1, "var a = [1,,]; out(brief(a));\n")
    # the dataset PoC shape: a large elision literal shifted by an array
    yield ("poc_shape", "elision", 40348, 1, 0,
           "var a = build('[' + ','.repeat(40348) + '] >> []'); out(typeof a + ':' + a);\n")


def main():
    outdir = Path(sys.argv[1])
    outdir.mkdir(parents=True, exist_ok=True)
    rows = ["case\tshape\tn\tslow\thas_element"]
    for name, shape, n, slow, he, body in cases():
        (outdir / f"{name}.js").write_text(PRELUDE.lstrip("\n") + body)
        rows.append(f"{name}\t{shape}\t{n}\t{slow}\t{he}")
    (outdir / "cases.tsv").write_text("\n".join(rows) + "\n")
    print(f"{len(rows) - 1} cases written to {outdir}")


if __name__ == "__main__":
    main()
