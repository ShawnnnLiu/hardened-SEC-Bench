"""Write the attribute case files for njs.cve-2022-31306 (the two unit
tests whose result differs between the developer patch and the root patch).
Usage: python3 recurdesc_attr_cases.py OUTDIR

The root patch (patches/njs.cve-2022-31306.root.diff) is a backport of
upstream 4ae2f2b8, which converts a fast array to a slow array at the top
of njs_object_prop_define(), before the property query. A side effect is
that Object.defineProperty() on a fast-array index now stores the
attributes of the descriptor; on the base build a fast-array element keeps
writable, enumerable and configurable true whatever the descriptor says.
Two unit tests at the base commit encode the base behaviour:
  - Object.getOwnPropertyNames(Object.defineProperty([], 'b', {}))
    expects "b,length" (4ae2f2b8 changes it to "length,b");
  - var a = [1, 2]; Object.defineProperty(a, '3', {}); njs.dump(a)
    expects "[1,2,<empty>,undefined]" (4ae2f2b8 keeps it by changing
    njs.dump to print non-enumerable array elements; the backport does not
    carry that change).
These cases restate both tests with standard output that a reference
engine also produces (property names, descriptors and keys instead of
njs.dump), plus upstream's own added test and a control whose result is
already correct at the base, so that the builds can be compared with
Node.js (scripts/njs_cases.py --oracle).
"""
import sys
from pathlib import Path

PRELUDE = r"""
function desc(o, k) { return JSON.stringify(Object.getOwnPropertyDescriptor(o, k)); }
function out(f) { var r; try { r = f(); } catch (e) { r = 'E:' + e.name; } console.log(r); }
"""


def cases():
    # unit test "var a = [1, 2]; Object.defineProperty(a, '3', {}); njs.dump(a)"
    yield ("attr_newidx_empty", "difftest",
           "out(function () { var a = [1, 2]; Object.defineProperty(a, '3', {});\n"
           "    return 'len' + a.length + ' has3 ' + (3 in a) + ' desc3 ' + desc(a, 3)\n"
           "           + ' keys ' + Object.keys(a).join(','); });\n")
    # unit test "Object.getOwnPropertyNames(Object.defineProperty([], 'b', {}))"
    yield ("attr_names_b", "difftest",
           "out(function () {\n"
           "    return Object.getOwnPropertyNames(Object.defineProperty([], 'b', {})).join(','); });\n")
    # test added by 4ae2f2b8: a new index defined with a value only
    yield ("attr_newidx_value", "upstream",
           "out(function () { var c = [0, 1, 2]; Object.defineProperty(c, 3, {value: 30});\n"
           "    return desc(c, 3); });\n")
    # control: an existing index made non-enumerable (already slow-array
    # path at the base; same result on every build)
    yield ("attr_existing_enum", "control",
           "out(function () { var e = [1, 2, 3]; Object.defineProperty(e, '1', {enumerable: false});\n"
           "    return desc(e, 1) + ' keys ' + Object.keys(e).join(','); });\n")


def main():
    outdir = Path(sys.argv[1])
    outdir.mkdir(parents=True, exist_ok=True)
    rows = ["case\tfamily\tabsent"]
    for name, fam, body in cases():
        (outdir / f"{name}.js").write_text(PRELUDE.lstrip("\n") + body)
        rows.append(f"{name}\t{fam}\tnone")
    (outdir / "cases.tsv").write_text("\n".join(rows) + "\n")
    print(f"{len(rows) - 1} cases written to {outdir}")


if __name__ == "__main__":
    main()
