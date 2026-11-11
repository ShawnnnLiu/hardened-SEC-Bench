"""Write the JavaScript case files for njs.cve-2022-31307 (a negative start
index reaches njs_string_offset() in the reverse iteration of a UTF-8 string).

Usage: python3 negfrom_cases.py OUTDIR

Writes OUTDIR/<case>.js and OUTDIR/cases.tsv with the columns case,
family, recv, str, n, from_ (the start index the reverse iteration
receives, "na" when the case does not use it), viol (1 when the case
reaches the faulty state: a UTF-8 string with from < 0), absent (the
column name is only the key that scripts/njs_cases.py uses for its
valid-output digest: "none" for a case that does not reach the faulty
state, "neg" for one that does).
Each script defines a printer (strings are printed as their length and
code units, so njs and the reference engine print the same text for the
same value; an exception is printed as its name) and prints one line.
The expected output of each case is the reference engine's output on the
same file (scripts/njs_cases.py --oracle).

Mechanism under test (src/njs_iterator.c at the base commit): the
Array.prototype.lastIndexOf() and reduceRight() builtins call
njs_object_iterate_reverse(vm, args, handler) with from = the start index
and to = 0. For a UTF-8 string (length != size in bytes) the function
computes the byte pointer of element `from` with njs_string_offset(start,
end, from) before it knows whether the loop `i = from + 1; while (i-- >
to)` runs. njs_string_offset() takes a size_t index and "assumes that
index is correct" (src/njs_string.c); a negative `from` becomes a huge
size_t, `map[index / 32 - 1]` is read far outside the string, and the
skip loop adds the value it read to the start pointer. lastIndexOf()
yields a negative `from` when fromIndex < -length; reduceRight() uses
from = length - 1, which is negative only for an empty string (an ASCII
string, another branch).

Families (case name prefix):
  lio_<recv>_<str>_<x>   Array.prototype.lastIndexOf(T, X) on a UTF-8 string
      recv: prim (string primitive as this, .call), obj (new String(s)),
            proto (the dataset PoC shape: a String object whose prototype
            is set to an array, then o.lastIndexOf(T, X))
      str:  u1 (1 character, 2 bytes), u3 (3 characters of 2, 3 and 2
            bytes), u33 (33 characters, so that njs_string_offset() uses
            its offset map)
      x:    v<k>   from = -k (k = 1, 2, 31, 32, 33, 100, 1000, 10^6, 2^31,
                   2^53), reaching the faulty state; inf: fromIndex =
                   -Infinity
            neg_n, neg_1, zero, last, len, beyond, pinf, nan, undef, null
                   fromIndex = -n, -1, 0, n-1, n, n+5, Infinity, NaN,
                   undefined, null; from is 0, n-1, 0, n-1, n-1, n-1,
                   n-1, 0, 0, 0 and the case does not reach the faulty state
            cstr, cobj, cflt   a fromIndex that is a string, an object with
                   valueOf, a fractional number, each giving from = -3
  rr_<recv>_<str>        reduceRight over a UTF-8 string (from = length - 1)
  ctl_*                  ASCII strings, arrays and array-likes with the same
                         negative fromIndex values (other branches of the
                         iteration)
  d_<method>_<str>_<v>   the other callers of njs_string_offset() reachable
                         from String.prototype and RegExp methods, called with
                         index values around the string length and far
                         outside it (the candidates for other ways to reach
                         an invalid index; the patch does not touch them)
  viol_poc_nospread      the dataset PoC without the call-site spread
                         (njs at the base commit passes `...x` as the single
                         argument x)

Excluded after the calibration run on the base build (cases that do not
reach the faulty state; scripts/negfrom_predictions.py lists the run):
  codePointAt(i) for an index outside the string: njs returns NaN, the
      reference returns undefined (a deviation unrelated to the invariant);
  endsWith(t, p) with a negative end position p: njs uses the length of the
      string, the reference clamps p to 0 (the index computed in
      njs_string_prototype_starts_or_ends_with() is inside the string);
  family x (x_replace_dollar_*): String.prototype.replace() with the
      templates $' and $` on a UTF-8 string uses a character offset as a
      byte offset on the base build (fixed upstream in 485b3657); the two
      cases are kept, are WRONG on every build and are not predicted.

The runs of this generator on the base build that precede the predictions
are listed in scripts/negfrom_predictions.py.

Syntax is limited to what njs at the base commit parses (no classes, no
template literals, no method shorthand).
"""
import sys
from pathlib import Path

PRELUDE = r"""
function codes(s) { var a = []; for (var i = 0; i < s.length; i++) a.push(s.charCodeAt(i)); return a.join(','); }
function show(v) { return typeof v === 'string' ? 'S' + v.length + ':' + codes(v) : typeof v + ':' + String(v); }
function out(f) { var r; try { r = show(f()); } catch (e) { r = 'E:' + e.name; } console.log(r); }
"""

# strings: name -> (JavaScript expression, length n, first char, last char)
BS = chr(92)  # backslash: the case files hold the characters as \u escapes, plain ASCII
F, E, V = BS + "u0424", BS + "u20ac", BS + "u0412"
STRS = {
    "u1": ('"%s"' % F, 1, F, F),
    "u3": ('"%s%s%s"' % (F, E, V), 3, F, V),
    "u33": ('"%s" + "%s".repeat(31) + "%s"' % (F, E, V), 33, F, V),
}
VIOL_K = [1, 2, 31, 32, 33, 100, 1000, 10**6, 2**31, 2**53]
VIOL_K_OTHER = [1, 2, 33, 1000, 2**31]      # for the obj and proto receivers


def xexpr(n, tok):
    """(fromIndex JavaScript text, from_) for a token and string length n."""
    if tok.startswith("v"):
        k = int(tok[1:])
        x = -(n + k) if k <= 10**6 else -k
        return str(x), x + n
    return {
        "inf": ("-Infinity", None),
        "neg_n": (str(-n), 0), "neg_1": ("-1", n - 1), "zero": ("0", 0),
        "last": (str(n - 1), n - 1), "len": (str(n), n - 1),
        "beyond": (str(n + 5), n - 1), "pinf": ("Infinity", n - 1),
        "nan": ("NaN", 0), "undef": ("undefined", 0), "null": ("null", 0),
        "cstr": ('"%d"' % -(n + 3), -3), "cobj": ("{valueOf: function() { return %d; }}" % -(n + 3), -3),
        "cflt": ("%d.5" % -(n + 3), -3),
    }[tok]


def call(recv, s, t, x):
    """JavaScript statements evaluating lastIndexOf(t, x) on string s."""
    if recv == "prim":
        return f"var s = {s};\nout(function() {{ return Array.prototype.lastIndexOf.call(s, {t}, {x}); }});\n"
    if recv == "obj":
        return f"var s = {s};\nout(function() {{ return Array.prototype.lastIndexOf.call(new String(s), {t}, {x}); }});\n"
    return (f"var s = {s};\nvar o = Object(s);\nObject.setPrototypeOf(o, [1, 2, 3]);\n"
            f"out(function() {{ return o.lastIndexOf({t}, {x}); }});\n")


def is_viol(from_):
    return from_ is None or from_ < 0


def lio_cases():
    for sname, (s, n, first, last) in STRS.items():
        t = f'"{first}"'
        for recv in ("prim", "obj", "proto"):
            ks = VIOL_K if recv == "prim" else VIOL_K_OTHER
            toks = [f"v{k}" for k in ks] + ["inf"]
            if recv == "prim":
                toks += ["neg_n", "neg_1", "zero", "last", "len", "beyond", "pinf", "nan", "undef", "null"]
                if sname != "u33":
                    toks += ["cstr", "cobj", "cflt"]
            else:
                toks += ["neg_n", "last", "pinf"]
            for tok in toks:
                x, from_ = xexpr(n, tok)
                body = call(recv, s, t, x)
                yield (f"lio_{recv}_{sname}_{tok}", "lio", recv, sname, n, from_, body)
                if recv == "prim" and tok in ("neg_n", "last", "len", "pinf"):
                    # same indices with the last character as the search term
                    yield (f"lio_{recv}_{sname}_{tok}_tl", "lio", recv, sname, n, from_,
                           call(recv, s, f'"{last}"', x))
    yield ("viol_poc_nospread", "lio", "proto", "u1", 1, -999999999,
           'function main() {\n    const a4 = String.fromCodePoint(6631);\n    const a7 = Object(a4);\n'
           '    const a9 = [65537, a7, "c"];\n    const a10 = Object.setPrototypeOf(a7, a9);\n'
           '    out(function() { return a10.lastIndexOf(a4, -1000000000.0); });\n}\nmain();\n')


def rr_cases():
    for sname, (s, n, first, last) in STRS.items():
        for recv in ("prim", "obj", "proto"):
            if recv == "prim":
                recv_expr = "s"
            elif recv == "obj":
                recv_expr = "new String(s)"
            else:
                recv_expr = "o"
            pre = f"var s = {s};\n"
            if recv == "proto":
                pre += "var o = Object(s);\nObject.setPrototypeOf(o, [1, 2, 3]);\n"
            if recv == "proto":
                body = pre + "out(function() { return Array.prototype.reduceRight.call(o, function(a, c) { return a + c; }, ''); });\n"
            else:
                body = pre + f"out(function() {{ return Array.prototype.reduceRight.call({recv_expr}, function(a, c) {{ return a + c; }}, ''); }});\n"
            yield (f"rr_{recv}_{sname}", "rr", recv, sname, n, None, body)
        yield (f"rr_noinit_{sname}", "rr", "prim", sname, n, None,
               f"var s = {s};\nout(function() {{ return Array.prototype.reduceRight.call(s, function(a, c) {{ return a + c; }}); }});\n")
    yield ("rr_empty_init", "rr", "prim", "empty", 0, None,
           "out(function() { return Array.prototype.reduceRight.call('', function(a, c) { return a + c; }, 'init'); });\n")
    yield ("rr_empty_noinit", "rr", "prim", "empty", 0, None,
           "out(function() { return Array.prototype.reduceRight.call('', function(a, c) { return a + c; }); });\n")
    yield ("rr_ascii", "rr", "prim", "ascii", 4, None,
           "out(function() { return Array.prototype.reduceRight.call('abcd', function(a, c) { return a + c; }, ''); });\n")


def ctl_cases():
    for name, recv_js, n in (("ascii", "'abcd'", 4), ("arr", "['%s', '%s']" % (F, V), 2),
                             ("arrlike", "{length: 2, 0: '%s', 1: '%s'}" % (F, V), 2)):
        toks = ["v1", "v100", "inf", "zero", "last"] if name != "arrlike" else ["v1", "inf", "last"]
        for tok in toks:
            x, from_ = xexpr(n, tok)
            body = f"out(function() {{ return Array.prototype.lastIndexOf.call({recv_js}, '{F}', {x}); }});\n"
            yield (f"ctl_{name}_{tok}", "ctl", "prim", name, n, None, body)


D_V = [("m1e9", "-1000000000"), ("m1", "-1"), ("n", "{n}"), ("n1", "{n1}"), ("big", "4294967297"),
       ("pinf", "Infinity"), ("ninf", "-Infinity"), ("nan", "NaN")]
D_EXPR = [
    ("indexOf", "s.indexOf({T}, {V})"), ("lastIndexOf", "s.lastIndexOf({T}, {V})"), ("includes", "s.includes({T}, {V})"),
    ("startsWith", "s.startsWith({T}, {V})"), ("endsWith", "s.endsWith({T}, {V})"),
    ("charAt", "s.charAt({V})"), ("charCodeAt", "s.charCodeAt({V})"),
    ("slice1", "s.slice({V})"), ("slice2", "s.slice(0, {V})"), ("substring1", "s.substring({V})"),
    ("substring2", "s.substring(0, {V})"), ("substr1", "s.substr({V})"), ("substr2", "s.substr(0, {V})"),
]
D_EXPR33 = ("indexOf", "lastIndexOf", "includes", "startsWith", "endsWith", "slice1", "substring1")


def d_cases():
    for sname in ("u3", "u33"):
        s, n, first, last = STRS[sname]
        for mname, expr in D_EXPR:
            if sname == "u33" and mname not in D_EXPR33:
                continue
            for vname, v in D_V:
                if sname == "u33" and vname not in ("m1", "n", "n1", "pinf"):
                    continue
                if mname == "endsWith" and vname in ("m1e9", "m1", "ninf"):
                    continue    # excluded deviation: njs treats a negative end position as the length
                vv = v.format(n=n, n1=n + 1)
                e = expr.replace("{T}", f'"{last}"').replace("{V}", vv)
                body = f"var s = {s};\nout(function() {{ return {e}; }});\n"
                yield (f"d_{mname}_{sname}_{vname}", "d", "-", sname, n, None, body)
    s, n, first, last = STRS["u3"]
    mid = E
    others = [
        ("padStart", f"s.padStart(5, '{last}')"), ("padEnd", f"s.padEnd(5, '{first}{last}')"),
        ("replace_str", f"s.replace('{mid}', 'x')"),
        ("replace_dollar_amp", f"s.replace('{mid}', '$&$&')"),
        ("replace_re", f"s.replace(new RegExp('{mid}'), 'x')"), ("replace_re_g", f"s.replace(new RegExp('{mid}', 'g'), 'x')"),
        ("split_str", f"s.split('{mid}').length"), ("split_re", f"s.split(new RegExp('{mid}')).length"),
        ("match", f"s.match(new RegExp('{mid}')).index"), ("search", f"s.search(new RegExp('{last}'))"),
        ("json_gap", f"JSON.stringify([1], null, '{first}'.repeat(12))"),
        ("json_gap_short", f"JSON.stringify([1], null, '{first}{last}')"),
    ]
    for name, e in others:
        yield (f"d_{name}_u3", "d", "-", "u3", n, None, f"var s = {STRS['u3'][0]};\nout(function() {{ return {e}; }});\n")
    # known deviations of the base build that are unrelated to the invariant: the
    # replacement templates $' and $` use a character offset as a byte offset
    # (fixed upstream in 485b3657); both are WRONG on every build and are not predicted
    yield ("x_replace_dollar_tail_u3", "x", "-", "u3", n, None,
           f"var s = {STRS['u3'][0]};\nout(function() {{ return s.replace('{mid}', \"$'\"); }});\n")
    yield ("x_replace_dollar_head_u3", "x", "-", "u3", n, None,
           f"var s = {STRS['u3'][0]};\nout(function() {{ return s.replace('{mid}', '$`'); }});\n")
    for vname, v in D_V:
        vv = v.format(n=n, n1=n + 1)
        for kind in ("g", "y"):
            body = (f"var s = {STRS['u3'][0]};\nvar re = new RegExp('{mid}', '{kind}');\nre.lastIndex = {vv};\n"
                    f"out(function() {{ var m = re.exec(s); return (m === null ? 'null' : m.index) + ':' + re.lastIndex; }});\n")
            yield (f"d_exec_{kind}_u3_{vname}", "d", "-", "u3", n, None, body)


def main():
    outdir = Path(sys.argv[1])
    outdir.mkdir(parents=True, exist_ok=True)
    rows = ["case\tfamily\trecv\tstr\tn\tfrom_\tviol\tabsent"]
    seen = set()
    for gen in (lio_cases, rr_cases, ctl_cases, d_cases):
        for name, family, recv, sname, n, from_, body in gen():
            assert name not in seen, name
            seen.add(name)
            viol = int(family == "lio" and is_viol(from_))
            (outdir / f"{name}.js").write_text(PRELUDE.lstrip("\n") + body)
            rows.append(f"{name}\t{family}\t{recv}\t{sname}\t{n}\t{('na' if family != 'lio' else 'inf') if from_ is None else from_}\t{viol}\t{'neg' if viol else 'none'}")
    (outdir / "cases.tsv").write_text("\n".join(rows) + "\n")
    print(f"{len(rows) - 1} cases written to {outdir}")


if __name__ == "__main__":
    main()
