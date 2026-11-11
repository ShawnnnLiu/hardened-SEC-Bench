"""Write the JavaScript case files for njs.cve-2022-38890
(String.prototype.trimEnd()/trim() on a UTF-8 string whose trailing run is
all whitespace leaves the string value with a recorded length of 0 and a
nonzero byte size).

Usage: python3 trimzero_cases.py OUTDIR

Writes OUTDIR/<case>.js and OUTDIR/cases.tsv with the columns case,
family, prod (the producer under test: trimEnd, trim, trimStart, none),
kind (the input string kind: utf8ws all UTF-8 whitespace, utf8mix a UTF-8
string with a non-whitespace character, utf8nows a UTF-8 string with no
whitespace, ascii a byte/ASCII string, empty), cons (the consumer applied
to the producer's result), viol (1 when the case exercises the faulty
state: a UTF-8 input whose whole trailing run is whitespace reaches the
trim-end break without setting end), absent (the key scripts/njs_cases.py
uses for its valid-output digest: "none" for a case that does not reach
the faulty state, "z" for one that does).

Each script defines the same printer as scripts/negfrom_cases.py (a string
is printed as its length and its code units, so njs and the reference
engine print the same text for the same value; an exception as its name),
and prints one line. The expected output of each case is the reference
engine's output on the same file (scripts/njs_cases.py --oracle).

Invariant under test (src/njs_string.c, njs_string_trim() at the base
commit 6af74b6c). njs_string_prop stores a string value as (start, size,
length): size is the byte count and length is the UTF-8 character count,
with length == 0 standing for a byte string (size bytes, not decoded) when
size != 0 and for the empty string when size == 0 (src/njs_string.h). A
substring that njs_string_trim() returns must keep (length, size)
consistent with an actual sub-range of the input: when every character is
removed the result is the empty string, size == 0 and length == 0.

In the UTF-8 trim-end branch the loop walks back over the trailing
whitespace with prev = njs_utf8_prev(prev) and sets end = p only when it
meets a non-whitespace character. When the whole remaining run is
whitespace the loop instead leaves through `if (start == prev) break;`
without ever setting end, so end still points at the original string end.
The tail of the function then takes `start != end`, sets
string->size = end - start (the original byte size) and
string->length -= trim (which reaches 0), so the result is a byte string
of nonzero size and length 0 that holds the original whitespace bytes,
rather than the empty string. The developer patch adds `end = prev;` in
that break so that start == end holds and the empty-string path is taken.

The faulty state (length 0, size != 0 from a UTF-8 input) is not visible
through the recorded length alone, which is 0 for both the faulty byte
string and the correct empty string. The case families therefore apply
consumers that read the bytes behind the recorded length:

Families (case name prefix):
  tz_<kind>_<cons>     a producer (trimEnd by default) on a string of the
                       kind, then a consumer that can reveal the byte
                       string; the reference result is the consumer applied
                       to the empty string (or to the correctly trimmed
                       string for the mix/nows kinds)
  prod_<prod>_<kind>   trim and trimStart on the whitespace kinds, to show
                       which producers reach the patched branch (trim runs
                       trim-start then trim-end; trimStart does not reach
                       the patched branch)
  valid_<kind>_<cons>  mix, nows, ascii and empty inputs through the trim
                       producers and the same consumers (the patched branch
                       runs but takes the `end = p` exit, or another branch)
  poc                  the dataset PoC shape (a UTF-8 whitespace char,
                       trimEnd, padEnd, lastIndexOf), added by the runner
                       as the extra case

Consumers (cons), each a function of the producer's result r:
  val     show(r)                      length and code units of r
  eq      (r === "")                   whether r equals the empty string
  cc0     r.charCodeAt(0)              first unit (NaN for the empty string)
  cat     show("" + r + "x")          r concatenated with a non-empty string
  len2    ("a" + r).length            length after a non-empty prefix
  json    JSON.stringify(r)           the JSON encoding of r
  idx     r.indexOf("U+2028")        a search of r for the trimmed char
  slice   show(r.slice(0, 1))        a length-indexed slice of r
  pad     show(r.padEnd(3, "ab"))    r used as the padded base
  padw    show("ab".padEnd(5, r))    r used as the pad argument (the PoC
                                       uses the trimmed string as the pad)

Whitespace kinds are built from UTF-8 whitespace code points so that the
input is a UTF-8 string (length != size): U+00A0, U+1680, U+2000..U+200A,
U+2028, U+2029, U+202F, U+205F, U+3000, U+FEFF, and a mix of an ASCII
whitespace (U+0009, U+0020) with a UTF-8 whitespace (the shape of the
developer's added unit test). A long whitespace kind of 40 UTF-8
whitespace characters is included so that a consumer that indexes past
NJS_STRING_MAP_STRIDE (32) uses the offset map.

Excluded consumer (dropped 2026-10-28 after the first before/after run, as
njs.cve-2022-31307 excluded codePointAt): r.codePointAt(0). On the empty
string (the correct trim result after the patch) njs returns NaN where the
reference returns undefined, a pre-existing njs deviation on an
out-of-range codePointAt index that is unrelated to the trim invariant. It
was WRONG on both the base build (it read the faulty byte string's first
byte) and the developer-patch build (NaN on the empty result), so it does
not cleanly measure the trim fix. charCodeAt(0) is kept: it returns NaN on
the empty string in both engines, so it is clean after the patch and
reveals the byte on the base build.

The syntax is limited to what njs at the base commit parses; the printer
uses plain functions and the cases avoid template literals.
"""
import sys
from pathlib import Path

BS = chr(92)  # backslash; the case files hold the characters as \u escapes


def u(cp):
    return BS + "u%04X" % cp


PRELUDE = r"""
function codes(s) { var a = []; for (var i = 0; i < s.length; i++) a.push(s.charCodeAt(i)); return a.join(','); }
function show(v) {
    if (typeof v === 'string') { return 'S' + v.length + ':' + codes(v); }
    if (typeof v === 'number') { return 'number:' + String(v); }
    if (typeof v === 'boolean') { return 'boolean:' + String(v); }
    return typeof v + ':' + String(v);
}
function out(f) { var r; try { r = show(f()); } catch (e) { r = 'E:' + e.name; } console.log(r); }
"""

# UTF-8 whitespace code points (all multi-byte in UTF-8).
WS_CP = [0x00A0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005,
         0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029, 0x202F,
         0x205F, 0x3000, 0xFEFF]

# Whitespace input kinds: name -> JavaScript string expression. Each is a
# string all of whose trailing characters (from any start) are whitespace
# and which is a UTF-8 string (length != byte size).
WS_KINDS = {
    "nbsp": '"%s"' % u(0x00A0),
    "ogham": '"%s"' % u(0x1680),
    "ls": '"%s"' % u(0x2028),
    "ps": '"%s"' % u(0x2029),
    "bom": '"%s"' % u(0xFEFF),
    "ideo": '"%s"' % u(0x3000),
    "run3": '"%s%s%s"' % (u(0x2000), u(0x2001), u(0x2002)),
    "mix_sp_ls": '"%s%s"' % (u(0x0020), u(0x2028)),              # dev test case 2
    "mix_tab_sp_ls": '"%s%s%s"' % (u(0x0009), u(0x0020), u(0x2028)),  # dev test case 3
    "long40": '"%s".repeat(40)' % u(0x2028),
}

# Non-faulty UTF-8 and byte/ASCII input kinds (valid inputs through the
# patched lines and the other branches).
VALID_KINDS = {
    "mix_trail": '"%s%s%s"' % (u(0x03B1), u(0x03B2), u(0x2028)),   # alpha beta <LS>: trailing ws
    "mix_lead": '"%s%s%s"' % (u(0x2028), u(0x03B1), u(0x03B2)),    # <LS> alpha beta: leading ws only
    "mix_both": '"%s%s%s"' % (u(0x2028), u(0x03B1), u(0x2028)),    # ws around a non-ws char
    "nows": '"%s%s%s"' % (u(0x03B1), u(0x03B2), u(0x03B3)),        # UTF-8, no whitespace
    "ascii_ws": '"   "',                                          # ASCII spaces (ASCII branch)
    "ascii_mix": '"  ab  "',                                      # ASCII spaces around ab
    "empty": '""',
}

# Consumers: name -> a JavaScript expression in terms of r, the producer
# result. The expression returns the raw value; out() renders it once with
# show(), so a string result is printed as its length and code units.
CONS = {
    "val": "r",
    "eq": "r === %s" % ('""',),
    "cc0": "r.charCodeAt(0)",
    "cat": '"" + r + "x"',
    "len2": '("a" + r).length',
    "json": "JSON.stringify(r)",
    "idx": 'r.indexOf("%s")' % u(0x2028),
    "slice": "r.slice(0, 1)",
    "pad": 'r.padEnd(3, "ab")',
    "padw": '"ab".padEnd(5, r)',
}

PROD_EXPR = {
    "trimEnd": "s.trimEnd()",
    "trim": "s.trim()",
    "trimStart": "s.trimStart()",
}


def body(sexpr, prod_expr, cons_expr):
    return ("var s = %s;\nvar r = %s;\nout(function() { return %s; });\n"
            % (sexpr, prod_expr, cons_expr))


def gen():
    # tz_: trimEnd on each whitespace kind, every consumer (the faulty set).
    for kind, sexpr in WS_KINDS.items():
        for cons, cexpr in CONS.items():
            yield ("tz_%s_%s" % (kind, cons), "tz", "trimEnd", kind, cons, 1,
                   body(sexpr, "s.trimEnd()", cexpr))
    # prod_: trim and trimStart on the whitespace kinds, over the revealing
    # consumers, to show which producers reach the faulty state. Neither is
    # faulty for an all-whitespace input: trim() runs trim-start first, which
    # advances start to end so the trim-end break already has start == end,
    # and trimStart() never enters the trim-end branch. Only trimEnd() (no
    # prior trim-start) reaches `if (start == prev) break;` with end still at
    # the original end. viol = 0 for both; a non-OK result here on the base
    # build would widen the faulty producer set.
    prod_cons = ["val", "eq", "cc0", "len2", "padw"]
    for kind, sexpr in WS_KINDS.items():
        for cons in prod_cons:
            yield ("prod_trim_%s_%s" % (kind, cons), "prod", "trim", kind, cons, 0,
                   body(sexpr, "s.trim()", CONS[cons]))
            yield ("prod_trimStart_%s_%s" % (kind, cons), "prod", "trimStart", kind, cons, 0,
                   body(sexpr, "s.trimStart()", CONS[cons]))
    # valid_: mix/nows/ascii/empty through each producer and a few consumers.
    valid_cons = ["val", "eq", "cc0", "cat", "len2", "slice", "pad"]
    for kind, sexpr in VALID_KINDS.items():
        for prod, pexpr in PROD_EXPR.items():
            for cons in valid_cons:
                yield ("valid_%s_%s_%s" % (kind, prod, cons), "valid", prod, kind, cons, 0,
                       body(sexpr, pexpr, CONS[cons]))


def main():
    outdir = Path(sys.argv[1])
    outdir.mkdir(parents=True, exist_ok=True)
    rows = ["case\tfamily\tprod\tkind\tcons\tviol\tabsent"]
    seen = set()
    for name, family, prod, kind, cons, viol, b in gen():
        assert name not in seen, name
        seen.add(name)
        (outdir / ("%s.js" % name)).write_text(PRELUDE.lstrip("\n") + b)
        rows.append("%s\t%s\t%s\t%s\t%s\t%d\t%s"
                    % (name, family, prod, kind, cons, viol, "z" if viol else "none"))
    (outdir / "cases.tsv").write_text("\n".join(rows) + "\n")
    print("%d cases written to %s" % (len(rows) - 1, outdir))


if __name__ == "__main__":
    main()
