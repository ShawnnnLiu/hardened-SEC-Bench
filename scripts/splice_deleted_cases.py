"""Write the JavaScript case files for njs.cve-2022-29779 (the array of
deleted elements that Array.prototype.splice returns).

Usage: python3 splice_deleted_cases.py OUTDIR

Writes OUTDIR/<case>.js and OUTDIR/cases.tsv with the columns case, group,
container, pattern, window, consumer, n, absent, faulty. Each script defines
the printers below, builds the `this` object of a splice call from a
container recipe, calls Array.prototype.splice on it and prints one line, so
that njs and the reference engine print the same text for the same call.
The expected output is the reference engine's output on the same file
(scripts/njs_cases.py --oracle).

njs_array_prototype_splice() at the base commit (f65981b0) allocates the
array of deleted elements with njs_array_alloc(vm, 0, delete, 0), which is a
flat (fast) array when delete <= 32768 and does not write its slots. When
`this` is not a fast array it copies each element with
njs_value_property_i64() and stores it only when the property exists
(NJS_OK); for an absent property (NJS_DECLINED) it leaves the slot of the
fast array unwritten, so the returned array holds raw memory where the
reference holds a hole. The developer patch writes the absent-element marker
into the slot in that case. The state of the note is the unwritten slot of a
fast array.

Groups (case <group>_<container>_<pattern>_<window>[_<consumer>]):
  splice    splice on a `this` that is not a fast array (or is, as control):
            containers like (array-like object), lenback (a slow array whose
            length was raised above 32768 and lowered again), args (an
            arguments object after deletes), fastholes (a fast array with
            holes, control), fast (dense fast array, control), ta (a
            zero-length Uint8Array whose prototype is an array of n elements,
            the shape of the dataset PoC); three elements with gap patterns
            none, first, mid, last, all, and the windows w0 (splice(0)), w02
            (splice(0, 2)) and w11 (splice(1, 1))
  consumer  the result of a faulty call read in other ways (JSON.stringify,
            join, Object.keys, length only, concat)
  size      deleted counts 1, 100, 1000, 32768 (the largest fast array of
            deleted elements) and 32769 (the smallest slow one)
  bt        the result stored as a property of a builtin and a native
            function that throws, so that the backtrace builder traverses
            the builtins (the way the dataset PoC reads the array)
  nbr       other Array builtins on a `this` with gaps (a search for the same
            state elsewhere): slice, concat, map, filter, join, indexOf,
            forEach, reduce, reverse, sort, fill, copyWithin
  reent     the delete count is an object whose valueOf shortens `this` before the
            deleted window is read (another defect of the same function)
  valid     calls that reach no gap: insertions, deletions, replacements,
            negative and overflowing arguments on fast arrays and on
            array-likes without gaps

Column absent is "none" for the valid group, else the group name. Column
faulty is 1 when the call leaves a fast array of deleted elements with an
unwritten slot on the base build (a `this` that is not a fast array, a gap
inside the deleted window, and a deleted count of 32768 or less).
Syntax is limited to what njs at the base commit parses (the parser accepts
but ignores a spread argument, so none is used).
"""
import sys
from pathlib import Path

PRELUDE = r"""
function show(v) {
    if (v === undefined) return 'undef';
    if (v === null) return 'null';
    if (typeof v === 'object') {
        if (Array.isArray(v)) {
            var s = [];
            for (var i = 0; i < v.length && i < 8; i++) s.push((i in v) ? show(v[i]) : 'hole');
            return '[' + s.join(',') + ']len' + v.length;
        }
        var ks = Object.keys(v).sort(), t = [];
        for (var j = 0; j < ks.length; j++) t.push(ks[j] + '=' + show(v[ks[j]]));
        return 'obj:{' + t.join(',') + '}';
    }
    if (typeof v === 'string') return 'string:' + JSON.stringify(v);
    return typeof v + ':' + String(v);
}
function out(f) {
    try { console.log(f()); } catch (e) { console.log('EXC ' + e.name); }
}
"""

GAPS = {"none": [], "first": [0], "mid": [1], "last": [2], "all": [0, 1, 2]}
WINDOWS = {"w0": (0, None), "w02": (0, 2), "w11": (1, 1)}
LIMIT = 32768


def elem(i):
    return "'e%d'" % i


def container(kind, n, gaps):
    """JavaScript expression of the `this` object."""
    present = [i for i in range(n) if i not in gaps]
    if kind == "like":
        props = ", ".join("%d: %s" % (i, elem(i)) for i in present)
        return "{length: %d%s}" % (n, (", " + props) if props else "")
    if kind == "lenback":
        sets = " ".join("a[%d] = %s;" % (i, elem(i)) for i in present)
        return ("(function() { var a = []; %s a.length = 40000; a.length = %d; return a; })()" % (sets, n))
    if kind == "args":
        dels = " ".join("delete arguments[%d];" % i for i in gaps)
        return ("(function() { %s return arguments; })(%s)" % (dels, ", ".join(elem(i) for i in range(n))))
    if kind == "fastholes":
        items = [elem(i) if i in present else "" for i in range(n)]
        return "[" + ",".join(items) + (",]" if (n - 1) in gaps else "]")
    if kind == "fast":
        return "[" + ",".join(elem(i) for i in range(n)) + "]"
    raise AssertionError(kind)


def call(this_expr, window):
    start, count = WINDOWS[window]
    if count is None:
        return "Array.prototype.splice.call(%s, %d)" % (this_expr, start)
    return "Array.prototype.splice.call(%s, %d, %d)" % (this_expr, start, count)


def faulty(kind, gaps, window, n=3):
    if kind in ("fast", "fastholes"):
        return 0
    start, count = WINDOWS[window]
    end = n if count is None else start + count
    return int(any(start <= g < end for g in gaps))


def mk(name, group, cont, pattern, window, consumer, n, body, faulty_flag):
    return dict(name=name, group=group, container=cont, pattern=pattern, window=window, consumer=consumer,
                n=n, faulty=faulty_flag, absent="none" if group == "valid" else group, body=body)


def ta_this(n):
    return "(function() { var t = new Uint8Array(0); var p = []; p.length = %d; t.__proto__ = p; return t; })()" % n


CONSUMERS = {
    "show": "show(r)",
    "json": "JSON.stringify(r)",
    "join": "show(r.join('-'))",
    "keys": "show(Object.keys(r))",
    "len": "show(r.length)",
    "concat": "show([0].concat(r))",
}


def cases():
    out = []
    # splice: three elements, gap patterns and windows
    for cont in ["like", "lenback", "args", "fastholes"]:
        for pat, gaps in GAPS.items():
            for win in WINDOWS:
                this = container(cont, 3, gaps)
                body = "out(function() { var r = %s; return show(r); });" % call(this, win)
                out.append(mk(f"splice_{cont}_{pat}_{win}", "splice", cont, pat, win, "show", 3, body,
                              faulty(cont, gaps, win)))
    for win in WINDOWS:
        body = "out(function() { var r = %s; return show(r); });" % call(container("fast", 3, []), win)
        out.append(mk(f"splice_fast_none_{win}", "splice", "fast", "none", win, "show", 3, body, 0))
    for n in [1, 3, 10, 100]:
        body = "out(function() { var r = %s; return show(r); });" % call(ta_this(n), "w0")
        out.append(mk(f"splice_ta_all_n{n}", "splice", "ta", "all", "w0", "show", n, body, 1))
    # consumer: a faulty result read in other ways
    for cont, this in [("like", container("like", 3, [1])), ("ta", ta_this(3))]:
        for cons in ["json", "join", "keys", "len", "concat"]:
            body = "out(function() { var r = %s; return %s; });" % (call(this, "w0"), CONSUMERS[cons])
            out.append(mk(f"consumer_{cont}_{cons}", "consumer", cont, "mid" if cont == "like" else "all", "w0",
                          cons, 3, body, 1))
    # size: deleted counts around the fast limit
    for n in [1, 100, 1000, 32768, 32769]:
        body = "out(function() { var r = %s; return show(r); });" % call("{length: %d}" % n, "w0")
        out.append(mk(f"size_like_n{n}", "size", "like", "all", "w0", "show", n, body, int(n <= LIMIT)))
    for n in [32768, 32769]:
        body = "out(function() { var r = %s; return show(r); });" % call(ta_this(n), "w0")
        out.append(mk(f"size_ta_n{n}", "size", "ta", "all", "w0", "show", n, body, int(n <= LIMIT)))
    # bt: the result reachable from a builtin while a native function throws
    bt_tail = "Promise.valueOf = r; try { Array(0x20000000000000); } catch (e) { return 'EXC ' + e.name; } return 'no error';"
    for name, cont, this, fl in [
        ("ta_n1", "ta", ta_this(1), 1), ("ta_n3", "ta", ta_this(3), 1),
        ("like_all", "like", container("like", 3, [0, 1, 2]), 1), ("lenback_all", "lenback", container("lenback", 3, [0, 1, 2]), 1),
        ("fastholes_all", "fastholes", container("fastholes", 3, [0, 1, 2]), 0), ("fast_none", "fast", container("fast", 3, []), 0),
    ]:
        body = "out(function() { var r = %s; %s });" % (call(this, "w0"), bt_tail)
        out.append(mk(f"bt_{name}", "bt", cont, "all", "w0", "backtrace", 3, body, fl))
    # nbr: other builtins on a `this` with a gap
    ops = {
        "slice": "show(Array.prototype.slice.call(T, 0))",
        "concat": "show(Array.prototype.concat.call(T, [9]))",
        "map": "show(Array.prototype.map.call(T, function(x) { return x; }))",
        "filter": "show(Array.prototype.filter.call(T, function(x) { return true; }))",
        "join": "show(Array.prototype.join.call(T, '-'))",
        "indexof": "show(Array.prototype.indexOf.call(T, 'e2'))",
        "foreach": "(function() { var c = 0; Array.prototype.forEach.call(T, function() { c++; }); return show(c); })()",
        "reduce": "show(Array.prototype.reduce.call(T, function(p, x) { return p + x; }, ''))",
        "reverse": "show(Array.prototype.reverse.call(T))",
        "sort": "show(Array.prototype.sort.call(T))",
        "fill": "show(Array.prototype.fill.call(T, 'f', 0, 2))",
        "copywithin": "show(Array.prototype.copyWithin.call(T, 0, 1, 2))",
    }
    readonly = ["slice", "concat", "map", "filter", "join", "indexof", "foreach", "reduce"]
    for cont, this in [("like", container("like", 3, [1])), ("lenback", container("lenback", 3, [1])),
                       ("ta", ta_this(3))]:
        for op, expr in ops.items():
            if cont == "ta" and op not in readonly:
                continue
            body = "out(function() { var T = %s; return %s; });" % (this, expr)
            out.append(mk(f"nbr_{cont}_{op}", "nbr", cont, "mid" if cont != "ta" else "all", "-", op, 3, body, 0))
    # reent: the delete count converts with a side effect that shrinks `this` (a different defect of the
    # same function, fixed upstream by 607de2bd): the deleted window is read after `this` became shorter
    for name, init, shrink, ret in [("shrink0", "['x']", 0, 10), ("shrink2", "['a','b','c']", 2, 3),
                                    ("shrink1", "['a','b','c','d','e']", 1, 5)]:
        body = ("out(function() { var a = %s; var r = a.splice(0, {valueOf: function() { a.length = %d; return %d; }}); "
                "return show(r) + ' ' + show(a); });" % (init, shrink, ret))
        out.append(mk(f"reent_{name}", "reent", "fast", "-", "w0", "show", 3, body, 0))
    # valid: calls that reach no gap
    valid = [
        ("fast_insert", "[1,2,3]", "splice(1, 0, 'x', 'y')"),
        ("fast_delete", "[1,2,3,4]", "splice(1, 2)"),
        ("fast_replace", "[1,2,3]", "splice(0, 1, 'a')"),
        ("fast_negative", "[1,2,3,4]", "splice(-2, 1)"),
        ("fast_overflow", "[1,2,3]", "splice(10, 5)"),
        ("fast_count_big", "[1,2,3]", "splice(1, 100)"),
        ("fast_all", "[1,2,3]", "splice(0)"),
        ("fast_none_args", "[1,2,3]", "splice()"),
        ("fast_zero", "[1,2,3]", "splice(1, 0)"),
        ("fast_holes", "[1,,3,,5]", "splice(0)"),
        ("fast_empty", "[]", "splice(0)"),
        ("fast_single", "[7]", "splice(0, 1)"),
    ]
    for name, this, meth in valid:
        body = "out(function() { var a = %s; var r = a.%s; return show(r) + ' ' + show(a); });" % (this, meth)
        out.append(mk(f"valid_{name}", "valid", "fast", "none", "-", "show", 3, body, 0))
    for name, this, args in [
        ("like_all_present", "{length: 3, 0: 'a', 1: 'b', 2: 'c'}", "0"),
        ("like_all_present_w11", "{length: 3, 0: 'a', 1: 'b', 2: 'c'}", "1, 1"),
        ("like_insert", "{length: 2, 0: 'a', 1: 'b'}", "1, 0, 'x'"),
        ("like_empty", "{length: 0}", "0"),
        ("like_gap_outside", "{length: 3, 0: 'a', 2: 'c'}", "2, 1"),
        ("like_gap_zero_count", "{length: 3, 0: 'a', 2: 'c'}", "1, 0"),
    ]:
        body = "out(function() { var o = %s; var r = Array.prototype.splice.call(o, %s); return show(r); });" % (this, args)
        out.append(mk(f"valid_{name}", "valid", "like", "none", "-", "show", 3, body, 0))
    out.append(mk("valid_lenback_all_present", "valid", "lenback", "none", "-", "show", 3,
                  "out(function() { var r = %s; return show(r); });" % call(container("lenback", 3, []), "w0"), 0))
    out.append(mk("valid_args_all_present", "valid", "args", "none", "-", "show", 3,
                  "out(function() { var r = %s; return show(r); });" % call(container("args", 3, []), "w0"), 0))
    return out


def main(outdir):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    cs = cases()
    names = [c["name"] for c in cs]
    assert len(names) == len(set(names)), "duplicate case names"
    cols = ["name", "group", "container", "pattern", "window", "consumer", "n", "absent", "faulty"]
    with open(outdir / "cases.tsv", "w") as f:
        f.write("case\tgroup\tcontainer\tpattern\twindow\tconsumer\tn\tabsent\tfaulty\n")
        for c in cs:
            f.write("\t".join(str(c[k]) for k in cols) + "\n")
    for c in cs:
        (outdir / (c["name"] + ".js")).write_text(PRELUDE + c["body"] + "\n")
    print(len(cs), "cases")


if __name__ == "__main__":
    main(sys.argv[1])
