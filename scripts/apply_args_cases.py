"""Write the JavaScript case files for njs.cve-2021-46462 (the argument
vector that Function.prototype.apply builds from an array).

Usage: python3 apply_args_cases.py OUTDIR

Writes OUTDIR/<case>.js and OUTDIR/cases.tsv with the columns case, group,
container, callee, n, absent, slow, holes. Each script defines the printers
below, builds the second argument of apply from a container recipe, calls a
callee through apply and prints one line, so that njs and the reference
engine print the same text for the same call. The expected output is the
reference engine's output on the same file (scripts/njs_cases.py --oracle).

njs_function_prototype_apply() at the base commit (6a40a85f) takes
`args = arr->start; length = arr->length` for any array second argument.
Those two fields describe the element storage only for a flat (fast) array.
An array that was converted to a slow array has start == NULL and keeps its
old element count in length (njs_array_convert_to_slow_array() does not reset
it). njs_function_frame() then copies nothing for args == NULL, so the
callee frame holds `length` argument slots that were never written: a lambda
callee sees them as undefined (the frame initialises them to the absent
marker), a native callee reads uninitialised frame memory. A fast array with
holes passes the absent marker (NJS_INVALID) as an argument.
Conversions to a slow array (src/njs_array.c, njs_object.c, njs_object_prop.c,
njs_value.c): Object.freeze() and Object.seal() (all elements), Object.defineProperty()
of a non-default attribute or an accessor on an element, setting an index of
32768 or more, setting length above 32768. The developer patch removes the
array shortcut (the generic njs_object_length / [[Get]] path serves every
array) and adds a limit of 1024 on the argument count.

Groups (case <group>_<container>_<callee>[_<n>]):
  slow   n = 3 unless named: containers freeze, seal, defenum, defro, defget,
         lenback (length raised above 32768 and lowered again: a slow array
         with its own 3 elements), freeze256, freeze1024, freezeempty
  hole   fast arrays with holes (lead, mid, trail, all), Array(3), and a fast
         array lengthened to 100
  limit  argument counts around the developer patch's limit of 1024 and the
         engine's own stack limit (lambda frame about 48 bytes per argument,
         native frame 16 bytes, NJS_MAX_STACK_SIZE 256 KiB): containers flatn
         (dense), like ({length: N}), lenset (a.length = N), idxbig (a[N-1] =
         9), sizes 1024, 1025, 2000, 9000, 40000
  huge   array-likes with a very large length: the cases print only whether
         the call threw, because the exception type differs between engines;
         without the developer patch's limit a length of 1e7 or 5e7 takes
         seconds before the stack-size RangeError (added after run 1)
  poc    the shape of the dataset PoC and variants of it
  valid  inputs without a slow array or hole: dense arrays, array-likes,
         arguments objects, typed arrays, null and undefined, non-objects,
         bound functions
  othr   other Array builtins applied to slow arrays (not part of apply; a search for
         neighbouring defects): containers lenback, lenbig, freeze
Callees: lam (a lambda that prints the argument count and the first eight
arguments), max (Math.max), of (Array.of), obj (Object), concat
(String.prototype.concat), fcc (String.fromCharCode), push
(Array.prototype.push on a one-element array), actor (Array called as a
function).

Column absent is "none" for the valid group (inputs for which every build
must agree; scripts/njs_cases.py hashes their outputs), else the group name.
Column slow is 1 when the array is a slow array with a nonzero stale length
at the call on the base build, holes is 1 when it is a fast array with holes.
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
        return 'obj:' + JSON.stringify(v);
    }
    if (typeof v === 'string') return 'string:' + JSON.stringify(v);
    return typeof v + ':' + String(v);
}
function lam() {
    var s = [arguments.length];
    for (var i = 0; i < arguments.length && i < 8; i++) s.push(show(arguments[i]));
    return s.join('|');
}
function out(f) {
    try { console.log(f()); } catch (e) { console.log('EXC ' + e.name); }
}
function outx(f) {
    try { console.log(f()); } catch (e) { console.log('threw'); }
}
"""

# callee: (call template over {A}, payload of three values, kind)
CALLEES = {
    "lam": ("lam.apply(null, {A})", ["1", "2", "3"]),
    "max": ("show(Math.max.apply(null, {A}))", ["1", "5", "3"]),
    "of": ("show(Array.of.apply(null, {A}))", ["1", "2", "3"]),
    "obj": ("show(Object.apply({{}}, {A}))", ["{p:1}", "{p:2}", "{p:3}"]),
    "concat": ("show(String.prototype.concat.apply('x', {A}))", ["'a'", "'b'", "'c'"]),
    "fcc": ("show(String.fromCharCode.apply(null, {A}))", ["72", "105", "33"]),
    "push": ("(function() { var t = ['t']; Array.prototype.push.apply(t, {A}); return show(t); })()",
             ["1", "2", "3"]),
    "actor": ("show(Array.apply(null, {A}))", ["5", "6", "7"]),
}
NATIVE = {c for c in CALLEES if c != "lam"}

SIZES = [1024, 1025, 2000, 9000, 40000]
HUGE = ["1577595327", "2147483648", "4294967295", "4294967296", "1e6", "1e7", "5e7"]


def arr(vals):
    return "[" + ",".join(vals) + "]"


def container(kind, vals):
    """JavaScript expression of the apply argument array, and (slow, holes)."""
    lit = arr(vals)
    n = len(vals)
    if kind == "flat":
        return lit, 0, 0
    if kind == "freeze":
        return f"Object.freeze({lit})", 1, 0
    if kind == "seal":
        return f"Object.seal({lit})", 1, 0
    if kind == "defenum":
        return ("(function() { var a = %s; Object.defineProperty(a, 0, {enumerable: false}); return a; })()" % lit,
                1, 0)
    if kind == "defro":
        return ("(function() { var a = %s; Object.defineProperty(a, 1, {writable: false}); return a; })()" % lit,
                1, 0)
    if kind == "defget":
        return ("(function() { var a = %s; Object.defineProperty(a, 1, {get: function() { return %s; }, "
                "enumerable: true, configurable: true}); return a; })()" % (lit, vals[1]), 1, 0)
    if kind == "lenback":
        return ("(function() { var a = %s; a.length = 40000; a.length = %d; return a; })()" % (lit, n), 1, 0)
    if kind == "hole_lead":
        return "[," + ",".join(vals[1:]) + "]", 0, 1
    if kind == "hole_mid":
        return "[" + vals[0] + ",," + vals[2] + "]", 0, 1
    if kind == "hole_trail":
        return "[" + vals[0] + "," + vals[1] + ",,]", 0, 1
    if kind == "hole_all":
        return "[,,,]", 0, 1
    raise AssertionError(kind)


def seq(n):
    return [str(i % 100) for i in range(n)]


def mk(name, group, cont, callee, n, expr, slow=0, holes=0, outfn="out"):
    return dict(name=name, group=group, container=cont, callee=callee, n=n, slow=slow, holes=holes,
                absent="none" if group == "valid" else group, body=f"{outfn}(function() {{ return {expr}; }});")


def call(callee, argexpr):
    return CALLEES[callee][0].replace("{A}", argexpr).replace("{{}}", "{}")


def cases():
    out = []
    # slow: arrays converted to slow arrays before the call
    for cont in ["freeze", "seal", "defenum", "defro", "defget", "lenback"]:
        for callee, (_, payload) in CALLEES.items():
            expr, slow, holes = container(cont, payload)
            out.append(mk(f"slow_{cont}_{callee}", "slow", cont, callee, 3, call(callee, expr), slow, holes))
    for cont, vals, callees in [("freeze256", seq(256), ["lam", "max", "of"]),
                                ("freeze1024", seq(1024), ["lam", "max"]),
                                ("freezeempty", [], ["lam", "max"])]:
        for callee in callees:
            expr = f"Object.freeze({arr(vals)})"
            out.append(mk(f"slow_{cont}_{callee}", "slow", cont, callee, len(vals), call(callee, expr),
                          1 if vals else 0, 0))
    # hole: fast arrays with holes
    for cont in ["hole_lead", "hole_mid", "hole_trail", "hole_all"]:
        for callee in ["lam", "max", "of", "concat", "fcc", "push", "actor"]:
            payload = CALLEES[callee][1]
            expr, slow, holes = container(cont, payload)
            out.append(mk(f"hole_{cont[5:]}_{callee}", "hole", cont, callee, 3, call(callee, expr), slow, holes))
    for callee in ["actor", "lam", "of"]:
        out.append(mk(f"hole_arr3_{callee}", "hole", "arr3", callee, 3, call(callee, "Array(3)"), 0, 1))
    for callee in ["lam", "of"]:
        out.append(mk(f"hole_lenfast_{callee}", "hole", "lenfast", callee, 100,
                      call(callee, "(function() { var a = [1,2,3]; a.length = 100; return a; })()"), 0, 1))
    # limit: argument counts around 1024 and the engine stack limit
    for n in SIZES:
        conts = {
            "flatn": ("(function() { var a = []; for (var i = 0; i < %d; i++) a.push(i); return a; })()" % n, 0, 0),
            "like": ("{length: %d}" % n, 0, 0),
            "lenset": ("(function() { var a = [1,2,3]; a.length = %d; return a; })()" % n,
                       1 if n > 32768 else 0, 0 if n > 32768 else 1),
            "idxbig": ("(function() { var a = [1,2,3]; a[%d] = 9; return a; })()" % (n - 1),
                       1 if n - 1 >= 32768 else 0, 0 if n - 1 >= 32768 else 1),
        }
        for cont, (expr, slow, holes) in conts.items():
            for callee in ["lam", "max"]:
                out.append(mk(f"limit_{cont}_{callee}_{n}", "limit", cont, callee, n, call(callee, expr),
                              slow, holes))
    # huge: array-likes with a very large length, only whether the call threw
    for h in HUGE:
        for callee in ["lam", "max"]:
            out.append(mk(f"huge_like_{callee}_{h.replace('+', '')}", "huge", "like", callee, h,
                          call(callee, "{length: %s}" % h), 0, 0, "outx"))
    # poc: the dataset PoC shape and variants (the njs parser ignores the spread of the PoC call)
    out.append(dict(name="poc_shape", group="poc", container="lenset", callee="obj", n="1577595327", slow=1,
                    holes=0, absent="poc",
                    body="outx(function() { var v3 = [23490,23490,23490,23490]; var v4 = {}; "
                         "v3.length = 1577595327; var v9 = Object.apply(v4, v3); v3.__proto__ = v9; "
                         "return 'done'; });"))
    out.append(dict(name="poc_len40000_obj", group="poc", container="lenset", callee="obj", n="40000", slow=1,
                    holes=0, absent="poc",
                    body="outx(function() { var v3 = [23490,23490,23490,23490]; v3.length = 40000; "
                         "var v9 = Object.apply({}, v3); return show(v9); });"))
    out.append(dict(name="poc_len40000_lam", group="poc", container="lenset", callee="lam", n="40000", slow=1,
                    holes=0, absent="poc",
                    body="outx(function() { var v3 = [23490,23490,23490,23490]; v3.length = 40000; "
                         "return lam.apply({}, v3); });"))
    out.append(dict(name="poc_len1500_obj", group="poc", container="lenset", callee="obj", n="1500", slow=0,
                    holes=1, absent="poc",
                    body="outx(function() { var v3 = [23490,23490,23490,23490]; v3.length = 1500; "
                         "var v9 = Object.apply({}, v3); v3.__proto__ = v9; return 'done'; });"))
    # valid: inputs that reach no slow array and no hole
    for n in [0, 1, 10, 100, 1024]:
        for callee in ["lam", "max", "of", "push"]:
            out.append(mk(f"valid_flat{n}_{callee}", "valid", f"flat{n}", callee, n,
                          call(callee, arr(seq(n))), 0, 0))
    for callee, (_, payload) in CALLEES.items():
        out.append(mk(f"valid_flat3_{callee}", "valid", "flat3", callee, 3, call(callee, arr(payload))))
    for callee in ["lam", "max", "of", "concat", "obj"]:
        vals = CALLEES[callee][1]
        like = "{length: 3, 0: %s, 1: %s, 2: %s}" % tuple(vals)
        out.append(mk(f"valid_like_{callee}", "valid", "like3", callee, 3, call(callee, like)))
    out.append(mk("valid_like_empty", "valid", "likeempty", "lam", 0, "lam.apply(null, {})"))
    out.append(mk("valid_like_neg", "valid", "likeneg", "lam", 0, "lam.apply(null, {length: -1})"))
    out.append(mk("valid_like_strlen", "valid", "likestr", "lam", 2,
                  "lam.apply(null, {length: '2', 0: 'a', 1: 'b'})"))
    out.append(mk("valid_args_lam", "valid", "arguments", "lam", 3,
                  "(function() { return lam.apply(null, arguments); })(1, 2, 3)"))
    out.append(mk("valid_args_max", "valid", "arguments", "max", 3,
                  "(function() { return show(Math.max.apply(null, arguments)); })(1, 5, 3)"))
    out.append(mk("valid_typed_lam", "valid", "typed", "lam", 3, "lam.apply(null, new Uint8Array([7, 8, 9]))"))
    out.append(mk("valid_typed_max", "valid", "typed", "max", 3,
                  "show(Math.max.apply(null, new Uint8Array([7, 8, 9])))"))
    out.append(mk("valid_shrink_lam", "valid", "shrink", "lam", 2,
                  "(function() { var a = [1,2,3,4,5]; a.length = 2; return lam.apply(null, a); })()"))
    out.append(mk("valid_shift_lam", "valid", "shift", "lam", 3,
                  "(function() { var a = [0,1,2,3]; a.shift(); return lam.apply(null, a); })()"))
    out.append(mk("valid_shift_max", "valid", "shift", "max", 3,
                  "(function() { var a = [0,1,5,3]; a.shift(); return show(Math.max.apply(null, a)); })()"))
    out.append(mk("valid_pushed_lam", "valid", "pushed", "lam", 4,
                  "(function() { var a = []; a.push(1); a.push(2); a.push(3, 4); return lam.apply(null, a); })()"))
    out.append(mk("valid_null_lam", "valid", "null", "lam", 0, "lam.apply(null, null)"))
    out.append(mk("valid_undef_lam", "valid", "undefined", "lam", 0, "lam.apply(null, undefined)"))
    out.append(mk("valid_noarg_lam", "valid", "noarg", "lam", 0, "lam.apply(null)"))
    out.append(mk("valid_num_lam", "valid", "number", "lam", 0, "lam.apply(null, 5)"))
    out.append(mk("valid_str_lam", "valid", "string", "lam", 0, "lam.apply(null, 'abc')"))
    out.append(mk("valid_bool_lam", "valid", "boolean", "lam", 0, "lam.apply(null, true)"))
    out.append(mk("valid_bound_lam", "valid", "flat3", "lam", 3,
                  "lam.bind(null, 0).apply(null, [1, 2, 3])"))
    out.append(mk("valid_this", "valid", "flat0", "lam", 0,
                  "show((function() { return this.x; }).apply({x: 7}, []))"))
    out.append(mk("valid_nested", "valid", "flat3", "lam", 3,
                  "Function.prototype.apply.call(lam, null, [1, 2, 3])"))
    # othr: other Array builtins on slow arrays (not part of apply): lenback is a slow array whose stale
    # length equals its real length, lenbig one whose stale length (3) differs from its real length
    # (40000), freeze a frozen array (only the methods that do not write)
    contain = {
        "lenback": ("(function() { var a = [3,1,2]; a.length = 40000; a.length = 3; return a; })()", ""),
        "lenbig": ("(function() { var a = [3,1,2]; a.length = 40000; return a; })()", "lenbig_"),
        "freeze": ("Object.freeze([3,1,2])", "freeze_"),
    }
    ops = {
        "slice": "show(%s.slice(1))",
        "slice_neg": "show(%s.slice(-2))",
        "concat": "show(%s.concat([4]))",
        "concat_arg": "show([0].concat(%s))",
        "join": "show(%s.join('-'))",
        "joinlen": "show(%s.join('-').length)",
        "indexof": "show(%s.indexOf(2))",
        "lastindexof": "show(%s.lastIndexOf(2))",
        "includes": "show(%s.includes(2))",
        "find": "show(%s.find(function(x) { return x < 3; }))",
        "map": "show(%s.map(function(x) { return x * 2; }))",
        "foreach": "(function() { var r = []; %s.forEach(function(x) { r.push(x); }); return show(r); })()",
        "filter": "show(%s.filter(function(x) { return x > 1; }))",
        "reduce": "show(%s.reduce(function(p, x) { return p + x; }, 0))",
        "every": "show(%s.every(function(x) { return x > 0; }))",
        "some": "show(%s.some(function(x) { return x > 2; }))",
        "reverse": "show(%s.reverse())",
        "sort": "show(%s.sort())",
        "splice": "(function() { var a = %s; var r = a.splice(1, 1); return show(r) + show(a); })()",
        "pop": "(function() { var a = %s; var r = a.pop(); return show(r) + show(a); })()",
        "shift": "(function() { var a = %s; var r = a.shift(); return show(r) + show(a); })()",
        "unshift": "(function() { var a = %s; var r = a.unshift(9); return show(r) + show(a); })()",
        "push": "(function() { var a = %s; a.push(9); return show(a); })()",
        "fill": "show(%s.fill(7, 0, 2))",
        "copywithin": "show(%s.copyWithin(0, 1, 2))",
        "json": "JSON.stringify(%s)",
        "jsonlen": "show(JSON.stringify(%s).length)",
        "keys": "show(Object.keys(%s))",
        "string": "String(%s)",
        "stringlen": "show(String(%s).length)",
        "forin": "(function() { var r = []; for (var k in %s) r.push(k); return show(r); })()",
    }
    sets = {
        "lenback": ["slice", "concat", "concat_arg", "join", "indexof", "map", "foreach", "filter", "reverse",
                    "sort", "splice", "pop", "shift", "push", "json", "keys", "string", "forin"],
        "lenbig": [o for o in ops if o not in ("join", "json", "string")],
        "freeze": ["slice", "slice_neg", "concat", "concat_arg", "join", "indexof", "lastindexof", "includes",
                   "find", "map", "foreach", "filter", "reduce", "every", "some", "json", "keys", "string",
                   "forin"],
    }
    for cname, (cexpr, prefix) in contain.items():
        for op in sets[cname]:
            out.append(mk(f"othr_{prefix}{op}", "othr", cname, op, 3 if cname != "lenbig" else 40000,
                          ops[op] % cexpr, 0, 0))
    return out


def main(outdir):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    cs = cases()
    names = [c["name"] for c in cs]
    assert len(names) == len(set(names)), "duplicate case names"
    with open(outdir / "cases.tsv", "w") as f:
        f.write("case\tgroup\tcontainer\tcallee\tn\tabsent\tslow\tholes\n")
        for c in cs:
            f.write("\t".join(str(c[k]) for k in ["name", "group", "container", "callee", "n", "absent",
                                                   "slow", "holes"]) + "\n")
    for c in cs:
        (outdir / (c["name"] + ".js")).write_text(PRELUDE + c["body"] + "\n")
    print(len(cs), "cases")


if __name__ == "__main__":
    main(sys.argv[1])
