"""Write the JavaScript case files for njs.cve-2022-32414 (absent elements
of array-like inputs to the Promise aggregation methods).

Usage: python3 promise_absent_cases.py OUTDIR

Writes OUTDIR/<case>.js, one script per case, and OUTDIR/cases.tsv with
the columns case, method, input, consumer, absent (where the absent
elements of the input are: none, first, later, big), source (input
construction) for scripts/promise_absent_predictions.py. Each script
prints exactly one result line through console.log, built by the
canonical printer show() below, so that njs and the reference engine
print the same text for the same value; a case that prints nothing (a
promise that never settles) has the empty output. The expected output of
every case is the output of the reference engine (Node.js) on the same
file: scripts/njs_cases.py --oracle.

Array-like inputs get a Symbol.iterator property set to
Array.prototype.values. njs at the base commit iterates array-likes by
their length and ignores that property (checked on the base build with an
iterator that logs when it is called); the reference engine requires an
iterable and, through Array.prototype.values, reads the same indices
0..length-1 with Get(), which yields undefined for an absent index. The
specification result for an array-like with an absent element is
therefore the reference engine's result for the same object.

Families (case name <method>_<input>_<consumer>):
  method    race, any, all, allSettled
  input     al1 {length:1}; al2p {length:2, 1:'b'}; al2q {length:2, 0:'a'};
            fn3 Float64Array (a function with length 3, the PoC input);
            hole1 [,]; holemid [1,,3]; sparse new Array(2); proto
            (index 0 inherited); getter (index 0 an accessor); dense
            ['a','b']; mixed [Promise.resolve(1), 2, thenable];
            alfull {length:2, 0:'a', 1:'b'}; str 'ab'; empty [];
            big {length:1025} (beyond NJS_ARRAY_FAST_OBJECT_LENGTH, so
            njs_object_iterate() visits only the present indices)
  consumer  then    P.then(v => show(v))
            args    P.then(function () { arguments.length, 0 in arguments,
                    show(arguments[0]) })
            str     P.then(String) (a native handler receives the value)
            json    P.then(JSON.stringify)
            vals    P.then(v => Object.values() of each object element)
            avar    var v = await P; show(v)
            alet    let v = await P; show(v)
            forin   var v = await P; for (var k in 'ab') {}; show(v)
            pocshape const v = await P; for (const k in 'test') {} (PoC shape)
            chain   var v = await P.then(x => x); for-in; show(v)
            freeze  var v = await P.then(Object.freeze); for-in; show(v)
  big has the consumers then and forin only; empty has no any cases
  (njs at the base commit fulfils Promise.any([]), which the reference
  engine rejects; a deviation outside this instance, excluded).
Other families:
  agg_<input>   new AggregateError(input).errors: length, per index
                "in" and show() (njs_iterator_to_array(), a second
                consumer of njs_object_iterate())
  src_<name>    non-promise operations that could leave an INVALID value
                in vm->retval before a for-in: Function.prototype.apply,
                Array.prototype.find with a native callback, array
                iterator next(), pop(), RegExp exec() with an unmatched
                group, AggregateError errors passed through apply
  ctl_forin     a plain for-in (control)
The dataset PoC (/testcase/poc.js) is added by the runner as case "poc"
(scripts/njs_cases.py --extra); the reference engine rejects its input
Float64Array as not iterable, so its expected output is the empty output
of a run that ends without a sanitizer report.

Syntax is limited to what njs at the base commit parses (no call spread,
no destructuring, no for-of).
"""
import sys
from pathlib import Path

PRELUDE = r"""
function show(v) {
    if (v === undefined) return 'undefined';
    if (v === null) return 'null';
    var t = typeof v;
    if (t === 'string') return 's:' + v;
    if (t === 'number' || t === 'boolean') return t.charAt(0) + ':' + String(v);
    if (t === 'function') return 'fn';
    if (Array.isArray(v)) {
        var r = [];
        for (var i = 0; i < v.length; i++) { r.push((i in v) ? show(v[i]) : 'hole'); }
        return '[' + r.join(',') + ']';
    }
    if (t === 'object') {
        if (v instanceof Error) return 'err:' + v.name;
        var ks = Object.keys(v).sort();
        var p = [];
        for (var j = 0; j < ks.length; j++) { p.push(ks[j] + '=' + show(v[ks[j]])); }
        return '{' + p.join(',') + '}';
    }
    return t;
}
function out(s) { console.log(s); }
function AL(o) { o[Symbol.iterator] = Array.prototype.values; return o; }
function brief(v) {
    if (!Array.isArray(v)) return show(v);
    return 'len=' + v.length + ' first=' + ((0 in v) ? show(v[0]) : 'hole')
           + ' last=' + ((v.length - 1 in v) ? show(v[v.length - 1]) : 'hole');
}
"""

# name: (construction, absent position)
INPUTS = {
    "al1": ("AL({length: 1})", "first"),
    "al2p": ("AL({length: 2, 1: 'b'})", "first"),
    "al2q": ("AL({length: 2, 0: 'a'})", "later"),
    "fn3": ("AL(Float64Array)", "first"),
    "hole1": ("[,]", "first"),
    "holemid": ("[1,,3]", "later"),
    "sparse": ("new Array(2)", "first"),
    "proto": ("AL((function () { var o = Object.create({0: 'p'}); o.length = 1; return o; })())", "none"),
    "getter": ("AL({length: 1, get 0() { return 'g'; }})", "none"),
    "dense": ("['a', 'b']", "none"),
    "mixed": ("[Promise.resolve(1), 2, {then: function (r) { r(3); }}]", "none"),
    "alfull": ("AL({length: 2, 0: 'a', 1: 'b'})", "none"),
    "str": ("'ab'", "none"),
    "empty": ("[]", "none"),
    "big": ("AL({length: 1025})", "big"),
}

METHODS = ["race", "any", "all", "allSettled"]

FORIN = "for (var k in 'ab') {}"

CONSUMERS = {
    "then": "P.then(function (v) { out(show(v)); }, function (e) { out('rej ' + show(e)); });",
    "args": "P.then(function () { out(arguments.length + ':' + (0 in arguments) + ':' + show(arguments[0])); },"
            " function (e) { out('rej ' + show(e)); });",
    "str": "P.then(String).then(function (s) { out('str ' + show(s)); }, function (e) { out('rej ' + show(e)); });",
    "json": "P.then(JSON.stringify).then(function (s) { out('json ' + show(s)); }, function (e) { out('rej ' + show(e)); });",
    "vals": "P.then(function (v) { var r = []; var a = Array.isArray(v) ? v : [v];"
            " for (var i = 0; i < a.length; i++) { var x = a[i];"
            " r.push((x !== null && typeof x === 'object') ? show(Object.values(x)) : show(x)); }"
            " out(r.join(';')); }, function (e) { out('rej ' + show(e)); });",
    "avar": "async function f() { var v = await P; out(show(v)); }\nf().catch(function (e) { out('rej ' + show(e)); });",
    "alet": "async function f() { let v = await P; out(show(v)); }\nf().catch(function (e) { out('rej ' + show(e)); });",
    "forin": "async function f() { var v = await P; " + FORIN + " out('done ' + show(v)); }\n"
             "f().catch(function (e) { out('rej ' + show(e)); });",
    "pocshape": "async function f() { const v = await P; for (const k in 'test') { } out('done'); }\n"
           "f().catch(function (e) { out('rej ' + show(e)); });",
    "chain": "async function f() { var v = await P.then(function (x) { return x; }); " + FORIN
             + " out('done ' + show(v)); }\nf().catch(function (e) { out('rej ' + show(e)); });",
    "freeze": "async function f() { var v = await P.then(Object.freeze); " + FORIN
              + " out('done ' + show(v)); }\nf().catch(function (e) { out('rej ' + show(e)); });",
}

BIG_CONSUMERS = {
    "then": "P.then(function (v) { out(brief(v)); }, function (e) { out('rej ' + show(e) + ' ' + brief(e.errors)); });",
    "forin": "async function f() { var v = await P; " + FORIN + " out('done ' + brief(v)); }\n"
             "f().catch(function (e) { out('rej ' + show(e) + ' ' + brief(e.errors)); });",
}

AGG_INPUTS = ["al1", "al2q", "hole1", "holemid", "sparse", "dense", "alfull", "big"]
AGG = ("var e = new AggregateError({inp}); var r = [e.errors.length];\n"
       "for (var i = 0; i < e.errors.length; i++) {{ r.push((i in e.errors) ? show(e.errors[i]) : 'hole'); }}\n"
       "out(r.join(' '));")

SRC = {
    "apply": "var v = Object.freeze.apply(null, [,]);",
    "find": "var v = [,].find(Object.freeze);",
    "iter": "var v = [,].values().next().value;",
    "pop": "var v = [1,,].pop();",
    "exec": "var v = /(a)|b/.exec('b')[1];",
    "aggapply": "var v = Object.freeze.apply(null, new AggregateError([,]).errors);",
}


def cases():
    """Yields (case, method, input, consumer, absent, source, body)."""
    for m in METHODS:
        for inp, (src, absent) in INPUTS.items():
            if inp == "empty" and m == "any":
                continue
            cons = BIG_CONSUMERS if inp == "big" else CONSUMERS
            for c, body in cons.items():
                yield (f"{m}_{inp}_{c}", m, inp, c, absent, src,
                       f"var P = Promise.{m}({src});\n{body}\n")
    for inp in AGG_INPUTS:
        src, absent = INPUTS[inp]
        yield (f"agg_{inp}", "AggregateError", inp, "errors", absent, src, AGG.format(inp=src) + "\n")
    for name, stmt in SRC.items():
        yield (f"src_{name}", "-", name, "forin", "none", stmt,
               f"{stmt}\n{FORIN}\nout('done ' + show(v));\n")
    yield ("ctl_forin", "-", "-", "forin", "none", "-",
           "var o = []; for (var k in 'ab') { o.push(k); } out(o.join('|'));\n")


def main():
    outdir = Path(sys.argv[1])
    outdir.mkdir(parents=True, exist_ok=True)
    rows = ["case\tmethod\tinput\tconsumer\tabsent\tsource"]
    for name, m, inp, c, absent, src, body in cases():
        (outdir / f"{name}.js").write_text(PRELUDE.lstrip("\n") + body)
        rows.append("\t".join([name, m, inp, c, absent, src]))
    (outdir / "cases.tsv").write_text("\n".join(rows) + "\n")
    print(f"{len(rows) - 1} cases written to {outdir}")


if __name__ == "__main__":
    main()
