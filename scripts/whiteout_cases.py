"""Write the JavaScript case files for njs.cve-2023-27727 (a deleted
property left as an NJS_WHITEOUT tombstone and read by njs_object_property).

Usage: python3 whiteout_cases.py OUTDIR

Writes OUTDIR/<case>.js and OUTDIR/cases.tsv with the columns case, group,
kind, consumer, absent, faulty. Each script defines the printer below,
builds an object with one property, deletes that property, reads the object
through one consumer, and prints one line, so that njs and the reference
engine (Node.js) print the same text for the same program. The expected
output is the reference engine's output on the same file
(scripts/njs_cases.py --oracle).

Mechanism at the base commit 1f54b79c. Deleting a property runs
njs_value_property_delete() (src/njs_value.c), which sets prop->type =
NJS_WHITEOUT and njs_set_invalid(njs_prop_value(prop)); the property stays
in the object hash as a tombstone, and the njs_set_invalid write overwrites
the accessor getter/setter union with the invalid-value bit pattern.
njs_object_property() (src/njs_object_prop.c), the internal property lookup
used by error name/message dumping, njs_value_to_primitive (toString /
valueOf), JSON toJSON, Array toString (join) and Object.defineProperty
descriptor reads, finds the tombstone in the own hash and does `goto found`.
At `found:` an accessor tombstone is not a data descriptor (njs_is_valid of
the value is false), so it reads njs_prop_getter(prop), which is no longer
NULL but the overwritten bits, and calls njs_function_apply with that
pointer: njs_function_frame dereferences it and faults (SEGV on 0x30, the
dataset report). A data tombstone keeps writable != NJS_ATTRIBUTE_UNSET, so
njs_is_data_descriptor() is true and njs_object_property() returns the
invalidated value instead, which the caller cannot convert (a wrong result,
not a crash).

Invariant (narrowest for the reported failure): njs_object_property() must
not return a property whose own-hash entry is an NJS_WHITEOUT tombstone;
a deleted property must be looked up further (shared hash, prototype chain)
or reported absent.

Property kinds (the own property defined then deleted), column kind:
  sacc   accessor, set only (the dataset PoC: {configurable:true, set: fn})
  gacc   accessor, get only
  bacc   accessor, get and set
  data   data, {configurable:true, value, writable:true}
  dataro data, {configurable:true, value} (writable defaults to false)
  assign a data property created by assignment, then deleted

Consumers (what reads the object through njs_object_property), column
consumer; the property name deleted is the one the consumer looks up:
  errmsg   an Error instance whose own "message" is deleted, then String(e)
  errname  an Error instance whose own "name" is deleted, then String(e)
  poc      the dataset shape: EvalError(v1) with v1's "message" deleted
           (error used as the message argument, converted through
           njs_value_to_primitive)
  prim_ts  a plain object whose "toString" is deleted, then o + ""
  prim_vo  a plain object whose "valueOf" is deleted, then o * 1
  json     an object whose "toJSON" is deleted, then JSON.stringify(o)
  arrjoin  an array whose own "join" is deleted, then String(arr)
  defprop  Object.defineProperty(t, "k", d) with d's "get" deleted

Groups (case <group>_<kind>_<consumer>):
  faulty  an accessor kind (sacc, gacc, bacc) deleted and read by a consumer
          above: the own-hash tombstone is reached by njs_object_property
          (base: a sanitizer report)
  wrong   a data kind (data, dataro, assign) deleted and read the same way
          (base: a wrong result, the invalidated value is returned)
  valid   controls that reach no tombstone through njs_object_property: no
          delete, redefine after delete, a deleted own property read by the
          ordinary property-get path (o.k, "k" in o), a deleted inherited
          method still present on the prototype

Column absent is "none" for the valid group, else the group name. Column
faulty is 1 for the faulty group (a sanitizer report on the base build).
Syntax is limited to what njs at the base commit parses.
"""
import sys
from pathlib import Path

PRELUDE = r"""
function show(v) {
    try {
        if (v === undefined) return 'undef';
        if (v === null) return 'null';
        if (typeof v === 'string') return 'string:' + JSON.stringify(v);
        if (typeof v === 'object') return 'object:' + Object.prototype.toString.call(v);
        return typeof v + ':' + String(v);
    } catch (e) { return 'EXC ' + e.name; }
}
function out(f) {
    try { console.log(show(f())); } catch (e) { console.log('EXC ' + e.name); }
}
"""

# kind -> the descriptor object passed to Object.defineProperty, with a
# function f already in scope for accessors.
KIND_DESC = {
    "sacc": "{configurable:true, set: f}",
    "gacc": "{configurable:true, get: f}",
    "bacc": "{configurable:true, get: f, set: f}",
    "data": "{configurable:true, value: 'v', writable:true}",
    "dataro": "{configurable:true, value: 'v'}",
}
ACC = ("sacc", "gacc", "bacc")
DATA = ("data", "dataro")


def define_delete(obj, name, kind):
    """JS that defines property `name` of expression result `obj` with the
    given kind, then deletes it; leaves the object in variable o."""
    s = "var f = function(){ return 'g'; }; var o = %s; " % obj
    if kind == "assign":
        s += "o[%r] = 'v'; " % name
    else:
        s += "Object.defineProperty(o, %r, %s); " % (name, KIND_DESC[kind])
    s += "delete o[%r]; " % name
    return s


# consumer -> (object expression, property name deleted, read expression
# producing the printed value). `o` is the object after define+delete.
def consumer(name):
    if name == "errmsg":
        return ("EvalError('m')", "message", "String(o)")
    if name == "errname":
        return ("EvalError('m')", "name", "String(o)")
    if name == "prim_ts":
        return ("({})", "toString", "o + ''")
    if name == "prim_vo":
        return ("({})", "valueOf", "o * 1")
    if name == "json":
        return ("({a:1})", "toJSON", "JSON.stringify(o)")
    if name == "arrjoin":
        return ("[1,2,3]", "join", "String(o)")
    raise AssertionError(name)


SIMPLE = ("errmsg", "errname", "prim_ts", "prim_vo", "json", "arrjoin")


def mk(name, group, kind, cons, body, faulty):
    return dict(name=name, group=group, kind=kind, consumer=cons,
                absent="none" if group == "valid" else group, faulty=faulty, body=body)


def cases():
    out = []
    # faulty and wrong: each simple consumer crossed with each property kind
    for cons in SIMPLE:
        obj, prop, read = consumer(cons)
        for kind in ACC + DATA + ("assign",):
            group = "faulty" if kind in ACC else "wrong"
            body = "out(function() { %s return %s; });" % (define_delete(obj, prop, kind), read)
            out.append(mk("%s_%s_%s" % (group, kind, cons), group, kind, cons, body, int(kind in ACC)))

    # poc: the dataset shape, error used as the message argument of a
    # constructor, for each accessor and data kind
    for kind in ACC + DATA:
        group = "faulty" if kind in ACC else "wrong"
        pre = define_delete("EvalError('m')", "message", kind)
        body = "out(function() { %s return String(EvalError(o)); });" % pre
        out.append(mk("%s_%s_poc" % (group, kind), group, kind, "poc", body, int(kind in ACC)))

    # defprop: a descriptor object whose own "get" is a deleted accessor,
    # then used as the descriptor of Object.defineProperty (reads it with
    # njs_object_property through njs_object_prop.c)
    for kind in ACC + DATA:
        group = "faulty" if kind in ACC else "wrong"
        pre = define_delete("({enumerable:true})", "get", kind)
        body = ("out(function() { %s var t = {}; "
                "Object.defineProperty(t, 'k', o); return ('k' in t) + ''; });" % pre)
        out.append(mk("%s_%s_defprop" % (group, kind), group, kind, "defprop", body, int(kind in ACC)))

    # wrong: a function assigned to "toString" then deleted, consumed by `+`
    # (the deleted own toString masks the inherited one through the tombstone;
    # a TypeError on the base build). Kept apart from the assign kind above,
    # which assigns a non-function value.
    out.append(mk("wrong_assignfn_ts", "wrong", "assignfn", "ts_fn",
                  "out(function() { var o = {}; o.toString = function(){ return 'own'; }; "
                  "delete o.toString; return o + ''; });", 0))

    # valid controls
    v = []
    # no delete: the accessor is present and read normally
    v.append(("nodel_sacc_errmsg",
              "out(function() { var f = function(){}; var o = EvalError('m'); "
              "Object.defineProperty(o, 'message', {configurable:true, get: function(){ return 'hi'; }}); "
              "return String(o); });"))
    # redefine after delete: a live property replaces the tombstone
    v.append(("redef_sacc_errmsg",
              "out(function() { %s o.message = 'back'; return String(o); });"
              % define_delete("EvalError('m')", "message", "sacc")))
    # deleted own accessor read by the ordinary get path, not njs_object_property
    v.append(("getpath_sacc_read",
              "out(function() { %s return ('x' in o) + ',' + show(o.x); });"
              % define_delete("({})", "x", "sacc")))
    v.append(("getpath_data_read",
              "out(function() { %s return ('x' in o) + ',' + show(o.x); });"
              % define_delete("({})", "x", "data")))
    # an object that never had an own toString uses the inherited one
    v.append(("inherited_only",
              "out(function() { var o = {a:1}; return o + ''; });"))
    # plain define+delete of a data property on a plain object, read by `in`
    v.append(("plain_del_in",
              "out(function() { var o = {}; Object.defineProperty(o, 'k', {configurable:true, value: 1}); "
              "delete o.k; return ('k' in o) + ',' + show(o.k); });"))
    # error with a normal (never-deleted) own message
    v.append(("err_plain_msg",
              "out(function() { var o = EvalError('plain'); return String(o); });"))
    # object with a normal toString used in a primitive conversion
    v.append(("prim_plain_ts",
              "out(function() { var o = {toString: function(){ return 'TS'; }}; return o + ''; });"))
    # JSON of an object with a normal toJSON
    v.append(("json_plain",
              "out(function() { var o = {a:1, toJSON: function(){ return 'J'; }}; return JSON.stringify(o); });"))
    # a second define+delete cycle on the same name (tombstone reused)
    v.append(("recycle_sacc_errmsg",
              "out(function() { var o = EvalError('m'); "
              "Object.defineProperty(o, 'message', {configurable:true, set: function(){}}); "
              "delete o.message; "
              "Object.defineProperty(o, 'message', {configurable:true, value: 'two', writable:true}); "
              "return String(o); });"))
    for name, body in v:
        out.append(mk("valid_" + name, "valid", "-", "-", body, 0))
    return out


def main(outdir):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    cs = cases()
    names = [c["name"] for c in cs]
    assert len(names) == len(set(names)), "duplicate case names"
    cols = ["name", "group", "kind", "consumer", "absent", "faulty"]
    with open(outdir / "cases.tsv", "w") as f:
        f.write("case\tgroup\tkind\tconsumer\tabsent\tfaulty\n")
        for c in cs:
            f.write("\t".join(str(c[k]) for k in cols) + "\n")
    for c in cs:
        (outdir / (c["name"] + ".js")).write_text(PRELUDE + c["body"] + "\n")
    print(len(cs), "cases")


if __name__ == "__main__":
    main(sys.argv[1])
