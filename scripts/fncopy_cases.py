"""Write the JavaScript case files for njs.cve-2022-43284 (a function
declaration binding re-initialized by the NJS_VMCODE_FUNCTION_COPY opcode
after the program assigned a value to it).

Usage: python3 fncopy_cases.py OUTDIR

Writes OUTDIR/<case>.js and OUTDIR/cases.tsv with the columns case, group,
structure, retrigger, value, absent, faulty. Each script assigns one value
to a function-declaration binding and then references or calls that binding
once more, and prints one line, so that njs and the reference engine
(Node.js) print the same text when njs is correct. The expected output is
the reference engine's output on the same file (scripts/njs_cases.py
--oracle).

Mechanism at the image tree 50bb20a8 (tag 0.7.2). A function declaration is
materialized lazily: every use of the name emits an NJS_VMCODE_FUNCTION_COPY
opcode, which runs njs_vmcode_function_copy() (src/njs_vmcode.c). The opcode
must store the function value only while the binding is still uninitialized
(NJS_INVALID). The base opcode instead reads the slot with
njs_scope_valid_value() (src/njs_scope.h), which converts an NJS_INVALID
slot to NJS_UNDEFINED, and re-initializes when njs_is_undefined() is true.
A binding the program assigned the value undefined therefore reads as
undefined and is wrongly re-materialized into the function on the next use.

Disassembly of the dataset PoC (njs -d; the probes in the generator date
line below): main() hoists a0, each call `a0()` in main emits
`FUNCTION COPY <tmpl> 0204` (a0's slot in main's local level) before the
call, and inside a0 the self-assignment `a0 = a1` emits
`FUNCTION COPY <tmpl> 0014` (a0's slot seen through the closure level) then
`MOVE 0014 <a1>`. First call: a0 slot NJS_INVALID -> materialized to the
function, then a0 = a1 (a1 absent, so undefined). Second call: the slot is
undefined, the base guard re-materializes a0 via njs_function_value_copy();
that fresh copy's closure level leaves slot 0014 holding a NULL pointer, so
on re-entry a0's own FUNCTION_COPY reads njs_scope_value(0014) = NULL and
njs_scope_valid_value() faults reading value->type (SEGV, READ at the zero
page, the dataset report). The developer patch uses njs_scope_value() (no
mutation) with the guard !njs_is_valid(), so an assigned undefined is not
re-materialized; calling it then throws TypeError, as the reference engine.

Invariant (narrowest for the reported failure): njs_vmcode_function_copy()
must store the function value only while the target binding is NJS_INVALID;
once the binding holds any valid value, including a program-assigned
undefined, the opcode must leave it unchanged.

Dimensions:
  structure  where the binding lives and whether the function names itself
    self   a function declared in an enclosing function that assigns its own
           name from inside (the dataset PoC shape); a closure variable, so a
           wrong re-materialization leaves a NULL closure slot (a crash when
           the re-materialized function is entered, i.e. retrigger=call)
    local  a function declared in an enclosing function, reassigned from the
           enclosing scope, not self-naming (no closure slot: a wrong result)
    global a function declaration at script top level, reassigned at top level
  retrigger  how FUNCTION_COPY is made to run again after the assignment
    ref    the binding is referenced in an expression (show the value)
    call   the binding is called (show the call result, or the exception)
  value  the value assigned to the binding before the retrigger
    undef  undefined        (base re-initializes: the faulty state)
    null   null             (non-undefined: base does not re-initialize)
    num    5
    str    's'
    obj    ({})

Groups (column group):
  undef    value=undef, every structure x retrigger: base diverges
           (self+call: a sanitizer report; otherwise a wrong result)
  defined  value in {null,num,str,obj}: base and patch agree (controls that
           show the base guard misfires only for undefined)
  valid    controls that never assign undefined to a live function binding

Column absent is "none" for the valid group (covered by the output digest),
else the group name. Column faulty is 1 for cases that give a sanitizer
report on the base build (self_call_undef and the dataset PoC). Syntax is
limited to what njs at the base commit parses (plain functions, var).
"""
import sys
from pathlib import Path

PRELUDE = r"""
function show(v) {
    if (v === undefined) return 'undef';
    if (v === null) return 'null';
    var t = typeof v;
    if (t === 'function') return 'function';
    if (t === 'object') return 'object';
    if (t === 'string') return 'string:' + JSON.stringify(v);
    return t + ':' + String(v);
}
function out(f) {
    try { console.log(show(f())); } catch (e) { console.log('EXC ' + e.name); }
}
"""

# A top-level observation, so that a global function declaration and the
# reference or call that retriggers FUNCTION_COPY stay at script top level
# (wrapping them in a function would reference the global through a closure).
def topobs(expr):
    return ("try { console.log(show(%s)); } "
            "catch (e) { console.log('EXC ' + e.name); }") % expr

# value key -> (argument form for self, right-hand side for assignment)
VALUES = {
    "undef": ("undefined", "undefined"),
    "null": ("null", "null"),
    "num": ("5", "5"),
    "str": ("'s'", "'s'"),
    "obj": ("{}", "({})"),
}
VKEYS = ("undef", "null", "num", "str", "obj")


def mk(name, group, structure, retrigger, value, body, faulty):
    return dict(name=name, group=group, structure=structure,
                retrigger=retrigger, value=value,
                absent="none" if group == "valid" else group,
                faulty=faulty, body=body)


def self_case(retr, vkey):
    arg = VALUES[vkey][0]
    # a0 is a closure variable: it assigns its own name from inside.
    head = "function a0(a1,a2) { a0 = a1; return 'ran'; } a0(%s); " % arg
    tail = "return a0;" if retr == "ref" else "return a0();"
    return "out(function() { %s%s });" % (head, tail)


def local_case(retr, vkey):
    rhs = VALUES[vkey][1]
    head = "function a0() { return 'ran'; } a0 = %s; " % rhs
    tail = "return a0;" if retr == "ref" else "return a0();"
    return "out(function() { %s%s });" % (head, tail)


def global_case(retr, vkey):
    rhs = VALUES[vkey][1]
    head = "function g0() { return 'ran'; } g0 = %s; " % rhs
    return head + topobs("g0" if retr == "ref" else "g0()")


def cases():
    out = []
    builders = {"self": self_case, "local": local_case, "global": global_case}
    for structure in ("self", "local", "global"):
        for retr in ("ref", "call"):
            for vkey in VKEYS:
                group = "undef" if vkey == "undef" else "defined"
                faulty = int(structure == "self" and retr == "call" and vkey == "undef")
                body = builders[structure](retr, vkey)
                out.append(mk("%s_%s_%s" % (structure, retr, vkey),
                              group, structure, retr, vkey, body, faulty))

    # valid controls (never assign undefined to a live function binding)
    v = []
    # self shape, reassigned to non-undefined values twice, then referenced
    v.append(("self_defined_twice", "self", "ref", "-",
              "out(function() { function a0(a1,a2) { a0 = a1; return 'ran'; } "
              "a0(1); a0(2); return a0; });"))
    # self shape that only reads its own name (no reassignment), called twice
    v.append(("self_readonly_call", "self", "call", "-",
              "out(function() { function a0() { return typeof a0; } a0(); "
              "return a0(); });"))
    # local function called normally, no reassignment
    v.append(("local_call_normal", "local", "call", "-",
              "out(function() { function a0() { return 7; } return a0(); });"))
    # local function referenced, no reassignment
    v.append(("local_ref_normal", "local", "ref", "-",
              "out(function() { function a0() {} return a0; });"))
    # global function called normally, no reassignment
    v.append(("global_call_normal", "global", "call", "-",
              "function h0() { return 9; } " + topobs("h0()")))
    # global function referenced, no reassignment
    v.append(("global_ref_normal", "global", "ref", "-",
              "function k0() {} " + topobs("k0")))
    for name, structure, retr, _v, body in v:
        out.append(mk("valid_" + name, "valid", structure, retr, "-", body, 0))

    # masked: the invariant is violated (FUNCTION_COPY re-initializes a slot
    # the program set to undefined) but the wrong result is overwritten by a
    # later assignment, so the observable output is correct on both builds;
    # the instrumented check still fires (like the data-fallback cases of
    # njs.cve-2023-27727). a0 is reassigned to undefined, then to a new
    # function whose value the final call observes.
    out.append(mk("masked_reassign_back", "masked", "local", "call", "-",
                  "out(function() { function a0() { return 'old'; } a0 = undefined; "
                  "a0 = function() { return 'new'; }; return a0(); });", 0))
    return out


def main(outdir):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    cs = cases()
    names = [c["name"] for c in cs]
    assert len(names) == len(set(names)), "duplicate case names"
    cols = ["name", "group", "structure", "retrigger", "value", "absent", "faulty"]
    with open(outdir / "cases.tsv", "w") as f:
        f.write("case\tgroup\tstructure\tretrigger\tvalue\tabsent\tfaulty\n")
        for c in cs:
            f.write("\t".join(str(c[k]) for k in cols) + "\n")
    for c in cs:
        (outdir / (c["name"] + ".js")).write_text(PRELUDE + c["body"] + "\n")
    print(len(cs), "cases")


if __name__ == "__main__":
    main(sys.argv[1])
