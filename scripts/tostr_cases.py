"""Write the JavaScript case files for njs.cve-2022-29369 (a key-to-string
conversion that fails inside the NJS_VMCODE_METHOD_FRAME opcode, which the
interpreter returns without unwinding the frame).

Usage: python3 tostr_cases.py OUTDIR

Writes OUTDIR/<case>.js and OUTDIR/cases.tsv with the columns case, group,
trigger, context, observe, absent, faulty. Each script defines the printer
below, performs one method call whose key conversion fails (or a control)
inside a same-frame try/catch, and prints one deterministic line describing
the surrounding synchronous control flow, so that njs and the reference
engine print the same text when njs is correct. The expected output is the
reference engine's output on the same file (scripts/njs_cases.py --oracle).

Mechanism of the note. njs_vmcode_interpreter() (src/njs_vmcode.c at the
image tree 7bd570b3) runs the opcode loop and, on an opcode error, is meant
to reach the common `error:` label, which offers the exception to the
current frame's catch and unwinds the active frames (njs_vm_scopes_restore)
before returning NJS_ERROR. The base NJS_VMCODE_METHOD_FRAME case, on the
branch where the looked-up property is not a function, converts the key to a
string to build the "...is not a function" TypeError (njs_value_to_key at
base line 757). On a conversion failure the base returns NJS_ERROR directly
(`return NJS_ERROR`), so the current frame's catch is skipped and its frame
is left as vm->top_frame / vm->active_frame while the interpreter returns to
the caller. The observable consequence is that a try/catch in the same frame
as the call does not catch the TypeError (the error escapes to an enclosing
frame); a later operation that consults the frame state (in the dataset PoC,
String.fromCharCode converting a function argument to a number, which reads
an object property through njs_object_property -> njs_lvlhsh_find) reads
stale state and faults. The developer patch (upstream 222d6fdc) makes this
error exit `goto error` (and writes the converted key to a local rather than
clobbering the key operand in place). The violated invariant: every NJS_ERROR
exit of the opcode loop passes through `error:`.

njs evaluates the key twice on this path: once at the property access
(base line 751) and once to build the error message (line 757). The bug is
reached only when the first conversion succeeds and the second fails, so the
trigger makes the key's to-string conversion break after its first use.
A conversion that fails on its first use fails at line 751, which already
reaches `error:` (a control); a conversion that always succeeds yields a
normal "not a function" TypeError, also at `error:` (a control).

Triggers (all reach NJS_VMCODE_METHOD_FRAME with a non-function property and
fail the second conversion):
  selfmod   key.toString returns a non-method name on its first call and
            throws on its second call (a per-key call counter; self-contained).
  unittest  Object.prototype.toString is a function that reassigns
            Object.prototype.toString to a non-callable on its first call,
            the dataset unit-test / PoC shape; used only in the single-call
            contexts because it corrupts global state.
Controls (reach NJS_VMCODE_METHOD_FRAME but do not fail the second
conversion; all caught by the same-frame try/catch on every build):
  throwfirst key.toString throws on its first call (the conversion fails at
            the property access, line 751, which already unwinds).
  goodkey   key.toString always returns a non-method name (a normal "not a
            function" TypeError, correctly unwound).
  strkey    a string key that names no method (a normal TypeError).
Valid (a method call that resolves to a real function; OK on every build):
  validcall a real method call that returns a value.

Contexts (the frame that holds the same-frame try/catch around the call):
  top    the call at the module top level.
  fn     the call inside host(), host() returns the caught result.
  fntry  the call inside host(), then a second independent try/throw/catch.
  recN   the call at the bottom of N nested host() frames.
  loop2  two calls in a row, each in its own same-frame try/catch.
  poc    the dataset PoC shape; a crash under a deep enough frame/heap state.
The observable is the surrounding synchronous control flow (whether the
same-frame catch runs), never a message text that differs between engines.

Column faulty is 1 when the case reaches the second-conversion failure (every
trigger case, top included, because the base skips the same-frame catch at
every frame depth). Column absent is "none" only for the controls and valid
cases, whose output is identical on every build (the digest covers them);
else the group name. The dataset PoC is added by the runner as "poc". Syntax
is limited to what njs at the image tree parses.
"""
import sys
from pathlib import Path

PRELUDE = r"""
function run(f) {
    var r;
    try { r = f(); } catch (e) { r = 'threw:' + (e && e.name ? e.name : String(e)); }
    console.log(String(r));
}
"""

# Each trigger is a statement block: it sets up the key and calls 's'[k](),
# whose error (if any) propagates to the enclosing same-frame try/catch.
TRIGGERS = {
    "selfmod": (
        "var n = 0;\n"
        "        var k = { toString: function(){ n++; if (n >= 2) { throw new TypeError('boom'); } return 'nope'; } };\n"
        "        's'[k]();"
    ),
    "unittest": (
        "Object.prototype.toString = function(){ Object.prototype.toString = 1; };\n"
        "        's'[{}]();"
    ),
    # controls: reach METHOD_FRAME but do not fail the second conversion
    "throwfirst": (
        "var k = { toString: function(){ throw new TypeError('boom'); } };\n"
        "        's'[k]();"
    ),
    "goodkey": (
        "var k = { toString: function(){ return 'nope'; } };\n"
        "        's'[k]();"
    ),
    "strkey": (
        "'s'['nope']();"
    ),
    # valid: a real method call that resolves to a function
    "validcall": (
        "var r0 = 'ab'['indexOf']('b');"
    ),
}

# faulty triggers: selfmod runs in every context; unittest only in the
# single-call contexts (it corrupts Object.prototype.toString globally).
TRIG_ALL = ("selfmod",)
TRIG_SINGLE = ("unittest",)
CTL = ("throwfirst", "goodkey", "strkey")

REC = {"rec1": 1, "rec2": 2, "rec3": 3}
ALL_CTX = ["top", "fn", "fntry", "rec1", "rec2", "rec3", "loop2"]
SINGLE_CTX = ["top", "fn", "fntry"]
CTL_CTX = ["fn", "fntry", "rec2"]


def mk(name, group, trigger, context, faulty, body):
    return dict(name=name, group=group, trigger=trigger, context=context,
                faulty=faulty,
                absent="none" if group in ("ctl", "valid") else group, body=body)


def cases():
    out = []
    for trigger in TRIG_ALL:
        for ctx in ALL_CTX:
            out.append(mk("trig_%s_%s" % (trigger, ctx), "trig_%s" % trigger,
                          trigger, ctx, 1, wrap(trigger, ctx)))
    for trigger in TRIG_SINGLE:
        for ctx in SINGLE_CTX:
            out.append(mk("trig_%s_%s" % (trigger, ctx), "trig_%s" % trigger,
                          trigger, ctx, 1, wrap(trigger, ctx)))
    for trigger in CTL:
        for ctx in CTL_CTX:
            out.append(mk("ctl_%s_%s" % (trigger, ctx), "ctl", trigger, ctx, 0,
                          wrap(trigger, ctx)))
    for ctx in CTL_CTX:
        out.append(mk("valid_validcall_%s" % ctx, "valid", "validcall", ctx, 0,
                      wrap("validcall", ctx)))
    out.append(mk("valid_plain", "valid", "-", "fn", 0,
                  "run(function host() { return 'after-call'; });"))
    out.append(mk("valid_try", "valid", "-", "fntry", 0,
                  "run(function host() { var hit; try { throw 'QQ'; } catch (e) { hit = 'caught:' + e; } return hit; });"))
    return out


def trycatch(stmt):
    """A same-frame try/catch around the trigger, yielding a deterministic
    token for whether the catch ran."""
    return ("var r = 'ESCAPED';\n"
            "        try { %s } catch (e) { r = 'caught:' + (e && e.name ? e.name : String(e)); }" % stmt)


def wrap(trigger, ctx):
    stmt = TRIGGERS[trigger]
    if ctx == "top":
        body = trycatch(stmt).replace("\n        ", "\n")
        return "%s\nconsole.log(r);" % body
    if ctx == "fn":
        return ("run(function host() {\n"
                "        %s\n"
                "        return r;\n"
                "    });") % trycatch(stmt)
    if ctx == "fntry":
        return ("run(function host() {\n"
                "        %s\n"
                "        var r2 = 'no';\n"
                "        try { throw 'QQ'; } catch (e) { r2 = 'c:' + e; }\n"
                "        return r + '|' + r2;\n"
                "    });") % trycatch(stmt)
    if ctx in REC:
        n = REC[ctx]
        return ("(function() {\n"
                "    function host(depth) {\n"
                "        if (depth > 0) { return 'd' + depth + ':' + host(depth - 1); }\n"
                "        %s\n"
                "        return r;\n"
                "    }\n"
                "    run(function() { return host(%d); });\n"
                "    })();") % (trycatch(stmt), n)
    if ctx == "loop2":
        return ("run(function host() {\n"
                "        var a = 'ESCAPED';\n"
                "        try { %s } catch (e) { a = 'caught:' + (e && e.name ? e.name : String(e)); }\n"
                "        var b = 'ESCAPED';\n"
                "        try { %s } catch (e) { b = 'caught:' + (e && e.name ? e.name : String(e)); }\n"
                "        return a + '|' + b;\n"
                "    });") % (stmt, stmt)
    raise AssertionError(ctx)


def main(outdir):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    cs = cases()
    names = [c["name"] for c in cs]
    assert len(names) == len(set(names)), "duplicate case names"
    cols = ["name", "group", "trigger", "context", "absent", "faulty"]
    with open(outdir / "cases.tsv", "w") as f:
        f.write("case\tgroup\ttrigger\tcontext\tabsent\tfaulty\n")
        for c in cs:
            f.write("\t".join(str(c[k]) for k in cols) + "\n")
    for c in cs:
        (outdir / (c["name"] + ".js")).write_text(PRELUDE + c["body"] + "\n")
    print(len(cs), "cases")


if __name__ == "__main__":
    main(sys.argv[1])
