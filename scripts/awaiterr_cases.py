"""Write the JavaScript case files for njs.cve-2022-34029 (a synchronous
await failure that the interpreter returns without unwinding the frame).

Usage: python3 awaiterr_cases.py OUTDIR

Writes OUTDIR/<case>.js and OUTDIR/cases.tsv with the columns case, group,
trigger, context, observe, absent, faulty. Each script defines the printer
below, runs one async call whose await fails synchronously in njs, and prints
one deterministic line describing the surrounding synchronous control flow,
so that njs and the reference engine print the same text when njs is correct.
The expected output is the reference engine's output on the same file
(scripts/njs_cases.py --oracle).

Mechanism of the note. njs_vmcode_interpreter() (src/njs_vmcode.c at the base
commit d493f891) runs the opcode loop and, on an opcode error, is meant to
reach the common `error:` label, which unwinds the active frames
(njs_vm_scopes_restore) before returning NJS_ERROR. One opcode returns the
error of its helper directly: the NJS_VMCODE_AWAIT case does
`return njs_vmcode_await(...)`. njs_vmcode_await() returns NJS_ERROR
synchronously when the awaited value cannot be resolved, so a failed await
inside an async function leaves that function's frame as vm->top_frame /
vm->active_frame while the interpreter returns to the caller; a later operand
fetch (njs_scope_valid_value -> njs_scope_value, src/njs_scope.h) in the
caller dereferences a scope-level vector that describes the freed frame. The
developer patch (upstream d09868bc) makes the AWAIT error exit `goto error`,
so the frame is unwound first. The violated invariant: every NJS_ERROR exit
of the opcode loop passes through `error:`.

Two triggers make njs_vmcode_await() return NJS_ERROR synchronously:
  ctor  await a native Promise whose `constructor` accessor throws; njs reads
        the constructor while resolving the awaited value (njs_promise_resolve),
        so the getter throws inside the AWAIT opcode. The reference engine does
        not read `constructor` when awaiting a native promise, so it does not
        fail the await; both engines run the surrounding synchronous code the
        same way when njs is correct.
  tdz   await an uninitialised let/const binding; njs_scope_valid_value() for
        await->retval returns NULL ("cannot access variable before
        initialization") inside the AWAIT opcode, before any promise setup.
Controls that reach the AWAIT opcode but do not fail synchronously (OK on
every build): a throwing `then` accessor on a non-promise thenable (read on a
later tick, not in the opcode), and valid awaits (Promise.resolve, a plain
value, a pending promise).

Contexts (what surrounds the async call, deciding whether the un-unwound frame
corrupts an observable computation):
  top    g() at the module top level, then a following statement; the failed
         await has no caller frame to damage, so the base build runs the
         following statement (documented boundary: OK on every build).
  fn     g() inside host(), which then returns a value; the base build returns
         undefined instead (wrong result).
  fntry  g() inside host(), then a try/throw/catch whose caught value host()
         returns.
  recN   N nested host() calls (each caught) before the async call.
  loop2  two async calls in a row before the observation.
  poc    the dataset PoC shape (recursion, an async call, then an uncaught
         throw); a crash under a deep enough frame/heap state.
The observable is the surrounding synchronous control flow (host()'s return
value, whether a catch runs), never the rejection of the async function, which
is swallowed with .catch and differs in wording between the engines.

Column faulty is 1 when the case reaches the synchronous await failure in a
context that exposes it (a ctor or tdz trigger inside a function). The top
cases also reach the synchronous await failure, but with no caller frame to
corrupt, so their faulty flag is 0 and their symptom is benign; they are
still excluded from the valid-output digest (absent "top"), because under the
STACK-INVARIANT instrumentation they abort at the failed await before the
following statement runs. Column absent is "none" only for the controls and
valid cases, whose output is identical on every build (the digest covers
them); else the group name. The dataset PoC is added by the runner as "poc".
Syntax is limited to what njs at the base commit parses.
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

# JavaScript that builds the awaited value and the async call, given a trigger.
TRIGGERS = {
    "ctor": (
        "var p = new Promise(function(){});\n"
        "    Object.defineProperty(p, 'constructor', {get: function(){ throw new Error('boom'); }});\n"
        "    async function g(){ await p; }\n"
        "    g().catch(function(){});"
    ),
    "tdz": (
        "async function g(){ await x; let x; }\n"
        "    g().catch(function(){});"
    ),
    # controls: reach the AWAIT opcode but do not fail synchronously
    "then": (
        "var t = {};\n"
        "    Object.defineProperty(t, 'then', {get: function(){ throw new Error('boom'); }});\n"
        "    async function g(){ await t; }\n"
        "    g().catch(function(){});"
    ),
    "resolve": (
        "async function g(){ await Promise.resolve(1); }\n"
        "    g().catch(function(){});"
    ),
    "value": (
        "async function g(){ await 42; }\n"
        "    g().catch(function(){});"
    ),
    "pending": (
        "async function g(){ await new Promise(function(){}); }\n"
        "    g().catch(function(){});"
    ),
}

TRIG = ("ctor", "tdz")            # reach the faulty state in a non-bare context
CTL = ("then", "resolve", "value", "pending")


REC = {"rec1": 1, "rec2": 2, "rec3": 3}


def mk(name, group, trigger, context, observe_kind, faulty, body):
    return dict(name=name, group=group, trigger=trigger, context=context,
                observe=observe_kind, faulty=faulty,
                absent="none" if group in ("ctl", "valid") else group, body=body)


def cases():
    out = []
    contexts = ["top", "fn", "fntry", "rec1", "rec2", "rec3", "loop2"]
    # trigger cases
    for trigger in TRIG:
        for ctx in contexts:
            faulty = 0 if ctx == "top" else 1
            group = "top" if ctx == "top" else "trig"
            out.append(mk("%s_%s_%s" % (group, trigger, ctx), group, trigger, ctx,
                          ctx, faulty, host_wrap(trigger, ctx)))
    # control cases (reach AWAIT, no synchronous failure)
    for trigger in CTL:
        for ctx in ["fn", "fntry", "rec2"]:
            out.append(mk("ctl_%s_%s" % (trigger, ctx), "ctl", trigger, ctx,
                          ctx, 0, host_wrap(trigger, ctx)))
    # plain valid controls without any async (sanity of the harness)
    out.append(mk("valid_plain", "valid", "-", "fn", "fn", 0,
                  "run(function host() { return 'after-call'; });"))
    out.append(mk("valid_try", "valid", "-", "fntry", "fntry", 0,
                  "run(function host() { var hit; try { throw 'QQ'; } catch (e) { hit = 'caught:' + e; } return hit; });"))
    return out


def host_wrap(trigger, ctx):
    """Build the full script body for a trigger in a context."""
    trig = TRIGGERS[trigger]
    trig_indent = trig.replace("\n    ", "\n        ")
    if ctx == "top":
        # genuine module top level: no enclosing function frame
        return ("%s\n"
                "console.log('after-call');") % trig.replace("\n    ", "\n")
    if ctx == "fn":
        return ("run(function host() {\n"
                "        %s\n"
                "        return 'after-call';\n"
                "    });") % trig_indent
    if ctx == "fntry":
        return ("run(function host() {\n"
                "        %s\n"
                "        var hit;\n"
                "        try { throw 'QQ'; } catch (e) { hit = 'caught:' + e; }\n"
                "        return hit;\n"
                "    });") % trig_indent
    if ctx in REC:
        n = REC[ctx]
        return ("(function() {\n"
                "    function host(depth) {\n"
                "        if (depth > 0) { try { host(depth - 1); } catch (e) {} }\n"
                "        %s\n"
                "        var hit;\n"
                "        try { throw 'QQ'; } catch (e) { hit = 'caught:' + e; }\n"
                "        return depth === %d ? hit : ('d' + depth);\n"
                "    }\n"
                "    run(function() { return host(%d); });\n"
                "    })();") % (trig_indent, n, n)
    if ctx == "loop2":
        return ("run(function host() {\n"
                "        %s\n"
                "        %s\n"
                "        return 'after-two';\n"
                "    });") % (trig_indent, trig_indent)
    raise AssertionError(ctx)


def main(outdir):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    cs = cases()
    names = [c["name"] for c in cs]
    assert len(names) == len(set(names)), "duplicate case names"
    cols = ["name", "group", "trigger", "context", "observe", "absent", "faulty"]
    with open(outdir / "cases.tsv", "w") as f:
        f.write("case\tgroup\ttrigger\tcontext\tobserve\tabsent\tfaulty\n")
        for c in cs:
            f.write("\t".join(str(c[k]) for k in cols) + "\n")
    for c in cs:
        (outdir / (c["name"] + ".js")).write_text(PRELUDE + c["body"] + "\n")
    print(len(cs), "cases")


if __name__ == "__main__":
    main(sys.argv[1])
