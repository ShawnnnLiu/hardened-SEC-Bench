"""Write the JavaScript case files for njs.cve-2022-27007 (a heap
use-after-free when a child frame is allocated from a saved async frame
whose spare-memory pointer was inherited from the now-freed original frame).

Usage: python3 awaitframe_cases.py OUTDIR

Writes OUTDIR/<case>.js and OUTDIR/cases.tsv with the columns case, group,
depth, absent, faulty. Each script prints one deterministic line that njs
and the reference engine (Node.js v20.9.0) print identically when njs is
correct; the expected output is the reference engine's output on the same
file (scripts/njs_cases.py --oracle). The dataset PoC is added by the
runner as case "poc" (expected to print nothing and end without a sanitizer
report).

Mechanism of the note. At `await`, njs_vmcode_await() saves the async
function's frame with njs_function_frame_save() (src/njs_function.c), which
copies *vm->active_frame into a heap njs_frame_t, carrying the original
frame's spare-memory allocator fields native->{size,free,free_size}; it then
returns through njs_vmcode_return(), which frees the original frame. On the
microtask, njs_await_fulfilled() (src/njs_async.c) sets vm->top_frame to the
saved frame and resumes the body. A call made by the resumed body runs
njs_function_frame_alloc(vm, size) (src/njs_function.c:544), whose fast path
reuses vm->top_frame->free when size <= vm->top_frame->free_size; the saved
frame's free points into the freed original chunk, so njs_memzero at
src/njs_function.c:574 writes into freed memory (the reported
heap-use-after-free WRITE). The developer patch (upstream ad48705b) sets
native->size = 0, native->free = NULL, native->free_size = 0 on the saved
frame, so free_size == 0 forces a fresh allocation and the freed spare is
never reused. The violated invariant: a frame saved by njs_function_frame_save
must not advertise reusable spare memory (native->free_size) pointing into the
original frame's allocation.

Depth gate. The crash needs the original frame to have been allocated on the
large path (njs_mp_alloc_large -> posix_memalign, freed with free()), which
happens only when the recursion is deep enough to exhaust the initial spare;
shallow async recursion and a single await-then-call stay on the fast path
(native->size == 0, no free()), so they do not crash. The sweep on the base
build (logs, morning report) shows the heap-use-after-free from depth 30
onward and no report at depth 10. Faulty cases therefore use depth >= 30 and
the shallow control uses depth 10.

Column faulty is 1 when the case reaches the faulty state (a deep awaited
recursion that reuses a large-allocation saved frame's spare). Column absent
is "none" for the cases whose output is stable on every build (the controls,
covered by the valid-output digest); the deep cases have absent "deep"
because on the base build they give a sanitizer report (and under the
instrumentation an AWAITFRAME-INVARIANT abort) instead of their line. Syntax
is limited to what njs at the base commit e673ae41 parses.

Predictions (scripts/awaitframe_predictions.py / .tsv) were written after this
generator and the Node oracle, from the mechanism above and the depth sweep,
before the `before` njs variant was run.
"""
import sys
from pathlib import Path


def rec_await(depth, awaitexpr="1"):
    # bounded awaited recursion (the developer-test shape): push each level,
    # await, then await the recursive call. Prints "<n>:<first>,<last>".
    return (
        "var s = [];\n"
        "async function f(v) {\n"
        "    if (v >= %d) { return; }\n"
        "    s.push(v);\n"
        "    await %s;\n"
        "    await f(v + 1);\n"
        "}\n"
        "f(0).then(function () {\n"
        "    console.log(s.length + ':' + s[0] + ',' + s[s.length - 1]);\n"
        "});" % (depth, awaitexpr)
    )


def rec_noawait(depth):
    # the PoC shape bounded: the recursive call is not awaited. The chain
    # completes through the microtask queue; print from the base case.
    return (
        "var done = 0;\n"
        "async function f(v) {\n"
        "    if (v >= %d) { done = v; console.log('end:' + done); return; }\n"
        "    await 1;\n"
        "    f(v + 1);\n"
        "}\n"
        "f(0);" % depth
    )


CASES = []


def add(name, group, depth, absent, faulty, body):
    CASES.append(dict(name=name, group=group, depth=depth, absent=absent,
                      faulty=faulty, body=body))


# Faulty: deep awaited recursion (depth >= 30), one per depth and one awaiting
# a resolved promise; and the non-awaited (PoC) shape at depth 60.
add("deep_await_d30", "deep", 30, "deep", 1, rec_await(30))
add("deep_await_d60", "deep", 60, "deep", 1, rec_await(60))
add("deep_await_d100", "deep", 100, "deep", 1, rec_await(100))
add("deep_prom_d60", "deep", 60, "deep", 1, rec_await(60, "Promise.resolve(1)"))
add("deep_noawait_d60", "deep", 60, "deep", 1, rec_noawait(60))

# Shallow control: awaited recursion depth 10 (reaches the await-save path but
# stays on the fast path, no crash).
add("shallow_await_d10", "shallow", 10, "none", 0, rec_await(10))

# await-then-return controls (await, no frame allocation after the resume).
add("ac_ret", "awaitctl", 1, "none", 0,
    "async function g() { await 1; return 7; }\n"
    "g().then(function (v) { console.log('r' + v); });")
add("ac_twoawait", "awaitctl", 2, "none", 0,
    "async function g() { var a = await 2; var b = await 3; return a + b; }\n"
    "g().then(function (v) { console.log('' + v); });")

# no-await / sync controls (no frame save).
add("na_asyncret", "noawait", 0, "none", 0,
    "async function g() { return 9; }\n"
    "g().then(function (v) { console.log('n' + v); });")
add("na_sync", "noawait", 0, "none", 0,
    "function h() { return 5; }\n"
    "console.log('s' + h());")
add("na_arith", "noawait", 0, "none", 0, "console.log('' + (1 + 2 + 3));")


def main(outdir):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    names = [c["name"] for c in CASES]
    assert len(names) == len(set(names)), "duplicate case names"
    cols = ["name", "group", "depth", "absent", "faulty"]
    with open(outdir / "cases.tsv", "w") as f:
        f.write("case\tgroup\tdepth\tabsent\tfaulty\n")
        for c in CASES:
            f.write("\t".join(str(c[k]) for k in cols) + "\n")
    for c in CASES:
        (outdir / (c["name"] + ".js")).write_text(c["body"] + "\n")
    print(len(CASES), "cases")


if __name__ == "__main__":
    main(sys.argv[1])
