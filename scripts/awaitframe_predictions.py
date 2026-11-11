"""Per-case predictions for njs.cve-2022-27007, printed as a TSV for
scripts/check_predictions.py.

Usage: python3 awaitframe_predictions.py > scripts/awaitframe_predictions.tsv

Columns are <model>:<variant>. Classes: OK (output equals the Node.js
v20.9.0 reference), WRONG (differs), ASAN (a sanitizer report), INV (the
AWAITFRAME-INVARIANT instrumentation fired), - (no prediction).

Hypothesis (ours). The reported failure is a heap use-after-free: at `await`,
njs_function_frame_save copies the active frame including its spare-memory
fields native->{size,free,free_size}; the original frame is then freed; on
resume a child frame is allocated from the saved frame, whose fast-path reuse
(njs_function_frame_alloc, size <= free_size) writes into the freed original
chunk. The crash needs the original frame to have used the large-allocation
path (njs_mp_alloc_large/posix_memalign, freed with free()), which happens
only for a deep enough recursion; shallow async recursion and a single
await-then-call stay on the fast path and do not crash (the depth sweep on the
base build: no report at depth 10, heap-use-after-free from depth 30).
  - deep awaited/non-awaited recursion (depth >= 30) and the PoC reach the
    faulty state: ASAN on base, OK after the patch (fresh allocation), OK at
    upstream master. The AWAITFRAME-INVARIANT instrumentation fires on the
    large-allocation save (native->size != 0), so assert_before is INV and
    assert_after is OK.
  - the shallow awaited recursion (depth 10), the await-then-return controls
    and the no-await / sync controls stay on the fast path or save no frame:
    OK on every build, and no AWAITFRAME-INVARIANT (native->size == 0 at the
    save), so assert_before is OK.

Developer model (dev). Commit ad48705b ("Fixed frame allocation from an
awaited frame.") names allocating a frame from an awaited frame as the fault,
with no depth qualification, so the dev model predicts a sanitizer report for
every case that allocates a child frame after an await (the deep cases, the
PoC, and the shallow awaited recursion), and OK for the await-then-return and
no-await controls. It mispredicts the shallow awaited recursion (depth 10),
which allocates frames from awaited frames but stays on the fast path and does
not crash: 1 contradiction. dev:after is OK for every case.

Written 2026-11-04 after scripts/awaitframe_cases.py and the Node oracle
(scripts/awaitframe_expected.tsv), from the mechanism and the base-build depth
sweep, before the `before` njs variant was run.
"""
import sys

COLS = ["ours:before", "ours:after", "ours:assert_before", "ours:assert_after",
        "ours:upstream_master", "dev:before", "dev:after"]

# (ours:before, ours:after, ours:assert_before, ours:assert_after,
#  ours:upstream_master, dev:before, dev:after)
FAULTY = ("ASAN", "OK", "INV", "OK", "OK", "ASAN", "OK")
CONTROL = ("OK", "OK", "OK", "OK", "OK", "OK", "OK")
SHALLOW = ("OK", "OK", "OK", "OK", "OK", "ASAN", "OK")  # dev model mispredicts

P = [
    ("deep_await_d30", FAULTY),
    ("deep_await_d60", FAULTY),
    ("deep_await_d100", FAULTY),
    ("deep_prom_d60", FAULTY),
    ("deep_noawait_d60", FAULTY),
    ("shallow_await_d10", SHALLOW),
    ("ac_ret", CONTROL),
    ("ac_twoawait", CONTROL),
    ("na_asyncret", CONTROL),
    ("na_sync", CONTROL),
    ("na_arith", CONTROL),
    ("poc", FAULTY),
]


def main():
    print("case\t" + "\t".join(COLS))
    for name, row in P:
        print(name + "\t" + "\t".join(row))


if __name__ == "__main__":
    main()
