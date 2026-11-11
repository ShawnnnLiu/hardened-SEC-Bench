"""Per-case predictions for njs.cve-2019-13617 (heap-buffer-overflow read
while parsing an unterminated regexp literal in njs_regexp_literal).

Prints scripts/relit_predictions.tsv: a header `case<TAB><model>:<variant>`
and one row per case, each cell a predicted class (OK, WRONG, ASAN, INV,
or - for no prediction).  scripts/check_predictions.py compares it with
the case logs.

This file was written on 2026-10-28 before the before variant ran; the
only prior observation was the dataset PoC on the base build (poc_before.log).

Case families (scripts/relit_cases.py): crash = an unterminated regexp
literal whose scan ends inside the character-class loop (cls), the
character-class backslash (clsbs) or the outer backslash (outbs); plain =
an unterminated literal with no class and no trailing backslash; valid = a
terminated literal whose match is printed.

ours (the invariant hypotheses):
  H1  The reported heap-buffer-overflow read happens exactly when the
      scan pointer p is left strictly past lexer->end at the failed:
      label of njs_regexp_literal, so that the span p - (lexer->start - 1)
      passed to njs_vsprintf as the "%*s" width exceeds the input buffer
      and njs_cpymem reads past the heap region holding the source.  On
      the base build the three scan paths cls, clsbs and outbs each step p
      past lexer->end when the literal ends inside them, so cls_bare,
      cls_tail, clsbs_tail and outbs_tail are ASAN on before.
  H2  The plain path exits the outer for-loop at p == lexer->end (not
      past): the span then reads exactly to the buffer end, in bounds, so
      plain is OK (a clean SyntaxError, empty stdout) on before, and the
      instrumented check (p > lexer->end) does not fire for it.
  H3  A valid (terminated) literal returns NJS_TOKEN_REGEXP and never
      reaches failed:; the patch does not change its match, so val_* is OK
      on every build and never INV.
  The developer patch makes the three scan paths stop at lexer->end, so
  after, assert_after and upstream_master have p <= lexer->end at failed:
  for every case: no ASAN, no INV, all OK.  assert_before fires INV on
  exactly the four cases that leave p past the end (the crash family minus
  plain).

dev (the developer's model, from commit ee400ea8 "Fixed heap-buffer-overflow
while parsing regexp literals." and its added unit tests /[, /[\, new
RegExp('['), new RegExp('['.repeat(16))):
  The message names the construct (parsing regexp literals) and the patch
  rewrites the character-class loop, the character-class backslash and the
  outer backslash, so the dev model predicts cls_bare, cls_tail,
  clsbs_tail and outbs_tail ASAN on before and OK after.  The patch leaves
  the plain path and valid parsing unchanged, so the dev model predicts
  plain and val_* OK on both builds.  The dev model has no INV class.
"""

# case -> (kind, site).  poc is the dataset PoC (/testcase/tmp.js), an
# unterminated character class with many '[' bytes: the cls path.
CASES = [
    ("cls_bare", "crash", "cls"),
    ("cls_tail", "crash", "cls"),
    ("clsbs_tail", "crash", "clsbs"),
    ("outbs_tail", "crash", "outbs"),
    ("plain", "crash", "plain"),
    ("val_cls", "valid", "cls"),
    ("val_clsbs", "valid", "clsbs"),
    ("val_outbs", "valid", "outbs"),
    ("val_plain", "valid", "plain"),
    ("poc", "crash", "cls"),
]

COLS = [
    "dev:before", "dev:after",
    "ours:before", "ours:after",
    "ours:assert_before", "ours:assert_after",
    "ours:upstream_master",
]


def predict(name, kind, site):
    over = kind == "crash" and site in ("cls", "clsbs", "outbs")  # leaves p past end
    # dev
    dev_before = "ASAN" if over else "OK"
    dev_after = "OK"
    # ours
    ours_before = "ASAN" if over else "OK"
    ours_after = "OK"
    ours_assert_before = "INV" if over else "OK"
    ours_assert_after = "OK"
    ours_master = "OK"
    return [dev_before, dev_after, ours_before, ours_after,
            ours_assert_before, ours_assert_after, ours_master]


def main():
    print("case\t" + "\t".join(COLS))
    for name, kind, site in CASES:
        print(name + "\t" + "\t".join(predict(name, kind, site)))


if __name__ == "__main__":
    main()
