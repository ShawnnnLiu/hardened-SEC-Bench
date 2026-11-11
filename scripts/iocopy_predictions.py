"""Predicted result class of every case of scripts/iocopy_cases.tsv under each
hypothesis, for scripts/check_predictions.py (mruby.cve-2018-10199).

Prints a TSV with one column per <model>:<variant>. Classes are OK, WRONG, ASAN
(an AddressSanitizer or LeakSanitizer report), INV (an IOCOPY-INVARIANT abort
from the assertion variant) or -.

dev: the developer's model, from issue #4001 (the fix commit "Fix `use after free
  in File#initilialize_copy`; fix #4001" and the bug report): "calling
  File#initialize_copy with an invalid argument causes the function to terminate
  early, leaving a dangling pointer in the receiver's DATA_PTR." The fix moves the
  argument validation (io_get_open_fptr) before the free. This model predicts a
  crash on the base for an open receiver (whose old struct is freed) with an
  argument that makes io_get_open_fptr raise (families r, u) and a complete fix
  by the patch (after: OK). Its stated consequence is a dangling pointer in the
  RECEIVER's DATA_PTR; it does not name the dup-closed leak (family d, where the
  receiver is fresh so DATA_PTR is not left dangling) or the self copy (family s,
  where the argument is a valid open IO, reported separately as #4005). So the
  dev model predicts OK for d and s on both builds; the contradictions are the
  base leak (d) and the self-copy use-after-free that the dev patch does not fix
  (s, before and after).

ours: H1, the reported failure. mrb_io_initialize_copy (io.c:555) frees the
  receiver's old struct (566-567), allocates a new one (569), then calls
  io_get_open_fptr(orig) (570) which raises TypeError (non-IO argument) or IOError
  (closed argument) BEFORE storing the new pointer (573): the receiver's DATA_PTR
  is left pointing to the freed old struct (read at the next use or at exit-time
  GC finalization) and the new struct is leaked. Family r (open receiver, raising
  argument, no later use): base ASAN (use-after-free at exit), after OK (the moved
  validation raises before the free; receiver unchanged -> CRuby's TypeError or
  IOError). Family u (the same, with one use of the receiver after the rescue):
  base ASAN (the use reads/writes the dangling struct), after OK. Family d (dup of
  a closed IO, a fresh receiver): base ASAN (the new struct is leaked while
  io_get_open_fptr raises after mrb_io_alloc), after OK (the moved validation
  raises before the alloc). The gold patch (SEC-bench model_patch.diff, adds the
  validation at the top but keeps the later call) fixes r, u and d the same way:
  gold OK.
  H2, the self copy (family s): when orig and copy are the same open IO, the free
  frees the struct both point to. On the base io_get_open_fptr(orig) then reads
  the freed struct's fd; after the developer patch io_get_open_fptr runs first and
  returns the live struct, but the free still frees it and mrb_dup(fptr_orig->fd)
  reads it (the #4005 report); the gold patch's second io_get_open_fptr reads the
  freed struct. So s is ASAN on before, after and gold. Upstream commit c9275bbb
  (dev + `if (fptr_orig == fptr_copy) return copy;`) returns before the free:
  dev_c9275bbb OK. The self guard placed on the base after io_get_open_fptr
  (selfguard_alone) is a no-op (there fptr_copy is the freshly allocated struct,
  not DATA_PTR(copy), and the self-copy crash is earlier inside io_get_open_fptr):
  selfguard_alone reproduces the base (r, u, d, s all ASAN). This shows the self
  guard alone fixes nothing and the self copy needs the dev patch's reordering
  plus the guard (a separate fix at a separate site -> residual).
  H3, assertion. scripts/iocopy_invariant_before.diff aborts with IOCOPY-INVARIANT
  before io_get_open_fptr when the old struct was freed in this call and orig would
  raise (dangling) or orig is the same freed struct (self); it fires on families r,
  u (dangling) and s (self) but not d (no free of the receiver) -> assert_before
  INV on r, u, s and ASAN (leak) on d. scripts/iocopy_invariant_after.diff (on the
  developer-patched tree) keeps only the self check after the free; the moved
  validation raises before the free for r, u and d, so only s reaches it ->
  assert_after INV on s, OK elsewhere.
  Families v (valid copies) and c (controls, IO#initialize re-init which validates
  the mode before the free, and no-IO) never reach the faulty state: OK on every
  build.

This file was written on 2026-11-07 before the before variant ran. Known when it
was written: poc_before.log (the use-after-free at exit, frames fptr_finalize /
mrb_io_free / obj_free; freed by mrb_io_initialize_copy), poc_after.log (no
sanitizer report; TypeError), and the CRuby 2.7.0 values of
scripts/iocopy_expected.tsv; no case of the table had been run with mruby.
"""
import csv
import sys

COLS = ["dev:before", "dev:after", "ours:before", "ours:after",
        "ours:assert_before", "ours:assert_after", "ours:gold",
        "ours:dev_c9275bbb", "ours:selfguard_alone"]

#            dev:b  dev:a  o:b    o:a    o:asb  o:asa  o:gold o:c9275 o:sg
ROW = {
    "r": ["ASAN", "OK",  "ASAN", "OK",  "INV",  "OK",  "OK",  "OK",  "ASAN"],
    "u": ["ASAN", "OK",  "ASAN", "OK",  "INV",  "OK",  "OK",  "OK",  "ASAN"],
    "d": ["OK",   "OK",  "ASAN", "OK",  "ASAN", "OK",  "OK",  "OK",  "ASAN"],
    "s": ["OK",   "OK",  "ASAN", "ASAN","INV",  "INV", "ASAN","OK",  "ASAN"],
    "v": ["OK",   "OK",  "OK",   "OK",  "OK",   "OK",  "OK",  "OK",  "OK"],
    "c": ["OK",   "OK",  "OK",   "OK",  "OK",   "OK",  "OK",  "OK",  "OK"],
}


def group(name):
    return name.split("_", 1)[0]


cases = [r[0] for r in csv.reader(open(sys.argv[1] if len(sys.argv) > 1 else
                                       "scripts/iocopy_cases.tsv"), delimiter="\t")]
print("case\t" + "\t".join(COLS))
for n in cases:
    g = group(n)
    assert g in ROW, n
    print(n + "\t" + "\t".join(ROW[g]))
