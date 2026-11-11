"""Predictions for the cases of scripts/prep13_cases.py (libredwg.cve-2021-28237).

This file was written on 2026-10-28 at 09:10 EDT (13:10 UTC), before any
variant of this instance ran. Before it, only the two anchor measurements
of the base and developer-patch builds were taken (the reused stage logs
poc_before.log and poc_after.log, and the entry-count trace of ACEB10:
56 on base, 0 after the developer patch); the variants before, after, root
and upstream_master had not been run through the case runner.

Usage: python3 prep13_predictions.py > prep13_predictions.tsv

Columns, one per <model>:<variant>:
  before           base commit (image tree 49aeec4e)
  after            developer patch ea0b9522 (the added PREP_TABLE guard)
  root             scripts/prep13_rootcand.diff (base + an unconditional
                   realloc sized for num + tbl->number objects, without the
                   developer guard)
  upstream_master  upstream master, whole tree
  assert_before    base + scripts/prep13_invariant_before.diff
  assert_after     developer patch + scripts/prep13_invariant_after.diff
A cell is OK, WRONG, ASAN, INV or - (no prediction).

Revision of 2026-11-04, before any variant of this instance ran: the
columns ours:assert_before and ours:assert_after were added for the
instrumentation written the same day (scripts/prep13_make_invariant.py);
the other columns are unchanged. The TSV of 2026-10-28 (sha256 195aaf54...)
was never checked against a case log.

Hypothesis "ours" (the invariant of decode_preR13_section, src/decode.c).
  I1  Before PREP_TABLE writes dwg->object[num + i] (num = dwg->num_objects
      at section entry, i the 0-based table-entry index), the allocation
      dwg->object must have capacity for at least num + i + 1 objects.
  The base build grows dwg->object only at the realloc guarded by
  `dwg->num_objects % REFS_PER_REALLOC == 0` (line 327-328), so for a
  section whose entries make num + i reach the capacity, the write is a
  heap-buffer-overflow (the reported failure: WRITE of size 8, 96 bytes
  after a 296-byte region, frames decode_preR13_section <- decode_preR13).
  The PoC is a crafted AC1002 file that reaches I1's violation; the valid
  file test/test-data/r11/ACEB10.dwg does not (56 entries, no report).
  The developer patch replaces the write with
  `if ((num + i) >= dwg->num_objects) return DWG_ERR_INVALIDDWG`; since
  dwg->num_objects == num + i at entry to entry i (num captured at section
  start and incremented once per created entry), the guard holds at i = 0
  of every section, so the function returns before creating any table
  entry. It removes the overflow by decoding no pre-R13 table entry, so
  the PoC gives no report (OK) and the valid file loses all 56 entries
  (WRONG, no report). The root candidate sizes the buffer for num +
  tbl->number objects every section and keeps the original write, so the
  PoC gives no report and the valid file keeps its 56 entries (OK).
  Upstream master rewrote the pre-R13 decoder (2022-04), so the entry count
  of the valid file is not predicted (-); the PoC is predicted not to
  report (the overflow was removed upstream).

Assertion columns (ours). The instrumentation checks I1 before every
  store of a new object of the pre-R13 decoder (PREP_TABLE in
  decode_preR13_section, and decode_preR13_entities) and prints
  PREP13-INVARIANT and exits before a store beyond the allocation. On the
  base build the PoC reaches the check at the table entry with index 1 (the
  296-byte allocation holds one object), so it is INV; the valid file does
  not violate I1 (OK, 56 entries). After the developer patch no table entry
  is stored, so the check never fires: the PoC is OK and the valid file is
  WRONG (0 entries), as in the uninstrumented after column.

Hypothesis "dev" (the developer's own explanation): the message of
ea0b9522, "decode_preR13: more PREP_TABLE protections / fixes GH #325 heap
overflow", predicts that the overflow is fixed (poc OK after) and, as a
protection of a decoder, that a valid file still decodes correctly (aceb10
OK before and after). The observation that the developer model does not
predict is aceb10 after the patch: the valid file loses all entries
(observed WRONG), a regression the "protections" framing does not foresee.
"""

ROWS = {
    #            ours:                                                       dev:
    #            before   after    root   upstream  assert_b  assert_a     before  after
    "poc":    ("ASAN", "OK",    "OK",  "OK",     "INV",    "OK",       "ASAN", "OK"),
    "aceb10": ("OK",   "WRONG", "OK",  "-",      "OK",     "WRONG",    "OK",   "OK"),
}
COLS = [("ours", "before"), ("ours", "after"), ("ours", "root"),
        ("ours", "upstream_master"), ("ours", "assert_before"),
        ("ours", "assert_after"), ("dev", "before"), ("dev", "after")]


def main():
    print("case\t" + "\t".join("%s:%s" % c for c in COLS))
    for name, vals in ROWS.items():
        print(name + "\t" + "\t".join(vals))


if __name__ == "__main__":
    main()
