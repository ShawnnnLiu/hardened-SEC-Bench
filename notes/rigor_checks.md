# Rigor checks for root-cause verification

Added 2026-10-12, worked out on mruby.cve-2022-1276.
Procedure, scripts and the filled-in example are in the repository.

## Why

The developer patch for mruby.cve-2022-1276 (upstream c8c083cb75) and the root-cause patch (developer patch plus one `pop()`) both stop the PoC:

| Oracle | before | developer patch | root-cause patch |
|---|---|---|---|
| PoC sanitizer report | crash | none | none |
| mruby test suite (OK/KO/crash/skip, bintest) | 1460/0/0/8, 61/61 | same | same |
| 103 index assignments with keyword arguments | 31 OK, 66 wrong, 6 ASan | 37 OK, 66 wrong, 0 ASan | 103 OK |

### The 103 cases

- Synthetic, generated cases that check the root error rather than the PoC; written here after the root cause was identified, not taken from the dataset or from mruby's test suite.
- The PoC is an index assignment with 13 positional arguments and a keyword argument; the compiler bug is an off-by-one in its register stack after the keyword hash, present for every positional count from 0 to 13.
- At 13 the VM reads an Integer as the argument array and crashes (out-of-bounds read); at 0 to 12 nothing crashes and the called method silently receives a wrong last argument.
- The developer fix special-cases count 13, the one the report hit; the root-cause fix removes the off-by-one and covers all 14 counts.

## Checks added

- Predictions before the run
  - From the stated root cause, the expected result of every case (OK, wrong value, sanitizer report) on base, after the developer patch and after the root patch, written before the cases run.
  - `scripts/check_predictions.py` diffs them against the case logs and fails on any mismatch, so the root cause is a prediction set that is checked, not a story.
- Developer-model column
  - The same predictions derived from the developer's own explanation (commit message, issue).
  - What the developer's explanation does not predict becomes a logged count.
- Assertion variant
  - A temporary check is added at the exact point where the invariant must hold, so the program stops with a fixed message (`STACK-INVARIANT`) the moment it breaks, instead of crashing later or silently giving a wrong value.
  - It must fire on exactly the predicted bad cases without the fix, on none with the root-cause patch, and never on the project's own code (here every Ruby file in the source tree).
- Blind second reading
  - A second reader gets only the dataset report, the PoC and the source file at base, in a sealed directory, and states the invariant and the failing inputs; the developer patch is disclosed in a second phase and the first reading's evidence in a third (adjudication).
  - Agreement is recorded per dimension (mechanism, invariant and scope, failing set, patch completeness, fix location), before and after adjudication.
- Separability rule
  - A second defect found by the cases is independent of the CVE defect only if its fix alone and the root patch alone repair disjoint case sets and neither repairs the other's.
  - "Independent defect" becomes a test result instead of a judgment.
- Oracle pin
  - The program and version that gives the expected output (here CRuby 2.7.0 in the image).
- Falsification and confidence
  - Each root-cause record states the observation that would refute it, and high, medium or low with the reason, separating the invariant from the choices made around it.
- Patch inventory
  - `results.jsonl` lists every patch of the instance: role (developer, gold, minimal, root), hash, source (`upstream:<hash>`, `backport:<hash>`, `secbench:<path>`, `synthetic`), what it fixes, status.
- Tables from logs
  - Case tables in notes are printed by `scripts/render_cases_table.py` from the logs; no numbers typed from memory.

## Results on mruby.cve-2022-1276

Predictions (`logs/mruby.cve-2022-1276/predictions.log`; 137 of 138 cases modelled, one case is on another code path):

| Model and build | predicted | matched | mismatched |
|---|---|---|---|
| ours, each of before / dev / root / root+hash fix / assert_before / assert_root | 137 | 137 | 0 |
| developer's model (fails only at 13 positional arguments), before | 137 | 55 | 82 |
| developer's model, after the developer patch (predicts all OK) | 137 | 54 | 83 |

## Questions

- Is this rigorous enough for an ACL resource paper (decision rules, agreement between readers, provenance, limitations), and if not, what is missing?
- When the developer patch does not fix the root cause and no developer commit anywhere (branches, tags, pull request heads, issues) fixes it, what goes in the dataset: the developer patch alone with a "does not fix the root cause" label, a synthetic root-cause patch marked as such, or neither?
- Do we stay with the bug as outlined by the report and the developer (here a crash at 13 arguments), or do we infer the root cause (here an off-by-one for 0 to 13 arguments with 66 silent wrong values)? If we infer, what is the acceptance bar: predictions, assertion, second reading, or all three?
- How do we define the scope of our own synthetic patch: only the faulty state the PoC reaches, every input that violates the same invariant, or every defect the cases find in the same code? (Here a second defect in `gen_hash()` is separable by the rule above but sits in the same branch.)
