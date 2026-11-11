"""Second case set of mruby.cve-2022-0717 (errclass): the exception class
of String#[]= for argument lists that do not reach the post-right-hand-side
branch of gen_assignment(), to decide where the TypeError of the cases
f1_strrecv, f2_strrecv and poc1276 comes from (CRuby 2.7 raises
ArgumentError there).

Prints one TSV row per case (name, family, program) in the format of
scripts/arypush_cases.tsv; scripts/arypush_run_cases.sh runs it against the
CRuby values of scripts/arypush_errclass_expected.tsv. Output goes to
logs/mruby.cve-2022-0717/variants/<build>.errclass.log.

Rows: index assignment with 3 or 13 index arguments (n < 14, the branch is
not reached on either build), the same 15-argument call through send
(which does not use gen_assignment()), and 14 index arguments (the patched
branch), each with an Integer and with a String as the third argument,
plus one valid assignment.

Decision rule:
  D1: on the base build, e_s15_int gives the same class as f1_strrecv on
      the developer build (variants/after.cases.log: WRONG got=E:TypeError).
  D2: on the developer build, e_c14_str gives the same class and value as
      e_s15_str.
If D1 and D2 hold, String#[]= gives that class for that argument list
independently of the code generator: an oracle difference, not a defect.
If either fails, the developer build passes another argument list than
send does, and the question stays open.
Hypothesis HE (reported, not deciding): String#[]= converts its third
argument before it checks the argument count, so the _int rows give
E:TypeError and the _str rows E:ArgumentError on both builds, e_c14_str
gives ASAN on the base build, e_ok2 is OK everywhere.

This file was written on 2026-11-04 before any row of this set ran.
"""
PRE = 'begin;s="abc";'
POST = ';print "<<",(s),">>";rescue => e;print "<<E:",e.class,">>";end'
I13 = ",".join(str(i) for i in range(4, 14))
I14 = ",".join(str(i) for i in range(4, 15))
ROWS = [
    ("e_c3_int", "errclass 3 index args, Integer third", 's[1,2,3]=:r'),
    ("e_c3_str", "errclass 3 index args, String third", 's[1,2,"x"]=:r'),
    ("e_c13_int", "errclass 13 index args, Integer third", "s[1,2,3," + I13 + "]=:r"),
    ("e_c13_str", "errclass 13 index args, String third", 's[1,2,"x",' + I13 + "]=:r"),
    ("e_s15_int", "errclass send with 15 args, Integer third", "s.send(:[]=,1,2,3," + I14 + ",:r)"),
    ("e_s15_str", "errclass send with 15 args, String third", 's.send(:[]=,1,2,"x",' + I14 + ",:r)"),
    ("e_c14_str", "errclass 14 index args, String third", 's[1,2,"x",' + I14 + "]=:r"),
    ("e_ok2", "errclass valid 2-index assignment", 's[1,1]="Z"'),
]
for name, family, stmt in ROWS:
    print(name + "\t" + family + "\t" + PRE + stmt + POST)
