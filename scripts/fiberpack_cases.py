#!/usr/bin/env python3
"""Case table for mruby.cve-2022-0890 (fiber 15+ argument packing), printed as a
TSV (name<TAB>family<TAB>program) for scripts/fiberpack_run_cases.sh.

Mechanism: a created fiber started with `len` arguments runs fiber_switch's
created branch (mrbgems/mruby-fiber/src/fiber.c), which copies the arguments to
c->stbase+1 and sets c->cibase->n = len. The callinfo field n is 4 bits with 15
meaning "packed in an Array" (include/mruby.h). So the stored n is len & 15: for
len 0..14 it is correct; for len == 15 (and 31, 47) it is 15, so OP_ENTER's
`if (argc == 15) { ary = mrb_ary_ptr(regs[1]); ... }` reads the first plain
argument as an Array (the reported SEGV); for len 16..30 (and 32..46) it is
len-16 (a wrong, smaller argument count, no crash). The developer patch, for
len >= 15, packs all arguments into one Array at c->stbase[1] and sets len = 15,
so OP_ENTER reads a real packed Array and every count is correct.

Both Fiber#resume and Fiber#transfer on a NEW fiber reach the created branch
(fiber_resume -> fiber_switch resume=TRUE; fiber_transfer -> resume=FALSE), so
both carry the bug. CRuby 2.7 (the oracle) has Fiber#resume but NOT
Fiber#transfer, so the transfer cases are compared against the resume value for
the same count (set in scripts/fiberpack_expected.tsv).

Each program captures what the fiber block's |*a| receives into $r as
"<size>,<last.inspect>" and prints it as <<...>>; a crash is judged by the
sanitizer report. Argument values are 1..N, so the correct result is "N,N"
(and "0,nil" for N == 0).

This file is the case table only; the per-case predicted classes are in
scripts/fiberpack_predictions.py, written before the before variant ran.
"""

rows = []  # (name, family, program)


def args(n):
    return ",".join(str(i) for i in range(1, n + 1))


RESUME = ('$r="X"; f=Fiber.new{{|*a| $r="#{{a.size}},#{{a.last.inspect}}"}}; '
          'begin; f.resume({a}); rescue=>e; $r="E:#{{e.class}}"; end; print "<<",$r,">>"')
TRANSFER = ('$r="X"; f=Fiber.new{{|*a| $r="#{{a.size}},#{{a.last.inspect}}"}}; '
            'begin; f.transfer({a}); rescue=>e; $r="E:#{{e.class}}"; end; print "<<",$r,">>"')

# n1: Fiber#resume, created-fiber start (the bug), counts across the nibble boundaries
for n in (0, 1, 14, 15, 16, 17, 20, 30, 31, 32, 47):
    rows.append((f"n1_r{n:02d}", "n1 resume count", RESUME.format(a=args(n))))

# n2: Fiber#transfer, created-fiber start (the PoC's entry); CRuby has no transfer
for n in (14, 15, 16, 31, 32):
    rows.append((f"n2_t{n:02d}", "n2 transfer count", TRANSFER.format(a=args(n))))

# n3: block parameter shapes with 15 arguments (resume); capture the params
A15 = args(15)
rows.append(("n3_two",  "n3 |a,b| 15",   f'$r="X"; f=Fiber.new{{|a,b| $r="#{{a}},#{{b}}"}}; begin; f.resume({A15}); rescue=>e; $r="E:#{{e.class}}"; end; print "<<",$r,">>"'))
rows.append(("n3_rest", "n3 |a,*r| 15",  f'$r="X"; f=Fiber.new{{|a,*r| $r="#{{a}},#{{r.size}},#{{r.last.inspect}}"}}; begin; f.resume({A15}); rescue=>e; $r="E:#{{e.class}}"; end; print "<<",$r,">>"'))
rows.append(("n3_post", "n3 |*r,z| 15",  f'$r="X"; f=Fiber.new{{|*r,z| $r="#{{r.size}},#{{z}}"}}; begin; f.resume({A15}); rescue=>e; $r="E:#{{e.class}}"; end; print "<<",$r,">>"'))
rows.append(("n3_none", "n3 || 15",      f'$r="X"; f=Fiber.new{{|| $r="none"}}; begin; f.resume({A15}); rescue=>e; $r="E:#{{e.class}}"; end; print "<<",$r,">>"'))

# n4: splat call forms (a different call path to the same created-fiber start)
rows.append(("n4_sp15", "n4 splat 15", '$r="X"; f=Fiber.new{|*a| $r="#{a.size},#{a.last.inspect}"}; begin; f.resume(*Array.new(15){|i|i+1}); rescue=>e; $r="E:#{e.class}"; end; print "<<",$r,">>"'))
rows.append(("n4_sp16", "n4 splat 16", '$r="X"; f=Fiber.new{|*a| $r="#{a.size},#{a.last.inspect}"}; begin; f.resume(*Array.new(16){|i|i+1}); rescue=>e; $r="E:#{e.class}"; end; print "<<",$r,">>"'))
rows.append(("n4_sp31", "n4 splat 31", '$r="X"; f=Fiber.new{|*a| $r="#{a.size},#{a.last.inspect}"}; begin; f.resume(*Array.new(31){|i|i+1}); rescue=>e; $r="E:#{e.class}"; end; print "<<",$r,">>"'))

# n5: neighbours / controls (not the created-start arg path; must stay correct)
# started-fiber 2nd resume with 15 args (the already-started path, a different site)
rows.append(("n5_restart", "n5 2nd resume 15", '$r="X"; f=Fiber.new{ x=Fiber.yield(:a); $r="#{x.class}:#{(x.is_a?(Array) ? x.size : x).inspect}" }; begin; f.resume; f.resume(' + args(15) + '); rescue=>e; $r="E:#{e.class}"; end; print "<<",$r,">>"'))
# Fiber.yield returning 15 values to resume (the fiber_result path)
rows.append(("n5_yield15", "n5 yield 15 values", '$r="X"; f=Fiber.new{ Fiber.yield(*Array.new(15){|i|i+1}) }; begin; v=f.resume; $r="#{v.class}:#{v.is_a?(Array) ? "#{v.size},#{v.last}" : v}"; rescue=>e; $r="E:#{e.class}"; end; print "<<",$r,">>"'))
# Enumerator built on a block that yields a 15-element value
rows.append(("n5_enum", "n5 Enumerator", '$r="X"; begin; e=Enumerator.new{|y| y<<Array.new(15){|i|i+1}}; v=e.next; $r="#{v.size},#{v.last}"; rescue=>e; $r="E:#{e.class}"; end; print "<<",$r,">>"'))
# break out of a fiber block (control; may reach the break path, see night6 lane note)
rows.append(("n5_break", "n5 break control", '$r="X"; begin; f=Fiber.new{|*a| break 42}; v=f.resume(1,2); $r="v:#{v}"; rescue=>e; $r="E:#{e.class}"; end; print "<<",$r,">>"'))

# n6: valid controls with a small argument count (regression evidence for the patched else branch)
for n in (2, 3):
    rows.append((f"n6_v{n}", "n6 valid", RESUME.format(a=args(n))))

# the dataset PoC (judged by the sanitizer report only)
rows.append(("poc", "poc dataset", "@/testcase/poc"))

for name, family, program in rows:
    print(f"{name}\t{family}\t{program}")
