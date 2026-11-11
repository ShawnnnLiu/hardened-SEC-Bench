"""Case table for mruby.cve-2018-12248 (heap-buffer-overflow in OP_ENTER because
fiber_switch does not extend a new fiber's stack for many arguments; upstream fix
778500563, mrbgems/mruby-fiber/src/fiber.c).

Prints one TSV row per case: name, family, program. The programs are run by
scripts/fiberargs_run_cases.sh inside the instance container; the expected values
are the results of the image's CRuby 2.7.0 (scripts/fiberargs_expected.tsv). A
program beginning with `@` names a file in the container (the dataset PoC
/testcase/poc.rb) and is judged by the sanitizer report only.

Only deterministic values are printed (the block's first argument, or the size
and first/last of a splat, or an exception class). Fiber#transfer is public in
this mruby but needs `require "fiber"` in CRuby 2.7, so transfer cases begin with
an inner-rescued `(begin; require "fiber"; rescue; end)`: CRuby loads the fiber
library, and this mruby (which has transfer natively and has neither `require`
nor the `defined?` keyword) swallows the error and continues. No clone or dup of a
class/module anywhere (the mruby.cve-2018-11743 and 2018-12247 defects are present
at this base).

Mechanism (base ff0a4f78): a new (CREATED) fiber's stack is FIBER_STACK_INIT_SIZE
= 64 slots (or 64 + the block's nregs when nregs > 64; fiber_init, fiber.c:65).
fiber_switch (fiber.c:183) copies `len` arguments to stack[1..len] after the check
`if (len >= c->stend - c->stack) raise FiberError` (fiber.c:204), which raises only
at len >= 64. The block's OP_ENTER (vm.c:1776) computes blk = &argv[argc] =
&stack[len+1] and does `regs[len+1] = *blk` (vm.c:1859), so with len = 63 the block
slot is stack[64], one past the 64-slot stack: the reported 16-byte heap-buffer-
over-read. The developer patch replaces the FiberError check with
`mrb_stack_extend(mrb, len+2)` (receiver + len args + block), sizing the stack for
any len, and (because mrb_stack_extend also switches context state) reads the status
once into a local, sets the old context's status, and moves fiber_switch_context
before the copy.

Behaviour change on valid input: at the base 64 or more arguments to a new fiber
raise FiberError; after the patch they are accepted (CRuby accepts them), so the
family-n cases at len >= 64 are WRONG on the base (E:FiberError vs the CRuby value)
and OK after.

Families (first word of the family column):
  n   boundary sweep, block |x| and |*a|, via resume and via transfer, at len
      0,1,2,61,62,63,64,65,100,1000: the block slot overruns the 64-slot stack at
      len 63 exactly (ASAN on the base), len <= 62 is OK, len >= 64 raises
      FiberError on the base (WRONG) and is accepted after.
  g   the larger stack: a block with more than 64 local variables makes
      fiber_init allocate 64 + nregs slots, so len 63 no longer overruns (OK on the
      base), showing the boundary tracks the block's nregs, not a fixed 64.
  h   block shapes at len 63 and 62 (|p,q|, |p,*r,q|, |p,q=1|, a strict lambda):
      every non-strict shape overruns at len 63 (the block slot is &argv[argc]
      regardless of the shape); the strict lambda raises ArgumentError before the
      block-slot move, so it does not overrun.
  w   a splat of 300000 arguments to a new fiber: at the base it raises FiberError
      before any context switch; after the patch mrb_stack_extend is reached (the
      context already switched) and raises when the size exceeds MRB_STACK_MAX, so
      this checks the state the main fiber is left in (a second fiber resume after
      the rescue).
  k   controls that do not copy onto a new fiber's stack: resume of an already
      started fiber with many arguments (fiber_result), Fiber.yield of many values,
      and an Enumerator driven by next (this mruby has no Fiber.current, so the
      transfer-to-root control is omitted).
"""

SWEEP = [0, 1, 2, 61, 62, 63, 64, 65, 100, 1000]
REQ = '(begin;require "fiber";rescue => _e;nil;end);'


def g(body):
    return 'begin;' + body + ';rescue => e;print "<<E:",e.class,">>";end'


ROWS = []
ROWS.append(("n_poc", "n dataset PoC poc.rb (Fiber.new{|x|}.transfer 63 args)",
             "@/testcase/poc.rb"))

# n: resume, block |x| and |*a|, full sweep
for L in SWEEP:
    ROWS.append((f"n_res_x_{L}", f"n resume |x| len {L}",
        g(f'a=(0...{L}).to_a;f=Fiber.new{{|x| x}};print "<<",(f.resume(*a).inspect),">>"')))
for L in SWEEP:
    ROWS.append((f"n_res_a_{L}", f"n resume |*a| len {L}",
        g(f'a=(0...{L}).to_a;f=Fiber.new{{|*x| [x.size,x.first,x.last]}};print "<<",(f.resume(*a).inspect),">>"')))
# n: transfer, block |x| at the boundary, |*a| at 63 (the block captures the
# argument in an outer closure variable, read after the transferred fiber
# terminates and control returns to the main fiber; this mruby has no Fiber.current)
for L in [62, 63, 64]:
    ROWS.append((f"n_tr_x_{L}", f"n transfer |x| len {L}",
        g(REQ + f'res=nil;a=(0...{L}).to_a;f=Fiber.new{{|x| res=x}};f.transfer(*a);print "<<",(res.inspect),">>"')))
ROWS.append(("n_tr_a_63", "n transfer |*a| len 63",
    g(REQ + 'res=nil;a=(0...63).to_a;f=Fiber.new{|*x| res=[x.size,x.first,x.last]};f.transfer(*a);print "<<",(res.inspect),">>"')))

# g: larger stack (block with 70 locals)
LOCALS = ";".join(f"v{i}={i}" for i in range(1, 71))
ROWS.append(("g_big63", "g resume |x| len 63 with a 70-local block (larger stack)",
    g(f'a=(0...63).to_a;f=Fiber.new{{|x| {LOCALS};x}};print "<<",(f.resume(*a).inspect),">>"')))

# h: block shapes at len 63 and 62
ROWS.append(("h_ab_63", "h resume |p,q| len 63",
    g('a=(0...63).to_a;f=Fiber.new{|p,q| [p,q]};print "<<",(f.resume(*a).inspect),">>"')))
ROWS.append(("h_arb_63", "h resume |p,*r,q| len 63",
    g('a=(0...63).to_a;f=Fiber.new{|p,*r,q| [p,r.size,q]};print "<<",(f.resume(*a).inspect),">>"')))
ROWS.append(("h_opt_63", "h resume |p,q=99| len 63",
    g('a=(0...63).to_a;f=Fiber.new{|p,q=99| [p,q]};print "<<",(f.resume(*a).inspect),">>"')))
ROWS.append(("h_lambda_63", "h resume strict lambda |x| len 63 (ArgumentError, no overrun)",
    g('a=(0...63).to_a;l=lambda{|x| x};f=Fiber.new(&l);print "<<",(f.resume(*a).inspect),">>"')))
ROWS.append(("h_ab_62", "h resume |p,q| len 62 (in bounds)",
    g('a=(0...62).to_a;f=Fiber.new{|p,q| [p,q]};print "<<",(f.resume(*a).inspect),">>"')))

# w: huge splat (switch-raise), then a second fiber resume to check the VM state
ROWS.append(("w_bigsplat", "w resume with 300000 args (exceeds MRB_STACK_MAX), then a second resume",
    g('r1=(begin;f=Fiber.new{|*a| a.size};f.resume(*Array.new(300000,0));"noraise";rescue Exception=>e;"E:"+e.class.to_s;end);'
      'r2=(begin;gg=Fiber.new{|y| y};gg.resume(42);rescue Exception=>e2;"E2:"+e2.class.to_s;end);'
      'print "<<",(r1.to_s+"|"+r2.to_s),">>"')))

# k: controls that do not copy onto a new fiber's stack
ROWS.append(("k_resume_started", "k resume an already started fiber with 100 args (fiber_result)",
    g('f=Fiber.new{|*a| Fiber.yield(a.size); "done"};f.resume(1);print "<<",(f.resume(*(0...100).to_a).inspect),">>"')))
ROWS.append(("k_yield", "k Fiber.yield of 100 values",
    g('f=Fiber.new{ Fiber.yield(*(0...100).to_a); 9 };r=f.resume;print "<<",((r.is_a?(Array) ? r.size : r).inspect),">>"')))
ROWS.append(("k_enum", "k an Enumerator driven by next",
    g('e=Enumerator.new{|y| (0...100).each{|i| y<<i}};print "<<",([e.next,e.next].inspect),">>"')))

for name, family, program in ROWS:
    print(name + "\t" + family + "\t" + program)
