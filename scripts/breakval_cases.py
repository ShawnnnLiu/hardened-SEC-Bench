#!/usr/bin/env python3
"""Case table for mruby.cve-2022-1212 (UAF of a break value during break_new).

Prints a 3-column TSV (name<TAB>family<TAB>program) read by
scripts/breakval_run_cases.sh. Each program sets r (or raises) and prints
<<value>> or <<E:Class>>; the row `poc` runs the dataset reproducer
(@/testcase/poc.rb) and is judged by the sanitizer report only.

The reported failure: a `break <value>` whose block was called directly by a
C function (ci->cci > CINFO_NONE) is handled in src/vm.c by popping the frame
(cipop), restoring the GC arena (mrb_gc_arena_restore) and then allocating the
RBreak object that holds <value> (break_new). break_new's MRB_OBJ_ALLOC can run
a GC step; if <value> is a heap object reachable from no GC root at that point,
the step frees it and it is used later (str_escape in the PoC). The value in
the PoC is a String made by String#* inside the block, held only by a register
of the popped frame; the frame's registers are not marked after cipop
(mark_context_stack), and the arena no longer holds the value after the
restore.

Families:
  c1  reported construct: break a freshly created heap value out of a block a C
      function yields to (Class.new), each value kind.
  c2  GC pressure variants of c1 (GC.start, GC.interval_ratio=1,
      GC.step_ratio, an allocation loop before the break), to trigger the GC
      step at break_new on the default (non-stress) build.
  c3  other C block callers (Module.new, instance_exec, instance_eval,
      class_eval, module_exec, ObjectSpace.each_object) with the heap String.
  c4  reachability controls: the broken value is also held by an outer local, a
      constant or a global (a GC root), and immediate values (Integer, nil,
      true, Symbol), which cannot be freed.
  c5  neighbours: break from a block called by a Ruby method (no C boundary),
      next, a normal block return, return across the proc boundary, break
      through an ensure clause, and a break whose value was produced by a
      nested C call.
  c6  valid programs through the patched branch (break an immediate, a plain
      Class.new), as regression evidence for the patched lines.

mruby-fiber is not in the default gembox of this image, so the fiber-block
neighbour is omitted (Fiber is undefined here).

Oracle: the image's CRuby 2.7.0p0 (scripts/breakval_expected.tsv). Programs
CRuby accepts and runs are compared by value; obj/class/module results are
compared by class because inspect embeds an address or anonymous id.
"""

rows = []


def add(name, family, program):
    rows.append((name, family, program))


def wrap(body, show):
    # body sets r (or raises); print the shown expression, catch exceptions.
    return ('begin;%s;print "<<",(%s),">>";rescue => e;'
            'print "<<E:",e.class,">>";end') % (body, show)


# Heap value constructors, created by the last expression before the break.
# name -> (expression, shown expression after the break assigns r)
HEAP = [
    ("strtimes", '"x"*7', "r.inspect"),
    ("strcat",   '"a"+"bc"', "r.inspect"),
    ("ary",      '[1,2,3]', "r.inspect"),
    ("hash",     '{a: 1}', "r.inspect"),
    ("obj",      'Object.new', "r.class"),
    ("range",    '(1..7)', "r.inspect"),
]

# C block callers: a format string taking the break value expression.
ENTRIES = [
    ("class_new",     'r=Class.new{break %s}'),
    ("module_new",    'r=Module.new{break %s}'),
    ("instance_exec", 'r=Object.new.instance_exec{break %s}'),
    ("instance_eval", 'r=Object.new.instance_eval{break %s}'),
    ("class_eval",    'r=Class.new.class_eval{break %s}'),
    ("module_exec",   'r=Class.new.module_exec{break %s}'),
    ("objspace",      'r=ObjectSpace.each_object{break %s}'),
]

# c1: Class.new with each heap value kind.
for vn, vexpr, show in HEAP:
    add(f"c1_{vn}", "c1", wrap(f'r=Class.new{{break {vexpr}}}', show))

# c2: GC pressure on Class.new + String#*.
add("c2_gcstart",   "c2", wrap('GC.start;r=Class.new{break "x"*7}', "r.inspect"))
# GC.interval_ratio= / GC.step_ratio= exist only in mruby; the inner rescue
# makes CRuby skip the setter (NoMethodError) and reach the same break value.
add("c2_iratio",    "c2", wrap('begin;GC.interval_ratio=1;rescue;end;r=Class.new{break "x"*7}', "r.inspect"))
add("c2_sratio",    "c2", wrap('begin;GC.step_ratio=200;rescue;end;r=Class.new{break "x"*7}', "r.inspect"))
add("c2_allocloop", "c2", wrap('r=Class.new{i=0;while i<3000;("y"*8);i+=1;end;break "x"*7}', "r.inspect"))
add("c2_allocbig",  "c2", wrap('a=[];2000.times{a<<("z"*16)};r=Class.new{break "x"*7}', "r.inspect"))

# c3: other C block callers with the heap String.
for en, efmt in ENTRIES:
    if en == "class_new":
        continue
    add(f"c3_{en}", "c3", wrap(efmt % '"x"*7', "r.inspect"))

# c4: reachability controls and immediates. A value held by an outer local is
# reachable via the main frame's registers (a live stack slot after cipop), so
# it is protected on every build. A value held only by a constant or a global
# is reachable via a GC root that the arena+live-stack instrumentation cannot
# see, so such controls would false-positive the assert and are omitted here;
# the GC-stress oracle (a full mark from all roots) covers root reachability.
add("c4_outerlocal", "c4", wrap('s="x"*7;r=Class.new{break s}', "[r,s].inspect"))
add("c4_int",        "c4", wrap('r=Class.new{break 42}', "r.inspect"))
add("c4_nil",        "c4", wrap('r=Class.new{break nil}', "r.inspect"))
add("c4_true",       "c4", wrap('r=Class.new{break true}', "r.inspect"))
add("c4_sym",        "c4", wrap('r=Class.new{break :foo}', "r.inspect"))

# c5: neighbours.
add("c5_rubymethod", "c5", wrap('def m;yield;end;r=m{break "x"*7}', "r.inspect"))
add("c5_next",       "c5", wrap('r=Class.new{next "x"*7}', "r.class"))
add("c5_normalret",  "c5", wrap('r=Class.new{"x"*7}', "r.class"))
# return across the C-called block boundary returns from the enclosing method
# (well-defined in both engines), unlike a top-level return which ends the script.
add("c5_procreturn", "c5", wrap('def mm;Class.new{return "x"*7};end;r=mm', "r.inspect"))
add("c5_ensure",     "c5", wrap('r=Class.new{begin;break "x"*7;ensure;nil;end}', "r.inspect"))
add("c5_nestc",      "c5", wrap('r=Class.new{break([].instance_exec{"x"*7})}', "r.inspect"))

# c6: valid programs through the patched branch.
add("c6_imm",        "c6", wrap('r=Class.new{break 1}', "r.inspect"))
add("c6_plain",      "c6", wrap('r=Class.new{1+1}', "r.class"))

# poc: the dataset reproducer, judged by the sanitizer report only.
add("poc", "poc", "@/testcase/poc.rb")

for name, family, program in rows:
    print("\t".join([name, family, program]))
