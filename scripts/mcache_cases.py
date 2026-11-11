#!/usr/bin/env python3
"""Case table for mruby.cve-2022-1286 (stale method cache after remove_method).

Prints a 3-column TSV (name<TAB>family<TAB>program) read by
scripts/mcache_run_cases.sh. Each program fills the method cache, removes a
method, calls again, and prints <<value>> or <<E:Class>>; the row `poc` runs
the dataset reproducer (@/testcase/poc.rb) and is judged by the sanitizer
report only.

Reported failure: mrb_remove_method (src/class.c) deletes a method from the
method table but, on the base build, does not clear the method cache, so a
later lookup returns a stale cache entry whose proc/env was freed or unshared
(the dataset heap-buffer-overflow at mrb_vm_exec, allocation from
mrb_env_unshare <- cipop). The developer patch adds
mrb_mc_clear_by_class(mrb, c) after a successful mt_del.

Invariant: the method cache must not return an entry that a method-table
change (here a removal) has made stale.

mrb_mc_clear_by_class clears the whole cache only if c has
MRB_FL_CLASS_IS_INHERITED; otherwise only entries whose start class mc->c == c.
A cache entry for a call that started from a subclass and found the method in c
(mc->c == subclass, mc->c0 == c) is therefore not cleared when c lacks the
flag. The only class reachable from Ruby that lacks the flag while being an
ancestor of others is BasicObject (bootstrapped via boot_defclass(mrb, 0), not
via mrb_class_inherited), so m3 removes a method from BasicObject and calls it
through an Object instance.

Families:
  m1  removal from the receiver's own class (self-search entry mc->c == C,
      which the by-class clear covers): a method with no superclass definition
      (expect NoMethodError), one that overrides a superclass method (expect
      the superclass result), and a method removed twice (second raises).
  m2  removal from a flagged ancestor or holder: a superclass (subclassing
      sets the flag on the super), an included module, a prepended module
      (origin class), a singleton class.
  m3  H-unflagged: a method defined on BasicObject, called through an Object
      instance, removed from BasicObject, in a program that never subclasses
      BasicObject (the by-class clear misses the Object-keyed entry) and in one
      that subclasses it first (which sets the flag, so the whole cache clears).
  m4  collected proc: m3 and m1 with GC.start and an allocation loop between
      the removal and the second call, so a surviving stale entry points to a
      freed or reused proc (memory-safety consequence).
  m5  entry points: remove several names in one call; remove an undefined name
      (NameError); and a redefine-then-remove chain.
  m6  controls that change the method table and must match CRuby on every
      build: undef_method, alias_method, def-redefinition, define_method,
      include after a call.

Oracle: the image's CRuby 2.7.0p0 (scripts/mcache_expected.tsv).
"""

rows = []


def add(name, family, program):
    rows.append((name, family, program))


def wrap(body, show):
    return ('begin;%s;print "<<",(%s),">>";rescue => e;'
            'print "<<E:",e.class,">>";end') % (body, show)


# m1: removal from the receiver's own class.
add("m1_noparent", "m1", wrap('class C1;def f;1;end;end;o=C1.new;o.f;C1.send(:remove_method,:f);r=o.f', "r.inspect"))
add("m1_override", "m1", wrap('class P2;def f;"p";end;end;class C2<P2;def f;"c";end;end;o=C2.new;o.f;C2.send(:remove_method,:f);r=o.f', "r.inspect"))
add("m1_twice",    "m1", wrap('class C3;def f;1;end;end;o=C3.new;o.f;C3.send(:remove_method,:f);C3.send(:remove_method,:f);r=o.f', "r.inspect"))
add("m1_cdef",     "m1", wrap('class C4;end;C4.send(:define_method,:f){1};o=C4.new;o.f;C4.send(:remove_method,:f);r=o.f', "r.inspect"))

# m2: removal from a flagged ancestor or holder (whole cache cleared).
add("m2_super",    "m2", wrap('class P5;def f;"p";end;end;class C5<P5;end;o=C5.new;o.f;P5.send(:remove_method,:f);r=o.f', "r.inspect"))
add("m2_module",   "m2", wrap('module M6;def f;"m";end;end;class C6;include M6;end;o=C6.new;o.f;M6.send(:remove_method,:f);r=o.f', "r.inspect"))
add("m2_prepend",  "m2", wrap('module M7;def f;"m";end;end;class C7;prepend M7;end;o=C7.new;o.f;M7.send(:remove_method,:f);r=o.f', "r.inspect"))
add("m2_singleton","m2", wrap('o=Object.new;class<<o;def f;1;end;end;o.f;class<<o;remove_method :f;end;r=o.f', "r.inspect"))

# m3: H-unflagged (BasicObject). The key test.
add("m3_basicobj",     "m3", wrap('class BasicObject;def f9;7;end;end;o=Object.new;o.f9;BasicObject.send(:remove_method,:f9);r=o.f9', "r.inspect"))
add("m3_basicobj_sub", "m3", wrap('class XSub9<BasicObject;end;class BasicObject;def f8;7;end;end;o=Object.new;o.f8;BasicObject.send(:remove_method,:f8);r=o.f8', "r.inspect"))

# m4: collected proc (memory-safety consequence of a surviving stale entry).
add("m4_basicobj_gc", "m4", wrap('class BasicObject;def f7;7;end;end;o=Object.new;o.f7;BasicObject.send(:remove_method,:f7);GC.start;i=0;while i<3000;Object.new;i+=1;end;GC.start;r=o.f7', "r.inspect"))
add("m4_own_gc",      "m4", wrap('class C8;def f;1;end;end;o=C8.new;o.f;C8.send(:remove_method,:f);GC.start;i=0;while i<3000;Object.new;i+=1;end;GC.start;r=o.f', "r.inspect"))

# m5: entry points.
add("m5_multi",     "m5", wrap('class C9;def f;1;end;def g;2;end;end;o=C9.new;o.f;o.g;C9.send(:remove_method,:f,:g);r=[(o.f rescue :nf),(o.g rescue :ng)]', "r.inspect"))
add("m5_undefined", "m5", wrap('class Ca;end;Ca.send(:remove_method,:nope);r=1', "r.inspect"))
add("m5_redef_rm",  "m5", wrap('class Cb;def f;1;end;end;o=Cb.new;o.f;class Cb;def f;2;end;end;o.f;Cb.send(:remove_method,:f);r=o.f', "r.inspect"))

# m6: controls that change the method table and must match CRuby on every build.
add("m6_undef",      "m6", wrap('class Cc;def f;1;end;end;o=Cc.new;o.f;Cc.send(:undef_method,:f);r=o.f', "r.inspect"))
add("m6_alias",      "m6", wrap('class Cd;def f;1;end;end;o=Cd.new;o.f;Cd.send(:alias_method,:g,:f);r=o.g', "r.inspect"))
add("m6_redef",      "m6", wrap('class Ce;def f;1;end;end;o=Ce.new;o.f;class Ce;def f;2;end;end;r=o.f', "r.inspect"))
add("m6_definemeth", "m6", wrap('class Cf;def f;1;end;end;o=Cf.new;o.f;Cf.send(:define_method,:f){2};r=o.f', "r.inspect"))
add("m6_include",    "m6", wrap('module Mg;def f;"m";end;end;class Cg;end;o=Cg.new;(o.f rescue nil);class Cg;include Mg;end;r=o.f', "r.inspect"))

# poc: the dataset reproducer, judged by the sanitizer report only.
add("poc", "poc", "@/testcase/poc.rb")

for name, family, program in rows:
    print("\t".join([name, family, program]))
