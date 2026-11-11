"""Case table for mruby.cve-2018-11743 (init_copy calls initialize_copy for a
TT_ICLASS object; upstream fix b64ce17852, src/kernel.c).

Prints one TSV row per case: name, family, program. The programs are run by
scripts/iclass_run_cases.sh inside the instance container; the expected values
are the results of the image's CRuby 2.7.0 (scripts/iclass_expected.tsv,
written by `iclass_run_cases.sh ruby`). A program beginning with `@` names a
file in the container (the dataset PoC) and is judged by the sanitizer report
only.

Mechanism: init_copy() (src/kernel.c) switches on mrb_type(obj); for a class or
module it calls copy_class(), for an object it copies ivars, and for every type
it then calls mrb_funcall(dest, "initialize_copy", obj). copy_class(), when the
source class carries a prepended module (MRB_FLAG_IS_PREPENDED), duplicates each
prepended iclass with mrb_obj_dup(), which re-enters init_copy() on a TT_ICLASS.
At the base commit init_copy() has no MRB_TT_ICLASS case, so the iclass copy's
fields are left uninitialized and mrb_funcall(dest, "initialize_copy", obj) is
still called on it; the method lookup walks the uninitialized iclass and runs a
wild method whose body reaches mrb_hash_keys (src/hash.c), reading a wild khash
pointer (the reported SEGV). The developer patch adds
  case MRB_TT_ICLASS: copy_class(mrb, dest, obj); return;
so a prepended iclass is copied with copy_class and initialize_copy is never
dispatched on it.

Invariant: init_copy() must not dispatch initialize_copy on a TT_ICLASS object
(an internal object that is never a Ruby value); a prepended iclass must be
copied with copy_class instead.

Families (first word of the family column):
  f1   duplicate (dup or clone) a class or module that carries a prepended
       module, so copy_class duplicates a prepended iclass and init_copy is
       re-entered on a TT_ICLASS: the reported crash. Receivers: a user class,
       a user class with a user initialize_copy, Object, Hash, Array, String;
       one or two prepended modules; dup and clone. `poc` runs the dataset
       /testcase/poc.rb. The value cases print a method dispatched through the
       prepended module on an instance of the copy, to check the copy is
       correct (wrong-result class) against CRuby 2.7.
  b    boundaries that do not re-enter init_copy on a TT_ICLASS: dup/clone a
       class with no prepended module, include (not prepend) then dup, prepend
       with no copy, and extend an object then dup the object.
  c    controls: plain value copies (String, Array, Hash).
"""

def wrap(setup, value):
    return setup + ';print "<<",(' + value + '),">>"'

def guarded(setup, value):
    body = wrap(setup, value)
    return 'begin;' + body + ';rescue => e;print "<<E:",e.class,">>";end'

# A module M with a method w returning :mw; a class C with w returning :cw.
UC = 'module M;def w;:mw;end;end;class C;def w;:cw;end;end'
# M whose w calls super, to check the prepended method and the class method both run.
UCS = 'module M;def w;"M<"+super;end;end;class C;def w;"C";end;end'
# Two modules, prepended M1 then M2 (ancestors M2,M1,C): d.new.w must be :m2.
UC2 = 'module M1;def w;:m1;end;end;module M2;def w;:m2;end;end;class C;def w;:cw;end;end'
# A class with a user initialize_copy (must not prevent the base crash).
UIC = 'module M;def w;:mw;end;end;class C;def w;:cw;end;def initialize_copy(o);super;end;end'

ROWS = [
    ("poc", "f1 dataset PoC (Hash prepend Enumerable, then dup)", "@/testcase/poc.rb"),
    ("f1_user_dup", "f1 user class, prepend, dup, call prepended method on a copy instance",
        guarded(UC + ';C.prepend(M);d=C.dup', 'd.new.w')),
    ("f1_user_clone", "f1 user class, prepend, clone, call prepended method on a copy instance",
        guarded(UC + ';C.prepend(M);d=C.clone', 'd.new.w')),
    ("f1_user_super", "f1 user class, prepended method calls super, dup",
        guarded(UCS + ';C.prepend(M);d=C.dup', 'd.new.w')),
    ("f1_two_dup", "f1 user class, two prepended modules, dup (MRO M2,M1,C)",
        guarded(UC2 + ';C.prepend(M1);C.prepend(M2);d=C.dup', 'd.new.w')),
    ("f1_initcopy_dup", "f1 user class with a user initialize_copy, prepend, dup",
        guarded(UIC + ';C.prepend(M);d=C.dup', 'd.new.w')),
    ("f1_object_dup", "f1 Object prepend then dup (isolated process)",
        guarded('Object.prepend(Module.new);Object.dup', '"done"')),
    ("f1_hash_dup", "f1 Hash prepend then dup", guarded('Hash.prepend(Module.new);Hash.dup', '"done"')),
    ("f1_hash_clone", "f1 Hash prepend then clone", guarded('Hash.prepend(Module.new);Hash.clone', '"done"')),
    ("f1_array_dup", "f1 Array prepend then dup", guarded('Array.prepend(Module.new);Array.dup', '"done"')),
    ("f1_string_clone", "f1 String prepend then clone", guarded('String.prepend(Module.new);String.clone', '"done"')),
    ("b_dup_noprepend", "b user class, no prepend, dup, call method on a copy instance",
        guarded(UC + ';d=C.dup', 'd.new.w')),
    ("b_clone_noprepend", "b user class, no prepend, clone, call method on a copy instance",
        guarded(UC + ';d=C.clone', 'd.new.w')),
    ("b_include_dup", "b user class, include (not prepend), dup, call included method on a copy instance",
        guarded('module M;def im;:im;end;end;class C;end;C.include(M);d=C.dup', 'd.new.im')),
    ("b_prepend_nocopy", "b user class, prepend, no copy, call prepended method",
        guarded(UC + ';C.prepend(M)', 'C.new.w')),
    ("b_extend_dup", "b object extend, then dup the object, call extended method",
        guarded('module M;def w;:mw;end;end;o=Object.new;o.extend(M);p2=o.dup', 'p2.respond_to?(:w)')),
    ("c_str_dup", "c plain String dup", guarded('s="abc"', 's.dup')),
    ("c_ary_clone", "c plain Array clone", guarded('a=[1,2]', 'a.clone.inspect')),
    ("c_hash_dup", "c plain Hash dup, read a key", guarded('h={:a=>1}', 'h.dup[:a]')),
]

for name, family, program in ROWS:
    print(name + "\t" + family + "\t" + program)
