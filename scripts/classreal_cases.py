"""Case table for mruby.cve-2018-12249 (NULL pointer dereference in
mrb_class_real; upstream fix faa4eaf6, src/class.c).

Prints one TSV row per case: name, family, program. The programs are run by
scripts/classreal_run_cases.sh inside the instance container; the expected
values are the results of the image's CRuby 2.7.0 (scripts/classreal_expected.tsv,
written by `classreal_run_cases.sh ruby`). A program beginning with `@` names a
file in the container (the dataset PoC /testcase/exploit.rb) and is judged by the
sanitizer report only.

Mechanism: mrb_class_real(struct RClass* cl) (src/class.c, base 55edae02) strips
singleton classes and iclasses from a class pointer:

    if (cl == 0) return NULL;
    while ((cl->tt == MRB_TT_SCLASS) || (cl->tt == MRB_TT_ICLASS)) {
      cl = cl->super;
    }
    return cl;

The entry guard rejects a NULL argument, but the loop reads cl->tt again after
cl = cl->super without checking cl. If the chain of SCLASS/ICLASS nodes ends in a
node whose super is NULL, the next while-condition reads NULL->tt: the reported
SEGV at class.c:1768. The reporter's input prepends a module to BasicObject
(the root class, whose own super is NULL): prepend inserts an iclass whose super
is BasicObject's original super (NULL), so mrb_class_real(BasicObject->super)
walks ICLASS -> NULL -> reads NULL->tt. The caller on the PoC path is
mrb_vm_define_class (OP_CLASS): reopening `class BasicObject < Super` evaluates
`mrb_class_real(c->super) != s` (class.c:314) to check the declared superclass.

Invariant: walking the super chain past singleton classes and iclasses in
mrb_class_real must stop at a NULL super and never read cl->tt when cl == NULL.

The developer patch adds `if (cl == 0) return NULL;` inside the loop after
`cl = cl->super;`, so the walk returns NULL instead of reading NULL->tt. The
callers already treat a NULL result safely (a comparison at class.c:230, 314,
2369; mrb_class_inherited at 321 maps NULL to object_class), so after the patch
the reported reopen raises a TypeError (superclass mismatch), matching CRuby.

Families (first word of the family column):
  d   reopen BasicObject with a declared superclass after a module was prepended
      to it, so mrb_vm_define_class (class.c:314) calls mrb_class_real on an
      iclass whose super is NULL: the reported crash. Declared super is Class,
      Object or BasicObject; the prepended module is Enumerable, a user module,
      or two modules; `d_poc` runs the dataset /testcase/exploit.rb. The expected
      CRuby result is a TypeError (superclass mismatch).
  b   boundaries that do not read a NULL class: reopen BasicObject with a super
      and no prepend (the entry guard returns NULL; TypeError), reopen BasicObject
      with no super (the super check is skipped), prepend then reopen with no
      super, prepend a user class whose original super is Object (the walk stops
      at Object), and define a new subclass of a prepended user class.
  cons other consumers of mrb_class_real on a prepended BasicObject: Object#class
      (class.c:1863), Module#const_missing (class.c:2369), and the Class query
      methods superclass, ancestors, inspect, to_s and singleton_class, to see
      which read a NULL class and whether the patch covers them.
  c   controls: reopen Object with its real super, a plain user class value, a
      plain subclass.
"""

def wrap(setup, value):
    return setup + ';print "<<",(' + value + '),">>"'

def guarded(setup, value):
    body = wrap(setup, value)
    return 'begin;' + body + ';rescue => e;print "<<E:",e.class,">>";end'

ROWS = [
    # d: the reported crash path (reopen prepended BasicObject with a super)
    ("d_poc", "d dataset PoC (BasicObject.prepend Enumerable; class BasicObject < Class)",
        "@/testcase/exploit.rb"),
    ("d_enum_class", "d prepend Enumerable, reopen BasicObject < Class",
        guarded('BasicObject.prepend Enumerable;class BasicObject < Class;end', '"done"')),
    ("d_enum_object", "d prepend Enumerable, reopen BasicObject < Object",
        guarded('BasicObject.prepend Enumerable;class BasicObject < Object;end', '"done"')),
    ("d_enum_basicobj", "d prepend Enumerable, reopen BasicObject < BasicObject",
        guarded('BasicObject.prepend Enumerable;class BasicObject < BasicObject;end', '"done"')),
    ("d_user_mod", "d prepend a user module, reopen BasicObject < Class",
        guarded('module Zz;end;BasicObject.prepend Zz;class BasicObject < Class;end', '"done"')),
    ("d_two_mods", "d prepend two user modules, reopen BasicObject < Class",
        guarded('module Aa;end;module Bb;end;BasicObject.prepend Aa;BasicObject.prepend Bb;class BasicObject < Class;end', '"done"')),
    # b: boundaries that do not read a NULL class
    ("b_noprepend_class", "b reopen BasicObject < Class, no prepend (entry guard; TypeError)",
        guarded('class BasicObject < Class;end', '"done"')),
    ("b_noprepend_nosuper", "b reopen BasicObject, no super, no prepend",
        guarded('class BasicObject;end', '"done"')),
    ("b_prepend_nosuper", "b prepend Enumerable, reopen BasicObject with no super (super check skipped)",
        guarded('BasicObject.prepend Enumerable;class BasicObject;end', '"done"')),
    ("b_user_prepend_reopen", "b prepend a module to a user class, reopen it < Object (chain stops at Object)",
        guarded('module Zz;end;class Cc;end;Cc.prepend Zz;class Cc < Object;end', '"done"')),
    ("b_new_subclass_prepended", "b define a new subclass of a prepended user class",
        guarded('module Zz;end;class Cc;end;Cc.prepend Zz;class Dd < Cc;end', '"done"')),
    # cons: other consumers of mrb_class_real on a prepended BasicObject
    ("cons_class", "cons BasicObject.class after prepend (mrb_obj_class)",
        guarded('BasicObject.prepend Enumerable', 'BasicObject.class')),
    ("cons_superclass", "cons BasicObject.superclass after prepend",
        guarded('BasicObject.prepend Enumerable', 'BasicObject.superclass.inspect')),
    ("cons_ancestors", "cons BasicObject.ancestors length after prepend",
        guarded('BasicObject.prepend Enumerable', 'BasicObject.ancestors.length')),
    ("cons_inspect", "cons BasicObject.inspect after prepend",
        guarded('BasicObject.prepend Enumerable', 'BasicObject.inspect')),
    ("cons_singleton", "cons BasicObject.singleton_class.class after prepend",
        guarded('BasicObject.prepend Enumerable', 'BasicObject.singleton_class.class')),
    # c: controls
    ("c_object_reopen", "c reopen Object with its real super BasicObject",
        guarded('class Object < BasicObject;end', '"done"')),
    ("c_user_value", "c plain user class, call a method",
        guarded('class Cc;def hi;:hi;end;end', 'Cc.new.hi')),
    ("c_plain_subclass", "c plain subclass, read its superclass",
        guarded('class Cc;end;class Dd < Cc;end', 'Dd.superclass.name')),
]

for name, family, program in ROWS:
    print(name + "\t" + family + "\t" + program)
