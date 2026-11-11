"""Writes the PREPTABLE-INVARIANT instrumentation diff of libredwg.cve-2021-28237.

Usage: python3 scripts/prep13_make_invariant.py <decode.c> > <out.diff>

<decode.c> is src/decode.c of the tree the diff is applied to: the base
tree 49aeec4e (scripts/prep13_invariant_before.diff) or the base tree with
the developer patch ea0b9522 applied (scripts/prep13_invariant_after.diff).
The two trees differ in the PREP_TABLE macro, so one diff does not apply to
both; the inserted lines are the same in both diffs.

Invariant I1 (scripts/prep13_predictions.py): before an object of the
pre-R13 decoder is written at dwg->object[k], the allocation dwg->object
holds at least k + 1 objects. The check compares (k + 1) * sizeof
(Dwg_Object) with malloc_usable_size (dwg->object), which under
AddressSanitizer is the requested size of the allocation, at the two
places that write a new object of a pre-R13 drawing:
  - PREP_TABLE in decode_preR13_section, before the first store into
    dwg->object[num + i] (the store `obj->tio.object = ...`);
  - decode_preR13_entities, before `obj = &dwg->object[num];` and the
    memset that follows it.
On a violation it prints a line with PREPTABLE-INVARIANT and exits with
status 86 before the store; it changes nothing else.
"""
import difflib
import sys

INCLUDE_ANCHOR = "#include <assert.h>\n"
INCLUDE_LINES = [
    "#include <malloc.h> /* PREPTABLE-INVARIANT check, instrumentation only */\n",
    "#include <unistd.h>\n",
]
# PREP_TABLE: the first store into dwg->object[num + i]
TABLE_ANCHORS = {
    "base": "  obj->tio.object = (Dwg_Object_Object*)calloc (1, sizeof (Dwg_Object_Object)); \\\n",
    "dev": "  obj->tio.object                                                             \\\n",
}
TABLE_LINES = [
    "  if ((num + i + 1) * sizeof (Dwg_Object)                                    \\\n",
    "      > malloc_usable_size (dwg->object))                                    \\\n",
    "    {                                                                         \\\n",
    "      fprintf (stderr, \"PREPTABLE-INVARIANT table entry write at index %lu, \"    \\\n",
    "               \"allocation holds %lu objects\\n\",                          \\\n",
    "               (unsigned long)(num + i),                                     \\\n",
    "               (unsigned long)(malloc_usable_size (dwg->object)              \\\n",
    "                               / sizeof (Dwg_Object)));                      \\\n",
    "      fflush (stderr);                                                        \\\n",
    "      _exit (86);                                                             \\\n",
    "    }                                                                         \\\n",
]
ENTITY_ANCHOR = "      obj = &dwg->object[num];\n"
ENTITY_LINES = [
    "      if ((num + 1) * sizeof (Dwg_Object) > malloc_usable_size (dwg->object))\n",
    "        {\n",
    "          fprintf (stderr, \"PREPTABLE-INVARIANT entity write at index %lu, \"\n",
    "                   \"allocation holds %lu objects\\n\",\n",
    "                   (unsigned long)num,\n",
    "                   (unsigned long)(malloc_usable_size (dwg->object)\n",
    "                                   / sizeof (Dwg_Object)));\n",
    "          fflush (stderr);\n",
    "          _exit (86);\n",
    "        }\n",
]


def insert_before(lines, anchor, new):
    idx = [k for k, line in enumerate(lines) if line == anchor]
    if len(idx) != 1:
        sys.exit("anchor found %d times (expected 1): %r" % (len(idx), anchor))
    k = idx[0]
    return lines[:k] + new + lines[k:]


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    old = open(sys.argv[1], encoding="latin-1").readlines()
    tree = [t for t, a in TABLE_ANCHORS.items() if old.count(a) == 1]
    if len(tree) != 1:
        sys.exit("cannot tell the base from the developer tree: PREP_TABLE anchors found for %r" % tree)
    new = list(old)
    k = new.index(INCLUDE_ANCHOR)
    new = new[:k + 1] + INCLUDE_LINES + new[k + 1:]
    new = insert_before(new, TABLE_ANCHORS[tree[0]], TABLE_LINES)
    # decode_preR13_entities is the only function with this line indented by 6 spaces
    new = insert_before(new, ENTITY_ANCHOR, ENTITY_LINES)
    sys.stdout.write("diff --git a/src/decode.c b/src/decode.c\n")
    sys.stdout.writelines(difflib.unified_diff(old, new, "a/src/decode.c", "b/src/decode.c", n=3))
    sys.stderr.write("tree %s: %d lines inserted\n" % (tree[0], len(new) - len(old)))


if __name__ == "__main__":
    main()
