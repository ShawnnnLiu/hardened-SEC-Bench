"""Print the --merge arguments of scripts/render_cases_table.py for the
scripts/splice_deleted_cases.py case groups (njs.cve-2022-29779).

Usage: python3 splice_deleted_groups.py [families|detail]
  families  (default) the faulty cases by group, and the cases that reach no
            unwritten slot
  detail    the faulty splice cases by container
The first matching entry names a case's group, so the arguments are meant to
be passed unquoted: render_cases_table.py LOGDIR VARIANT... $(python3 ...).
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from splice_deleted_cases import cases  # noqa: E402


def names(pred):
    # scripts/render_cases_table.py strips a trailing _n<digits> from a case name before it matches a merge
    out = []
    for c in cases():
        if pred(c):
            n = re.sub(r"_n\d+$", "", c["name"])
            if n not in out:
                out.append(n)
    return out


def merge(label, members):
    print("--merge", "%s=%s" % (label, ",".join(members)))


def main(mode):
    cs = cases()
    if mode == "detail":
        for cont in ["like", "lenback", "args", "ta"]:
            merge("splice_%s_faulty" % cont,
                  names(lambda c, cont=cont: c["group"] == "splice" and c["container"] == cont and c["faulty"]))
        merge("splice_%s_clean" % "gapfree", names(lambda c: c["group"] == "splice" and not c["faulty"]))
        for g in ["consumer", "size", "bt", "nbr", "reent", "valid"]:
            merge(g, names(lambda c, g=g: c["group"] == g))
        print("--merge", "poc=poc")
        return
    merge("splice_faulty", names(lambda c: c["group"] == "splice" and c["faulty"]))
    merge("splice_clean", names(lambda c: c["group"] == "splice" and not c["faulty"]))
    merge("consumer_faulty", names(lambda c: c["group"] == "consumer"))
    merge("size", names(lambda c: c["group"] == "size"))
    merge("bt_faulty", names(lambda c: c["group"] == "bt" and c["faulty"]))
    merge("bt_clean", names(lambda c: c["group"] == "bt" and not c["faulty"]))
    merge("nbr", names(lambda c: c["group"] == "nbr"))
    merge("reent", names(lambda c: c["group"] == "reent"))
    merge("valid", names(lambda c: c["group"] == "valid"))
    print("--merge", "poc=poc")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "families")
