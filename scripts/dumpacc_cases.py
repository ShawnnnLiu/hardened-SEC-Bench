"""Write the JavaScript case files for njs.cve-2023-27728 (a fast array with
an own accessor property dumped by njs_vm_value_dump).

Usage: python3 dumpacc_cases.py OUTDIR

Writes OUTDIR/<case>.js and OUTDIR/cases.tsv with the columns case, group,
kind, container, absent. Each script builds one value, then makes that value
the program's final expression so that the shell's retval dump
(njs_console_output -> njs_vm_retval_dump -> njs_vm_value_dump) traverses it.
In non-interactive (file) mode njs_console_output builds the dump string but
does not print it, so a correct run prints nothing; the observable is
therefore: a sanitizer report (the OOB read), a printed marker (a getter or
setter was invoked by the dump, which must not happen), or no output. Node.js
on the host is the reference engine: it runs each file, dumps nothing and
invokes no accessor, so every case's expected output is empty
(scripts/njs_cases.py --oracle).

Mechanism at the base commit 4c1e2332 (v0.7.10). njs_vm_value_dump
(src/njs_json.c) iterates a container's keys. For each property it sets
val = njs_prop_value(prop), and only inside `if (!state->fast_array)` does it
run the NJS_PROPERTY_HANDLER call and the accessor-descriptor substitution
that replaces val with the static marker string "[Getter]"/"[Setter]"/
"[Getter/Setter]". A fast array therefore skips the substitution: for an own
accessor property val stays the raw njs_prop_value(prop) union, whose bytes
are the getter/setter pointers, not a valid njs_value_t. The code then calls
njs_dump_is_recursive(val) and, for the PoC's value, njs_json_push_stringify_state(vm, stringify, val)
-> njs_value_own_enumerate(vm, val, ...), dereferencing the union as an object
(a READ near address 0, 0x18 in this build at njs_value.c:241, 0x22 in the
dataset report at njs_dump_is_recursive; the first faulting field is build
dependent, the faulty state is the same).

Invariant (narrowest for the reported failure): before njs_vm_value_dump
treats a dumped property's val as a value (njs_dump_is_recursive / recursion),
an accessor-descriptor (or NJS_PROPERTY_HANDLER) property's val must have been
replaced with the marker string, for every container kind including a fast
array. The developer patch removes the `if (!state->fast_array)` gate, so the
substitution runs for fast arrays too.

A named (non-index) property leaves the array a fast array (indexed elements
stay in ->start). An index accessor cannot live in ->start, so defining one
converts the array to a slow array, which took the handled `!fast_array` path
already. An object (not an array) and a slow array also took the handled path.

Groups (case <group>_<kind>):
  fa   a fast array with one own enumerable named accessor property: the
       reported faulty state (base: sanitizer report).
  fab  a fast-array boundary: non-enumerable accessor (arrays dump
       non-enumerable own keys too) and a fast array that also has indexed
       elements before the accessor.
  ctl  a container that took the handled path at the base commit already:
       a fast array with a data property, a plain object with an accessor,
       a slow array with an accessor, an index accessor (converts to slow),
       and a plain fast array with no named property.
"""
import sys
from pathlib import Path

# A getter/setter that announces itself if the dump ever invokes it; the dump
# must show a static marker and never call the accessor, so a correct run is
# silent. GET returns a value, so a wrongly-invoked getter is still observable.
GET = "function(){ console.log('GETTER-INVOKED'); return 9; }"
SET = "function(v){ console.log('SETTER-INVOKED'); }"

# kind -> the descriptor passed to Object.defineProperty.
DESC = {
    "get":    "{enumerable:true, configurable:true, get: %s}" % GET,
    "set":    "{enumerable:true, configurable:true, set: %s}" % SET,
    "getset": "{enumerable:true, configurable:true, get: %s, set: %s}" % (GET, SET),
    "getobj": "{enumerable:true, configurable:true, get: Object}",  # the dataset getter
}

# case -> (group, kind, container, body). body leaves the dumped value as the
# program's final expression.
CASES = [
    # fa: fast array, one own enumerable named accessor -> base crash.
    ("fa_get",    "fa",  "get",    "fast array",
     "var a = []; Object.defineProperty(a, 'p', %s); a;" % DESC["get"]),
    ("fa_set",    "fa",  "set",    "fast array",
     "var a = []; Object.defineProperty(a, 'p', %s); a;" % DESC["set"]),
    ("fa_getset", "fa",  "getset", "fast array",
     "var a = []; Object.defineProperty(a, 'p', %s); a;" % DESC["getset"]),
    ("fa_getobj", "fa",  "getobj", "fast array",
     "var a = []; Object.defineProperty(a, 'p', %s); a;" % DESC["getobj"]),
    # fab: fast-array boundaries that still reach the accessor.
    ("fab_nonenum", "fab", "get", "fast array, non-enumerable accessor",
     "var a = []; Object.defineProperty(a, 'p', {enumerable:false, configurable:true, get: %s}); a;" % GET),
    ("fab_elems",   "fab", "get", "fast array with indexed elements",
     "var a = [1, 2, 3]; Object.defineProperty(a, 'p', %s); a;" % DESC["get"]),
    # ctl: containers already on the handled path at the base commit.
    ("ctl_plain",    "ctl", "none", "fast array, no named property",
     "var a = [1, 2, 3]; a;"),
    ("ctl_data",     "ctl", "data", "fast array, data property",
     "var a = []; Object.defineProperty(a, 'p', {enumerable:true, configurable:true, value: 5, writable:true}); a;"),
    ("ctl_obj_get",  "ctl", "get",  "plain object (not an array)",
     "var o = {}; Object.defineProperty(o, 'p', %s); o;" % DESC["get"]),
    ("ctl_slow_get", "ctl", "get",  "slow array",
     "var a = []; a[100000] = 1; Object.defineProperty(a, 'p', %s); a;" % DESC["get"]),
    ("ctl_idx_get",  "ctl", "get",  "index accessor (converts to slow)",
     "var a = [0]; Object.defineProperty(a, '0', %s); a;" % DESC["get"]),
]


def main():
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    tsv = ["\t".join(("case", "group", "kind", "container", "absent"))]
    for name, group, kind, container, body in CASES:
        (out / f"{name}.js").write_text(body + "\n")
        # absent=none marks a case that runs cleanly on every build (a stable
        # output for the cross-build digest); the fa/fab accessor cases crash
        # on the base build, so they are not "none".
        absent = "none" if group == "ctl" else "crash"
        tsv.append("\t".join((name, group, kind, container, absent)))
    (out / "cases.tsv").write_text("\n".join(tsv) + "\n")
    print(len(CASES), "cases")


if __name__ == "__main__":
    main()
