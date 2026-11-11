"""Write the JavaScript case files for njs.cve-2023-27730 (njs_object_property
re-derives njs_object(value) from a stale value pointer during error dumping).

Usage: python3 errname_cases.py OUTDIR

Writes OUTDIR/<case>.js and OUTDIR/cases.tsv with the columns case, group,
kind, mode, absent.

Mechanism at the base commit 4c1e2332 (v0.7.10). njs_object_property
(src/njs_object_prop.c) took `const njs_value_t *value` and derived
object = njs_object(value) lazily at the moment of the hash lookup. The error
string builder njs_error_to_string2 (src/njs_error.c) fetches the error's
"name" (line 597) and, when the name is not a string, converts it with
njs_value_to_string (line 606); for a non-string OBJECT name this goes through
njs_value_to_primitive, which invokes the name's toString/valueOf, a function
call that can reallocate the VM value stack. The `error` argument of
njs_error_to_string2 points into that stack during a dump (njs_dump_terminal
-> njs_error_to_string -> njs_error_to_string2), so after the reallocation it
is stale. The next fetch, "message" (line 619), re-derives njs_object(error)
from the stale slot (now holding other bytes, e.g. a string whose first bytes
are read as a pointer, address 0x726f) and njs_lvlhsh_find dereferences it: a
sanitizer report. The name fetch at 597 ran before the reallocation, so it
does not fault; only the message fetch does.

Invariant (narrowest for the reported failure): the object whose hash
njs_object_property searches for the error's "message" must be the error
object that was live at the "name" fetch; the base re-derives it from a value
pointer that an intervening njs_value_to_string of a non-string name can
invalidate. The developer patch changes njs_object_property to take a
njs_object_t* and has njs_error_to_string2 capture error_object once, before
the conversion, so the stale value pointer is never dereferenced again; it
also guards njs_error_to_string with njs_is_object(error).

Trigger conditions (from base probes): a non-string OBJECT name under the
dump path (not toString, which holds a stable argument pointer). A string
name, a number/boolean name (no function call in the conversion, no
reallocation), or a non-string message (converted only after the message
fetch) do not fault.

Observable. For a bare final expression (mode dump) the shell's retval dump
builds the string but does not print it in file mode, so the observable is a
sanitizer report (ASAN) or nothing (OK); Node.js prints nothing for a bare
expression either, so the reference output is empty. The mode log cases print
console.log(...) of a primitive string that both njs and Node.js print, so
they test the rendered value against the reference (a wrong result is a
differing string).

absent is "crash" for a case that reports on the base build and "none" for a
case that runs cleanly on every build.

Groups (case <group>_<kind>):
  name  dump an Error whose "name" is a non-string object: the reported
        faulty state (base: sanitizer report).
  prim  dump an Error whose "name" is a non-string primitive (number,
        boolean): a boundary that reaches the name conversion without a
        function call, so no reallocation (base: no report).
  ctl   a dump that does not reach the stale re-deref: a string name, a
        non-string message, a plain error, and the toString path.
  render  console.log(String(e)): the rendered error string vs Node.js.
  sib   the other njs_object_property callers the patch changes.
"""
import sys
from pathlib import Path

# (case, group, kind, mode, absent, body). body leaves the value as the final
# expression (mode dump) or prints via console.log (mode log).
CASES = [
    ("name_obj",   "name", "obj",   "dump", "crash",
     "var e = Error(); e.name = {}; e"),
    ("name_err",   "name", "err",   "dump", "crash",
     "var e = Error(); e.name = Error(); e"),
    ("name_arr",   "name", "arr",   "dump", "crash",
     "var e = Error(); e.name = [1, 2, 3]; e"),
    ("name_fn",    "name", "fn",    "dump", "crash",
     "var e = Error(); e.name = function f(){}; e"),
    ("name_tyerr", "name", "tyerr", "dump", "crash",
     "var e = TypeError(); e.name = {}; e"),
    # the dataset PoC (const v1 = URIError(); v1.name = URIError(); URIError && v1)
    # is run by njs_run_variant.sh as the --extra case "poc", so it is not
    # repeated here.
    ("prim_num",  "prim", "num",  "dump", "none",
     "var e = Error(); e.name = 5; e"),
    ("prim_bool", "prim", "bool", "dump", "none",
     "var e = Error(); e.name = true; e"),
    ("ctl_name_str", "ctl", "str",  "dump", "none",
     "var e = Error(); e.name = 'X'; e"),
    ("ctl_msg_obj",  "ctl", "msg",  "dump", "none",
     "var e = Error(); e.message = {}; e"),
    ("ctl_plain",    "ctl", "plain", "dump", "none",
     "var e = Error('boom'); e"),
    ("ctl_tostring", "ctl", "tostr", "dump", "none",
     "var e = Error(); e.name = {}; String(e)"),
    ("render_name_obj", "render", "obj", "log", "none",
     "var e = Error(); e.name = {}; console.log(String(e));"),
    ("render_name_str", "render", "str", "log", "none",
     "var e = Error(); e.name = 'X'; e.message = 'm'; console.log(String(e));"),
    ("sib_arr_tostr",   "sib", "arr",  "log", "none",
     "console.log(Array.prototype.toString.call(5));"),
    ("sib_json_prim",   "sib", "jprim", "log", "none",
     "console.log(JSON.stringify(5));"),
    ("sib_json_tojson", "sib", "jtojson", "log", "none",
     "console.log(JSON.stringify({toJSON: function(){ return 7; }}));"),
]


def main():
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    tsv = ["\t".join(("case", "group", "kind", "mode", "absent"))]
    for name, group, kind, mode, absent, body in CASES:
        (out / f"{name}.js").write_text(body + "\n")
        tsv.append("\t".join((name, group, kind, mode, absent)))
    (out / "cases.tsv").write_text("\n".join(tsv) + "\n")
    print(len(CASES), "cases")


if __name__ == "__main__":
    main()
