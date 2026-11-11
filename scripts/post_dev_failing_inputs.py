#!/usr/bin/env python3
"""Collect named failures after the developer patch from retained evidence.

Only instances with dev_patch_fixes_root_cause false are catalogued.
Independent residuals, mixed inputs and dismissed cross-CVE findings retain
their classifications; inclusion does not change any verdict.
Inputs are program text where retained or generated, and a report reference
where the second reading did not retain its program files.
Case identifiers include the case set, so counts are evidence entries rather
than counts of unique program texts.
No build or case is rerun by this script.

Usage: python3 scripts/post_dev_failing_inputs.py [instance ...]
       python3 scripts/post_dev_failing_inputs.py --parquet FILE --card FILE --stage DIR
"""
import argparse
import csv
import importlib.util
import json
import re
import shutil
import subprocess
from pathlib import Path


FIELDS = (
    "case_id", "input", "input_path", "generator", "source_status", "expected", "observed",
    "outcome", "classification", "evidence",
)
INSTANCES = (
    "mruby.cve-2022-1276", "mruby.cve-2022-0240",
    "mruby.cve-2022-1201", "njs.cve-2022-31306",
    "njs.cve-2022-29780", "njs.cve-2020-24348",
    "mruby.cve-2022-0614", "mruby.cve-2022-0623",
)


def entry(case_id, source, expected, observed, outcome, classification,
          evidence, input_path="", generator=""):
    return dict(zip(FIELDS, (
        case_id, source, input_path, generator, "program" if source else "report_only", expected, observed,
        outcome, classification, evidence,
    )))


def simple_results(path):
    return {m[1]: (m[2], m[3].strip()) for m in re.finditer(
        r"^(\w+)\s+(OK|WRONG|ASAN)([^\n]*)$", Path(path).read_text(), re.M)}


def shell_cases(script, marker):
    """Expand the runner's existing case definitions without running an engine.

    Only the case-definition suffix is evaluated.
    Its run_case/crash_case/ctrl_case calls emit their arguments as NUL fields.
    """
    text = Path(script).read_text()
    suffix = text[text.index(marker):]
    suffix = suffix.split('\necho "summary:', 1)[0]
    capture = """MRUBY=ruby
is_ruby=1
# The image uses GNU seq, which emits nothing for `seq 1 0`.
# Some host versions instead count down, changing the zero-argument input.
seq() {
    local sep=$'\\n' first=1 last i
    if [[ "$1" == -s* ]]; then sep=${1:2}; shift; fi
    if [ "$#" = 1 ]; then last=$1; else first=$1; last=$2; fi
    for ((i=first; i<=last; i++)); do
        [ "$i" = "$first" ] || printf '%s' "$sep"
        printf '%s' "$i"
    done
    if ((first <= last)); then printf '\\n'; fi
    return 0
}
run_case() { printf 'CASE\\0%s\\0%s\\0%s\\0%s\\0' "$1" "${2-}" "${3-}" "${4-}"; }
crash_case() { run_case "$@"; }
ctrl_case() { run_case "$@"; }
"""
    result = subprocess.run(["bash", "-e", "-c", capture + suffix],
                            capture_output=True, check=True, text=True)
    if result.stderr:
        raise ValueError(f"Case expansion wrote stderr: {script}: {result.stderr}")
    parts = result.stdout.split("\0")
    cases = {}
    while len(parts) >= 5 and parts[0] == "CASE":
        _, name, a, b, c = parts[:5]
        cases[name] = (a, b, c)
        parts = parts[5:]
    if not cases:
        raise ValueError(f"No case definitions expanded: {script}")
    return cases


def kwargs_inputs(instance):
    script = "scripts/kwargs_aset_cases.sh"
    cases = shell_cases(script, "big=$(for")
    log = f"logs/{instance}/variants/after.cases.log"
    rows = []
    recorder = "class R; def []=(*a); $got = a; end; def [](*a); $ref = a; R.new; end; end; o = R.new"
    for name, (outcome, detail) in simple_results(log).items():
        if outcome == "OK":
            continue
        setup, statement, expected = cases[name]
        source = (f'{recorder}\n{setup}\n{statement}\nexp = {expected}\n'
                  'puts($got == exp ? "OK" : "WRONG got=#{$got.inspect}")\n')
        classification = "residual" if name.startswith("kwbig_") or name == "opasgn_kw_n1" else "root_cause"
        rows.append(entry(f"main/{name}", source, f"received arguments: {expected}",
                          detail, outcome, classification, log, generator=script))
    script = "scripts/kwargs_residual_cases.sh"
    cases = shell_cases(script, "pairs() {")
    log = f"logs/{instance}/variants/after.residual.log"
    for name, (outcome, detail) in simple_results(log).items():
        if outcome != "OK":
            source, expected, _ = cases[name]
            rows.append(entry(f"residual/{name}", source + "\n", expected, detail,
                              outcome, "residual", log, generator=script))
    return rows


def raw_catalog(path):
    runs, current, mode = {}, None, None
    for line in Path(path).read_text().splitlines():
        if line.startswith("@@@ BEGIN "):
            name, status = line[len("@@@ BEGIN "):].rsplit(" rc=", 1)
            current = {"out": [], "err": [], "status": int(status)}
            runs[name] = current
            mode = None
        elif line == "@@@ STDOUT":
            mode = "out"
        elif line == "@@@ STDERR":
            mode = "err"
        elif line == "@@@ END":
            mode = None
        elif current is not None and mode:
            current[mode].append(line)
    for run in runs.values():
        for key in ("out", "err"):
            if run[key] and run[key][-1] == "":
                run[key].pop()
            run[key] = "\n".join(run[key])
    return runs


def error_of(stderr):
    # Same error-class/message oracle as nvalhash_variants_compare.py.
    patterns = (
        r"^\S+:\d+:in [^:]*?: (.*) \(([A-Z]\w*)\)$",
        r"^\S+:\d+: (.*) \(([A-Z]\w*)\)$",
        r"^\S+:\d+:in `[^']*': (.*) \(([A-Z]\w*)\)$",
    )
    for line in stderr.splitlines():
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                return match[2], match[1]
    for line in stderr.splitlines():
        if any(s in line for s in ("stack pointer", "syntax error", "codegen")):
            return "COMPILE", line.strip()
    return None


def classify(run, reference):
    if "ERROR: AddressSanitizer" in run["out"] + run["err"]:
        return "ASAN"
    error, ref_error = error_of(run["err"]), error_of(reference["err"])
    if run["out"] == reference["out"] and error == ref_error:
        return "OK"
    if run["out"] == reference["out"] and error and ref_error and error[0] == ref_error[0]:
        return "OKc"
    return "WRONG"


def rendered(run):
    error = error_of(run["err"])
    value = f'stdout={run["out"]!r}'
    if error:
        value += f"; error={error[0]}: {error[1]}"
    report = re.search(r"ERROR: (AddressSanitizer:[^\n]+)", run["err"])
    if report:
        value += "; " + report[1]
    return value


def nvalhash_inputs(instance):
    script = "scripts/nvalhash_cases.sh"
    cases = shell_cases(script, "# --- reaching forms:")
    log = f"logs/{instance}/variants/after.cases.log"
    rows = []
    for name, (outcome, detail) in simple_results(log).items():
        if outcome == "OK":
            continue
        body, expected, _ = cases[name]
        source = ('def t\n  x = 111\n  y = 222\n' + f'  {body}\n  [x, y]\nend\n'
                  'begin; print "<<" + t.inspect + ">>"; rescue => e; print "<<E:" + e.class.to_s + ">>"; end\n')
        rows.append(entry(f"main/{name}", source, expected, detail,
                          outcome, "root_cause", log, generator=script))
    base = Path(f"logs/{instance}/second_reading")
    seen = set()
    for prefix in ("variants", "adjudication"):
        dev_path = base / f"{prefix}_dev.log"
        dev, ref, root = (raw_catalog(base / f"{prefix}_{build}.log")
                          for build in ("dev", "cruby", "root"))
        other = raw_catalog(base / "variants_b.log") if prefix == "variants" else {}
        both = raw_catalog(base / "variants_ab.log") if prefix == "variants" else {}
        for name, run in dev.items():
            if name in seen:
                continue
            seen.add(name)
            outcome = classify(run, ref[name])
            if outcome not in ("WRONG", "ASAN"):
                continue
            if classify(root[name], ref[name]) == "OK":
                classification = "root_cause"
            elif name in other and classify(other[name], ref[name]) == "OK":
                classification = "residual"
            elif name in both and classify(both[name], ref[name]) == "OK":
                classification = "mixed_root_cause_and_residual"
            else:
                classification = "other_observed_failure"
            group, stem = name.split("/", 1)
            phase = "phase3" if group == "inputs_g" else "phase2"
            source_path = base / phase / group / (stem + ".rb")
            rows.append(entry(f"second_reading/{name}", source_path.read_text(),
                              rendered(ref[name]), rendered(run), outcome, classification,
                              str(dev_path), input_path=str(source_path)))
    return rows


def tsv_catalog(path):
    return {p[0]: (p[1], p[2]) for line in Path(path).read_text().splitlines()
            if not line.startswith("#") and len(p := line.split("\t")) == 3}


def super_inputs(instance):
    script = "scripts/supernull_cases.sh"
    cases = shell_cases(script, "# --- MRB_TT_MODULE branch:")
    log = f"logs/{instance}/variants/after.cases.log"
    rows = []
    for name, (outcome, detail) in simple_results(log).items():
        if outcome != "OK":
            source, _, _ = cases[name]
            rows.append(entry(f"main/{name}", source + "\n", "controlled exception; no sanitizer report",
                              detail, outcome, "cross_cve:mruby.cve-2022-1427", log, generator=script))
    base = Path(f"logs/{instance}/second_reading")
    dev_path = base / "catalog_dev.tsv"
    dev, ref = tsv_catalog(dev_path), tsv_catalog(base / "catalog_cruby.tsv")
    for name, (outcome, detail) in dev.items():
        expected = ref[name][1]
        if outcome == "ASAN":
            classification = "cross_cve:mruby.cve-2022-1427"
        elif expected.startswith("value=") and detail != expected:
            outcome, classification = "WRONG", "residual"
        else:
            continue
        source_path = base / "phase3" / (name + ".rb")
        rows.append(entry(f"second_reading/{name}", source_path.read_text(),
                          expected, detail, outcome, classification, str(dev_path),
                          input_path=str(source_path)))
    return rows


def load_generator(path):
    spec = importlib.util.spec_from_file_location(Path(path).stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def njs_inputs(instance):
    rows = []
    for topic, variant, case_set in (("recurdesc", "cases", "main"), ("recurdesc_big", "big", "large_array")):
        script = f"scripts/{topic}_cases.py"
        module = load_generator(script)
        generated = module.rc_cases() if topic == "recurdesc" else module.cases()
        sources = {row[0]: module.PRELUDE.lstrip("\n") + row[-1] for row in generated}
        expected_path = f"scripts/{topic}_expected.tsv"
        with open(expected_path) as stream:
            expected = {r["case"]: r["output"] for r in csv.DictReader(
                (line for line in stream if not line.startswith("#")), delimiter="\t")}
        log = f"logs/{instance}/variants/after.{variant}.log"
        text = Path(log).read_text()
        for name, (outcome, detail) in simple_results(log).items():
            if outcome == "OK":
                continue
            match = re.search(rf"^{re.escape(name)}\s+(?:WRONG|ASAN)[^\n]*\n.*\n[^\n]*stdout=([^\n]*)", text, re.M)
            if match:
                detail += "; stdout=" + match[1]
            rows.append(entry(f"{case_set}/{name}", sources[name], expected[name],
                              detail.strip("; "), outcome, "root_cause", log, generator=script))
    # These five named observations are retained, but their original program
    # files were not copied from the second reading's sealed directory.
    log = f"logs/{instance}/second_reading/runs_patched.log"
    for line in Path(log).read_text().splitlines():
        fields = [part.strip() for part in line.split("|")]
        if len(fields) != 4 or fields[0] not in ("c4obs", "c4big", "c5obs", "p_dup", "p_dup2"):
            continue
        name, _, observed, expected = fields
        rows.append(entry(f"second_reading/{name}", "", expected, observed,
                          "ASAN" if "SAN:" in observed else "WRONG", "root_cause",
                          log, input_path=f"logs/{instance}/second_reading.log"))
    return rows


def njs_residual_inputs(instance, topic):
    """The residual case set of an njs instance whose flag was confirmed after the
    set was written (njs.cve-2022-29780, njs.cve-2020-24348, review of 2026-11-06).

    Their main case sets have no WRONG or ASAN case after the developer patch
    (variants/after.cases.log), so only the residual set contributes; the
    flagged leftover is in scope, so its entries are classified root_cause.
    """
    script = f"scripts/{topic}_residual_cases.py"
    module = load_generator(script)
    # The program text as the generator writes it to <case>.js.
    sources = {name: module.PRELUDE.lstrip("\n") + "out(function() { " + body + " });\n"
               for name, body in module.CASES.items()}
    expected_path = f"scripts/{topic}_residual_expected.tsv"
    with open(expected_path) as stream:
        expected = {r["case"]: r["output"] for r in csv.DictReader(
            (line for line in stream if not line.startswith("#")), delimiter="\t")}
    log = f"logs/{instance}/variants/resid_after.cases.log"
    text = Path(log).read_text()
    rows = []
    for name, (outcome, detail) in simple_results(log).items():
        if outcome == "OK":
            continue
        match = re.search(rf"^{re.escape(name)}\s+(?:WRONG|ASAN)[^\n]*\n.*\n[^\n]*stdout=([^\n]*)", text, re.M)
        if match and match[1]:
            detail += "; stdout=" + match[1]
        rows.append(entry(f"residual/{name}", sources[name], expected[name],
                          detail.strip("; "), outcome, "root_cause", log, generator=script))
    return rows


def hashtype_inputs(instance):
    """The aliasing cases of mruby.cve-2022-0614 and mruby.cve-2022-0623.

    The developer patch closes every non-hash case of the main set, so the
    failures after it are the hash-operand cases of
    scripts/hashtype_alias_cases.sh, the basis of the semantic flag
    (review of 2026-11-06): the source hash of a leading double-splat is mutated.
    """
    script = "scripts/hashtype_alias_cases.sh"
    cases = {m[1]: (m[2], m[3]) for m in re.finditer(
        r"^alias_case\s+(\w+)\s+'([^']*)'\s+\"([^\"]*)\"\s*$", Path(script).read_text(), re.M)}
    if not cases:
        raise ValueError(f"No case definitions found: {script}")
    log = f"logs/{instance}/variants/after.residual.log"
    rows = []
    for name, (outcome, detail) in simple_results(log).items():
        if outcome == "OK":
            continue
        source, expected = cases[name]
        rows.append(entry(f"alias/{name}", source + "\n", f"prints <<{expected}>> (CRuby 2.7: the source hash is unchanged)",
                          detail, outcome, "root_cause", log, generator=script))
    return rows


def collect(instance):
    functions = {
        "mruby.cve-2022-1276": kwargs_inputs,
        "mruby.cve-2022-0240": nvalhash_inputs,
        "mruby.cve-2022-1201": super_inputs,
        "njs.cve-2022-31306": njs_inputs,
        "njs.cve-2022-29780": lambda i: njs_residual_inputs(i, "sortconv"),
        "njs.cve-2020-24348": lambda i: njs_residual_inputs(i, "jsonfast"),
        "mruby.cve-2022-0614": hashtype_inputs,
        "mruby.cve-2022-0623": hashtype_inputs,
    }
    if instance not in functions:
        raise ValueError(f"No post-developer-patch inventory defined: {instance}")
    rows = functions[instance](instance)
    names = [row["case_id"] for row in rows]
    if len(names) != len(set(names)):
        raise ValueError(f"Duplicate case identifiers: {instance}")
    return rows


def summary(rows):
    from collections import Counter
    counts = Counter(row["classification"] for row in rows)
    labels = {
        "root_cause": "root defect",
        "residual": "residual",
        "mixed_root_cause_and_residual": "mixed root defect and residual",
        "cross_cve:mruby.cve-2022-1427": "counted under mruby.cve-2022-1427",
        "other_observed_failure": "other observed failure, scope not assigned",
    }
    return "; ".join(f"{count} {labels[kind]}" for kind, count in counts.items()) or "not catalogued"


def stage_column(parquet, card_path, stage):
    """Add one column while preserving every existing row and column value."""
    import pandas as pd

    stage = Path(stage)
    if stage.exists():
        raise ValueError(f"Stage already exists: {stage}")
    frame = pd.read_parquet(parquet)
    column = "post_dev_failing_inputs"
    if column in frame:
        raise ValueError(f"Column already exists: {column}")
    old_columns = list(frame.columns)
    inventory = {row.instance_id: collect(row.instance_id)
                 for row in frame.itertuples() if not row.dev_patch_fixes_root_cause}
    frame[column] = [inventory.get(instance, []) for instance in frame.instance_id]
    (stage / "data").mkdir(parents=True)
    target = stage / "data/verified-00000-of-00001.parquet"
    frame.to_parquet(target, index=False)
    reread = pd.read_parquet(target)
    pd.testing.assert_frame_equal(pd.read_parquet(parquet), reread[old_columns])
    for instance, rows in inventory.items():
        stored = reread.loc[reread.instance_id == instance, column].iloc[0]
        assert list(stored) == rows, instance

    card = Path(card_path).read_text()
    lines, table = [], False
    for line in card.splitlines():
        if line.startswith("| Instance | PoC before / after |"):
            table = True
            line += " Inputs failing after developer patch |"
        elif table and line.startswith("|---"):
            line += "---|"
        elif table and line.startswith("| "):
            instance = line.split("|")[1].strip()
            line += " " + summary(inventory.get(instance, [])) + " |"
        elif table and not line.startswith("|"):
            table = False
        lines.append(line)
    card = "\n".join(lines) + "\n"
    anchor = "| `dev_patch_fixes_root_cause` | Whether the developer patch restores the violated invariant rather than guarding the crash site |\n"
    assert card.count(anchor) == 1
    card = card.replace(anchor, anchor + "| `post_dev_failing_inputs` | Named failing inputs after the developer patch, with program text or report reference, expected and observed behavior, outcome, scope classification and evidence paths |\n")
    anchor = "### Files\n"
    assert card.count(anchor) == 1
    explanation = """### Inputs failing after the developer patch

`post_dev_failing_inputs` is a list of records on the four rows whose `dev_patch_fixes_root_cause` is false.
The other rows contain an empty list, meaning not catalogued by this column, not a claim that they have no residual defects.
The column collects every WRONG or ASAN observation from the retained main case sets, the additional large-array or residual case sets, and the second-reading validation catalogs for these four instances.
For mruby.cve-2022-1201, the value oracle covers programs for which CRuby returns a value; differences in controlled exception classes are not added as wrong-result claims.
An exception-message difference classified OKc by the existing oracle is also excluded.
The same program may occur in more than one case set; counts are named evidence entries, not unique program texts.
This inventory covers recorded cases, not all possible inputs.

Each entry contains `case_id`, `input` (program text), `input_path` (a retained program or report), `generator`, `source_status`, `expected`, `observed`, `outcome` (WRONG or ASAN), `classification`, and `evidence` (the developer-build log).
`source_status` is `program` when the program text is present and `report_only` when only a named observation and report reference were retained.
Five njs.cve-2022-31306 second-reading entries (c4obs, c4big, c5obs, p_dup and p_dup2) have no retained program file; their `input` is empty and their report gives the available input description.

`classification` preserves the reviewed distinction between `root_cause`, `residual`, and `cross_cve:mruby.cve-2022-1427`.
`mixed_root_cause_and_residual` marks an input requiring both independent repairs.
`other_observed_failure` records an oracle mismatch without assigning a new scope verdict when the retained evidence does not establish that classification.
In particular, mruby.cve-2022-1201's remaining crash inputs are counted under mruby.cve-2022-1427, consistent with its dismissed flag.
No existing verdict or reference-patch decision is changed.
`scripts/post_dev_failing_inputs.py` derives the column from the published case generators and logs without rerunning a build or case.

"""
    card = card.replace(anchor, explanation + anchor)
    (stage / "README.md").write_text(card)
    (stage / "scripts").mkdir()
    for name in ("post_dev_failing_inputs.py", "hf_build_verified.py"):
        shutil.copy2(Path("scripts", name), stage / "scripts" / name)
    print(f"Preserved {len(frame)} rows and {len(old_columns)} existing columns")
    for instance, rows in inventory.items():
        print(f"{instance}: {len(rows)} entries; {summary(rows)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("instances", nargs="*", default=list(INSTANCES))
    parser.add_argument("--parquet")
    parser.add_argument("--card")
    parser.add_argument("--stage")
    args = parser.parse_args()
    if any((args.parquet, args.card, args.stage)):
        if not all((args.parquet, args.card, args.stage)):
            parser.error("--parquet, --card and --stage must be supplied together")
        stage_column(args.parquet, args.card, args.stage)
        return
    print(json.dumps({instance: collect(instance) for instance in args.instances},
                     ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
