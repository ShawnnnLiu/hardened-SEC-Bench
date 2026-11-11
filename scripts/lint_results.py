#!/usr/bin/env python3
"""Check results.jsonl against the field conventions of this repository.

Usage: python3 scripts/lint_results.py [--forbid-file FILE] [--instance ID]...
                                       [RESULTS]

RESULTS defaults to results.jsonl in the repository root, the parent of
this script's directory; `-` reads standard input, for example the staged
copy from `git show :results.jsonl`. --forbid-file names a file with one
string per line that must not occur in any field (compared without case).
--instance limits the check to the given instance ids.

Each finding is printed as `<instance>: E <message>` (error) or
`<instance>: W <message>` (warning). The exit status is 1 if any error was
found, else 0.

Errors are violations of the recorded conventions: the base field set; the
verdict fields poc_resolved, semantic_flag, semantic_reasoning and
semantic_status placed right after dev_patch_fixes_root_cause; boolean
fields; poc_resolved equal to not poc_crashed_after; the allowed
semantic_status values and their agreement with semantic_flag; the opening
words of semantic_reasoning; patch_sha256 equal to the digest of
patches/<instance>.diff; the root-cause fields, the root patch file and its
digest when dev_patch_fixes_root_cause is false; the patches list (role,
path, digest, source); root_fix_distance when upstream_status says the root
cause is fixed upstream; ISO timestamps and an image digest; plain ASCII;
no first person singular; no forbidden string; every path under logs/,
scripts/, patches/, notes/ or data/ named in a field exists.

Warnings are style points and references that need a human look: a missing
rigor field, exclamation marks, promotional words, and a log name relative
to logs/<instance>/ that does not exist.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BASE_FIELDS = [
    "instance_id", "timestamp", "image_digest", "container_commit",
    "patch_sha256", "apply_method", "poc_crashed_before", "poc_crashed_after",
    "tests", "dev_patch_fixes_root_cause", "poc_resolved", "semantic_flag",
    "semantic_reasoning", "semantic_status", "host_arch", "logs", "status",
    "note",
]
VERDICT = ["poc_resolved", "semantic_flag", "semantic_reasoning", "semantic_status"]
ROOT_FIELDS = [
    "dev_patch_scope", "root_cause", "root_patch", "root_patch_sha256",
    "root_patch_source", "root_patch_status", "upstream_status",
    "root_poc_crashed_after", "root_tests", "root_check", "residual",
]
RIGOR_FIELDS = [
    "patches", "case_oracle", "predictions", "dev_model", "assertion",
    "second_reading", "falsified_by", "confidence",
]
DISTANCE_KEYS = [
    "dev_fix", "root_fix", "days", "commits", "same_author", "pull_request",
    "root_fix_cites_cve", "first_release_dev", "first_release_root",
    "releases_with_dev_fix_only",
]
BOOL_FIELDS = [
    "poc_crashed_before", "poc_crashed_after", "dev_patch_fixes_root_cause",
    "poc_resolved", "semantic_flag",
]
ROLES = {"developer", "gold", "minimal", "root"}
SOURCE = re.compile(
    r"^(synthetic|upstream:[0-9a-f]{7,40}|backport:[0-9a-f]{7,40}(\+[0-9a-f]{7,40})*|secbench:\S+)$")
INSTANCE = re.compile(r"^[a-z0-9_-]+\.cve-\d{4}-\d+$")
STATUS = re.compile(r"^(not flagged|flagged, not reviewed|(confirmed|dismissed) \d{4}-\d{2}-\d{2}\b.*)$")
BANNED = re.compile(r"\b(robust|comprehensive|seamless|significantly|very|clearly|obviously)\b", re.I)
FIRST_PERSON = re.compile(r"(?<![\w/])I(?=[\s,.'])|\bLet me\b")
REPO_PATH = re.compile(r"(?<![\w/.-])((?:logs|scripts|patches|notes|data)/[\w./<>*-]+)")
REMOVED = re.compile(r"\b(removed|deleted|dropped|no longer|not written|not kept|absent|withdrawn)\b", re.I)
LOG_TOKEN = re.compile(r"(?<![\w/.<>-])([\w<>-]+(?:/[\w.<>-]+)*\.(?:log|diff|tsv|sh|py))(?![\w/-])")
PATH_PREFIXES = ("logs/", "scripts/", "patches/", "notes/", "data/")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def walk_strings(obj, prefix=""):
    if isinstance(obj, str):
        yield prefix, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_strings(v, f"{prefix}[{i}]")


class Report:
    def __init__(self, inst):
        self.inst = inst
        self.errors = []
        self.warnings = []

    def e(self, msg):
        if msg not in self.errors:
            self.errors.append(msg)

    def w(self, msg):
        if msg not in self.warnings:
            self.warnings.append(msg)


def check_strings(d, inst, forbidden, r):
    seen_tokens = set()
    for field, s in walk_strings(d):
        bad = [c for c in s if ord(c) > 126 or (ord(c) < 32 and c not in "\n\t")]
        if bad:
            r.e(f"{field}: non-ASCII character {bad[0]!r}")
        low = s.lower()
        for term in forbidden:
            if term and term.lower() in low:
                r.e(f"{field}: contains forbidden string {term!r}")
        if FIRST_PERSON.search(s):
            r.e(f"{field}: first person singular or conversational phrasing")
        if re.search(r"!(\s|$)", s):
            r.w(f"{field}: exclamation mark")
        # Quoted text (a commit message, an issue title) is kept verbatim.
        for m in BANNED.finditer(re.sub(r'"[^"]*"', "X", s)):
            r.w(f"{field}: word {m.group(0)!r}")
        for m in REPO_PATH.finditer(s):
            tok = m.group(1).rstrip(".,;:)")
            if "<" in tok or ">" in tok or "*" in tok:
                continue
            if not (ROOT / tok).exists():
                # a patch file that the text says was removed is not an error
                if tok.startswith("patches/") and REMOVED.search(s[max(0, m.start() - 60):m.end() + 60]):
                    continue
                r.e(f"{field}: path {tok} does not exist")
        if not isinstance(inst, str):
            continue
        for m in LOG_TOKEN.finditer(s):
            tok = m.group(1)
            if "<" in tok or ">" in tok or tok.startswith(PATH_PREFIXES) or tok in seen_tokens:
                continue
            seen_tokens.add(tok)
            if (ROOT / "logs" / inst / tok).exists():
                continue
            if tok.endswith((".sh", ".py", ".tsv")) and (ROOT / "scripts" / tok).exists():
                continue
            name = tok.rsplit("/", 1)[-1]
            logdir = ROOT / "logs" / inst
            if logdir.is_dir() and any(logdir.rglob(name)):
                continue
            # A name the instance's own logs print (a test-suite script, a
            # file inside the container) is not a dead reference.
            if logdir.is_dir() and any(tok in p.read_text(errors="replace") for p in logdir.glob("*.log")):
                continue
            r.w(f"{field}: logs/{inst}/{tok} does not exist")


def check_line(d, forbidden, seen):
    inst = d.get("instance_id", "?")
    r = Report(inst if isinstance(inst, str) else "?")
    if not isinstance(inst, str) or not INSTANCE.match(inst):
        r.e(f"instance_id {inst!r} is not of the form <project>.cve-<year>-<n>")
    if inst in seen:
        r.e("duplicate instance_id")
    seen.add(inst)
    keys = list(d.keys())
    for f in BASE_FIELDS:
        if f not in d:
            r.e(f"missing field {f}")
    if "dev_patch_fixes_root_cause" in d:
        i = keys.index("dev_patch_fixes_root_cause")
        if keys[i + 1:i + 5] != VERDICT:
            r.e("verdict fields must follow dev_patch_fixes_root_cause in the order "
                + ", ".join(VERDICT))
    for f in BOOL_FIELDS:
        if f in d and not isinstance(d[f], bool):
            r.e(f"{f} must be a boolean")
    if isinstance(d.get("poc_resolved"), bool) and isinstance(d.get("poc_crashed_after"), bool):
        if d["poc_resolved"] == d["poc_crashed_after"]:
            r.e("poc_resolved must equal not poc_crashed_after")
    if d.get("poc_crashed_before") is False:
        r.w("poc_crashed_before is false; the procedure stops when the PoC does not reproduce")
    st = d.get("semantic_status")
    flag = d.get("semantic_flag")
    if isinstance(st, str):
        if not STATUS.match(st):
            r.e("semantic_status must be 'not flagged', 'flagged, not reviewed', "
                "'confirmed <date> ...' or 'dismissed <date> ...'")
        if flag is True and st == "not flagged":
            r.e("semantic_flag is true but semantic_status is 'not flagged'")
        if flag is False and st != "not flagged":
            r.e("semantic_flag is false but semantic_status is not 'not flagged'")
    sr = d.get("semantic_reasoning")
    if isinstance(sr, str):
        if flag is True and not sr.startswith("consequence after the developer patch:"):
            r.e("semantic_reasoning of a flagged instance must open with "
                "'consequence after the developer patch:'")
        if flag is False and not sr.startswith("none"):
            r.e("semantic_reasoning of an unflagged instance must open with 'none'")
    if isinstance(inst, str):
        p = ROOT / "patches" / f"{inst}.diff"
        if not p.exists():
            r.e(f"patches/{inst}.diff is missing")
        elif d.get("patch_sha256") != sha256(p):
            r.e(f"patch_sha256 differs from the digest of patches/{inst}.diff")
    if d.get("dev_patch_fixes_root_cause") is False:
        for f in ROOT_FIELDS:
            if f not in d:
                r.e(f"dev_patch_fixes_root_cause is false but {f} is missing")
        rp = d.get("root_patch")
        if isinstance(rp, str) and rp:
            p = ROOT / rp
            if not p.exists():
                r.e(f"root_patch {rp} does not exist")
            elif d.get("root_patch_sha256") != sha256(p):
                r.e(f"root_patch_sha256 differs from the digest of {rp}")
        else:
            r.e("root_patch must name the root-cause patch file")
        src = d.get("root_patch_source")
        if not (isinstance(src, str) and SOURCE.match(src)):
            r.e("root_patch_source must be synthetic, upstream:<hash> or backport:<hash>[+<hash>]")
    for f in RIGOR_FIELDS:
        if f not in d:
            r.w(f"rigor field {f} is missing")
    pl = d.get("patches")
    if isinstance(pl, list):
        for i, p in enumerate(pl):
            if not isinstance(p, dict):
                r.e(f"patches[{i}] is not an object")
                continue
            role = p.get("role")
            if role not in ROLES:
                r.e(f"patches[{i}].role {role!r} is not developer, gold, minimal or root")
            path = p.get("path")
            if path:
                fp = ROOT / path
                if not fp.exists():
                    r.e(f"patches[{i}].path {path} does not exist")
                elif p.get("sha256") != sha256(fp):
                    r.e(f"patches[{i}].sha256 differs from the digest of {path}")
            elif role != "gold":
                r.e(f"patches[{i}] ({role}) has no path")
            src = p.get("source")
            if not (isinstance(src, str) and SOURCE.match(src)):
                r.e(f"patches[{i}].source {src!r} is not upstream:<hash>, backport:<hash>, "
                    "secbench:<path> or synthetic")
            if role != "gold":
                for k in ("fixes_poc", "fixes_root_cause", "tests", "status"):
                    if k not in p:
                        r.w(f"patches[{i}] lacks {k}")
    elif "patches" in d:
        r.e("patches must be a list")
    us = d.get("upstream_status", "")
    rfd = d.get("root_fix_distance")
    if isinstance(us, str) and "fixed upstream" in us.lower() and rfd is None \
            and "by the developer patch itself" not in us:
        if d.get("dev_patch_fixes_root_cause") is False:
            r.e("upstream_status names an upstream root fix but root_fix_distance is missing")
        else:
            r.w("upstream_status names an upstream fix but root_fix_distance is missing "
                "(required with a note when the fix is of a residual defect)")
    if rfd is not None:
        if not isinstance(rfd, dict):
            r.e("root_fix_distance must be an object")
        else:
            for k in DISTANCE_KEYS:
                if k not in rfd:
                    r.e(f"root_fix_distance lacks {k}")
            if "root_fix" in rfd and not isinstance(rfd["root_fix"], list):
                r.e("root_fix_distance.root_fix must be a list, one entry per commit")
    ts = d.get("timestamp")
    if isinstance(ts, str) and not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", ts):
        r.e("timestamp is not ISO 8601")
    dig = d.get("image_digest")
    if isinstance(dig, str) and "@sha256:" not in dig:
        r.e("image_digest must contain @sha256:")
    check_strings(d, inst, forbidden, r)
    return r


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("results", nargs="?", default=str(ROOT / "results.jsonl"))
    ap.add_argument("--forbid-file")
    ap.add_argument("--instance", action="append", default=[])
    a = ap.parse_args()
    forbidden = []
    if a.forbid_file:
        forbidden = [l.strip() for l in Path(a.forbid_file).read_text().splitlines()
                     if l.strip() and not l.startswith("#")]
    text = sys.stdin.read() if a.results == "-" else Path(a.results).read_text()
    seen = set()
    n_err = n_warn = n_lines = 0
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError as ex:
            print(f"line {lineno}: E invalid JSON: {ex}")
            n_err += 1
            continue
        if not isinstance(d, dict):
            print(f"line {lineno}: E not a JSON object")
            n_err += 1
            continue
        if a.instance and d.get("instance_id") not in a.instance:
            continue
        n_lines += 1
        r = check_line(d, forbidden, seen)
        for m in r.errors:
            print(f"{r.inst}: E {m}")
        for m in r.warnings:
            print(f"{r.inst}: W {m}")
        n_err += len(r.errors)
        n_warn += len(r.warnings)
    print(f"checked {n_lines} lines: {n_err} errors, {n_warn} warnings")
    sys.exit(1 if n_err else 0)


if __name__ == "__main__":
    main()
