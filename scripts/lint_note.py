#!/usr/bin/env python3
"""Check a note under notes/ against the writing conventions of this repository.

Usage: python3 scripts/lint_note.py [--forbid-file FILE] [--results RESULTS]
                                    [--name PATH] NOTE...

NOTE is a Markdown file; --name gives its repository path when the file is
a temporary copy (for example of the staged version). --forbid-file names a
file with one string per line that must not occur anywhere in the note.
--results names results.jsonl (default: the repository copy) and is used to
decide whether an instance note needs the root-cause sections.

Findings are printed as `<note>:<line>: E <message>` or `W <message>`; the
exit status is 1 if any error was found.

Errors: a non-ASCII character; first person singular or conversational
phrasing outside code; a forbidden string; a path under logs/, scripts/,
patches/, notes/ or data/ that does not exist; a required section missing
from an instance note (Summary, Mechanism, Developer patch, Root-cause
patch, Residual defect, Upstream status, Not covered; plus Predictions,
Developer model, Assertion, Second reading, Falsification and confidence
when RESULTS records dev_patch_fixes_root_cause false for the instance).

Warnings: two sentences on one line; an exclamation mark; a promotional
word; a log name relative to logs/<instance>/ that does not exist; a
case-count table in a note that does not mention render_cases_table.py.
Code fences and inline code are excluded from the style checks but not
from the forbidden-string and path checks.
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

INSTANCE = re.compile(r"^([a-z0-9-]+\.cve-\d{4}-\d+)\.md$")
WORKLIST = ROOT / "data" / "cve_nvd_review_worklist.csv"
SECTIONS = ["Summary", "Mechanism", "Developer patch", "Root-cause patch",
            "Residual defect", "Upstream status", "Not covered"]
ROOT_SECTIONS = ["Predictions", "Developer model", "Assertion", "Second reading",
                 "Falsification and confidence"]
BANNED = re.compile(r"\b(robust|comprehensive|seamless|significantly|very|clearly|obviously)\b", re.I)
FIRST_PERSON = re.compile(r"(?<![\w/])I(?=[\s,.'])|\bLet me\b|\bGreat\b")
ABBREV = re.compile(r"\b(e\.g|i\.e|vs|cf|et al|No|Fig|approx)\.")
TWO_SENTENCES = re.compile(r"[a-z0-9)\]\"'X]\.\s+[A-Z(\[\"']")
REPO_PATH = re.compile(r"(?<![\w/.-])((?:logs|scripts|patches|notes|data)/[\w./<>*-]+)")
LOG_TOKEN = re.compile(r"(?<![\w/.<>-])([\w<>-]+(?:/[\w.<>-]+)*\.(?:log|diff|tsv|sh|py))(?![\w/-])")
REMOVED = re.compile(r"\b(removed|deleted|dropped|no longer|not written|not kept|absent|withdrawn)\b", re.I)
PATH_PREFIXES = ("logs/", "scripts/", "patches/", "notes/", "data/")


def root_cause_instances(results):
    out = {}
    try:
        for line in Path(results).read_text().splitlines():
            if line.strip():
                d = json.loads(line)
                out[d.get("instance_id")] = d.get("dev_patch_fixes_root_cause")
    except (OSError, json.JSONDecodeError):
        return None
    return out


def lint(path, name, forbidden, results):
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    errors, warnings = [], []
    inst = None
    m = INSTANCE.match(Path(name).name)
    if m and Path(name).parts[0] == "notes":
        inst = m.group(1)
        if WORKLIST.exists() and inst not in WORKLIST.read_text() \
                and not (results and inst in results):
            inst = None
    in_fence = False
    headings = []
    has_case_table = False
    seen_tokens = set()
    log_text = None
    for n, raw in enumerate(lines, 1):
        bad = [c for c in raw if ord(c) > 126 or (ord(c) < 32 and c != "\t")]
        if bad:
            errors.append((n, f"non-ASCII character {bad[0]!r}"))
        low = raw.lower()
        for term in forbidden:
            if term and term.lower() in low:
                errors.append((n, f"forbidden string {term!r}"))
        for mm in REPO_PATH.finditer(raw):
            tok = mm.group(1).rstrip(".,;:)")
            if "<" in tok or ">" in tok or "*" in tok:
                continue
            if not (ROOT / tok).exists():
                if tok.startswith("patches/") and REMOVED.search(raw):
                    continue
                if tok.startswith("data/"):
                    warnings.append((n, f"path {tok} does not exist in this repository"))
                    continue
                errors.append((n, f"path {tok} does not exist"))
        if inst:
            for mm in LOG_TOKEN.finditer(raw):
                tok = mm.group(1)
                if "<" in tok or ">" in tok or tok.startswith(PATH_PREFIXES) or tok in seen_tokens:
                    continue
                seen_tokens.add(tok)
                if (ROOT / "logs" / inst / tok).exists():
                    continue
                if tok.endswith((".sh", ".py", ".tsv")) and (ROOT / "scripts" / tok).exists():
                    continue
                logdir = ROOT / "logs" / inst
                if logdir.is_dir() and any(logdir.rglob(tok.rsplit("/", 1)[-1])):
                    continue
                # A name the instance's own logs print (a test-suite script,
                # a file inside the container) is not a dead reference.
                if log_text is None:
                    log_text = "".join(p.read_text(errors="replace") for p in logdir.glob("*.log")) if logdir.is_dir() else ""
                if tok in log_text:
                    continue
                warnings.append((n, f"logs/{inst}/{tok} does not exist"))
        if raw.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if raw.startswith("#"):
            headings.append(raw.lstrip("#").strip())
            continue
        if raw.startswith("|"):
            if raw.startswith("| Case group") or raw.startswith("| Check |"):
                has_case_table = True
            continue
        prose = re.sub(r"`[^`]*`", "X", raw)
        if FIRST_PERSON.search(prose):
            errors.append((n, "first person singular or conversational phrasing"))
        if re.search(r"!(\s|$)", prose):
            warnings.append((n, "exclamation mark"))
        # Quoted text (a commit message, an issue title) is kept verbatim.
        for mm in BANNED.finditer(re.sub(r'"[^"]*"', "X", prose)):
            if mm.group(0).lower() == "significantly" and re.search(r"\d", prose):
                continue
            warnings.append((n, f"word {mm.group(0)!r}"))
        # An ordered-list marker ("1. ") is not the end of a sentence, and a
        # quoted commit message may hold several.
        unquoted = re.sub(r'"[^"]*"', "X", re.sub(r"^\s*\d+\.\s+", "", prose))
        if TWO_SENTENCES.search(ABBREV.sub("X", unquoted)):
            warnings.append((n, "two sentences on one line"))
    if inst:
        for sec in SECTIONS:
            if not any(h.startswith(sec) for h in headings):
                errors.append((0, f"missing section '{sec}'"))
        rc = results.get(inst) if results else None
        if results is not None and inst not in results:
            warnings.append((0, f"{inst} has no results.jsonl line; root-cause sections not checked"))
        elif rc is False:
            for sec in ROOT_SECTIONS:
                if not any(h.startswith(sec) for h in headings):
                    errors.append((0, f"missing section '{sec}' (dev_patch_fixes_root_cause is false)"))
        if has_case_table and "render_cases_table" not in text:
            warnings.append((0, "case-count table without a mention of scripts/render_cases_table.py"))
    return errors, warnings


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("notes", nargs="+")
    ap.add_argument("--forbid-file")
    ap.add_argument("--results", default=str(ROOT / "results.jsonl"))
    ap.add_argument("--name", help="repository path of the note when NOTE is a copy")
    a = ap.parse_args()
    forbidden = []
    if a.forbid_file:
        forbidden = [l.strip() for l in Path(a.forbid_file).read_text().splitlines()
                     if l.strip() and not l.startswith("#")]
    results = root_cause_instances(a.results)
    n_err = n_warn = 0
    for note in a.notes:
        name = a.name if (a.name and len(a.notes) == 1) else note
        try:
            name = str(Path(name).resolve().relative_to(ROOT))
        except ValueError:
            pass
        errors, warnings = lint(note, name, forbidden, results)
        for n, msg in errors:
            print(f"{name}:{n}: E {msg}")
        for n, msg in warnings:
            print(f"{name}:{n}: W {msg}")
        n_err += len(errors)
        n_warn += len(warnings)
    print(f"checked {len(a.notes)} notes: {n_err} errors, {n_warn} warnings")
    sys.exit(1 if n_err else 0)


if __name__ == "__main__":
    main()
