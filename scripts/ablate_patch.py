"""Write ablation variants of a unified diff: the patch minus some changed lines.

Usage: python3 ablate_patch.py PATCH OUTDIR [NAME=I,J,... ...]

Changed lines ('+' and '-' lines inside hunks) are numbered 1..N in patch
order. For each i, OUTDIR/L<i>.diff is the patch without changed line i.
Each NAME=I,J,... argument adds OUTDIR/<NAME>.diff without the listed
lines. Dropping a '+' line removes it; dropping a '-' line keeps the
original line as context. Hunk headers are recomputed, and hunks left with
no change are removed. OUTDIR/MANIFEST lists every variant and the lines
it drops.
"""
import re
import sys
from pathlib import Path

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")


def parse(text):
    """Return a list of files: (header_lines, [(old_start, tail, body_lines)])."""
    files, cur, hunk = [], None, None
    for line in text.splitlines():
        m = HUNK.match(line)
        if line.startswith("diff --git"):
            cur = ([line], [])
            files.append(cur)
            hunk = None
        elif m:
            hunk = (int(m.group(1)), m.group(5), [])
            cur[1].append(hunk)
        elif hunk is None:
            cur[0].append(line)
        else:
            hunk[2].append(line)
    return files


def render(files, drop):
    out, idx = [], 0
    for header, hunks in files:
        body_out, delta = [], 0
        for old_start, tail, body in hunks:
            lines = []
            for line in body:
                if line[:1] in "+-":
                    idx += 1
                    if idx in drop:
                        if line[0] == "-":
                            lines.append(" " + line[1:])
                        continue
                lines.append(line)
            # trailing empty strings come from blank lines after the patch
            while lines and lines[-1] == "":
                lines.pop()
            if not any(l[:1] in "+-" for l in lines):
                continue
            old_n = sum(1 for l in lines if l[:1] in " -" or l == "")
            new_n = sum(1 for l in lines if l[:1] in " +" or l == "")
            body_out.append(f"@@ -{old_start},{old_n} +{old_start + delta},{new_n} @@{tail}")
            body_out.extend(lines)
            delta += new_n - old_n
        if body_out:
            out.extend(header)
            out.extend(body_out)
    return "\n".join(out) + "\n"


def main():
    patch, outdir = Path(sys.argv[1]), Path(sys.argv[2])
    files = parse(patch.read_text())
    changed = [l for _, hunks in files for _, _, body in hunks for l in body if l[:1] in "+-"]
    outdir.mkdir(parents=True, exist_ok=True)
    variants = [(f"L{i}", {i}) for i in range(1, len(changed) + 1)]
    for arg in sys.argv[3:]:
        name, idx = arg.split("=", 1)
        variants.append((name, {int(x) for x in idx.split(",")}))
    with open(outdir / "MANIFEST", "w") as man:
        for i, line in enumerate(changed, 1):
            man.write(f"line {i}: {line}\n")
        for name, drop in variants:
            (outdir / f"{name}.diff").write_text(render(files, drop))
            man.write(f"{name}: drops {','.join(map(str, sorted(drop)))}\n")
    print(f"{len(changed)} changed lines, {len(variants)} variants")


if __name__ == "__main__":
    main()
