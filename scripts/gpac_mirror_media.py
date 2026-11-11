"""Mirror the external media of the GPAC test suite and write a sha256 manifest.

Usage: python3 scripts/gpac_mirror_media.py OUTDIR [--check MANIFEST]

Downloads the media tree that "make_tests.sh -sync-media" fetches with
"wget -m -nH --cut-dirs=4" into OUTDIR/external_media, with the same layout
and the same exclusions (*.gif, index.html*), and writes
OUTDIR/external_media.sha256 in sha256sum format. The remote tree is not
versioned, so the manifest is what identifies the media a test run used.
With --check, the new manifest must equal MANIFEST or the script exits 1.
"""
import argparse
import hashlib
import re
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

MEDIA_URL = "https://download.tsi.telecom-paristech.fr/gpac/gpac_test_suite/resources/media/"


def listing(url):
    html = urllib.request.urlopen(url, timeout=120).read().decode("utf-8", "replace")
    return [m.group(1) for m in re.finditer(r'<a href="([^"?][^"]*)">', html)
            if not m.group(1).startswith(("/", "..", "http"))]


def walk(url, rel, files):
    for name in listing(url):
        if name.endswith("/"):
            walk(url + name, rel + name, files)
        elif not name.endswith(".gif") and not name.startswith("index.html"):
            files.append((url + name, urllib.parse.unquote(rel + name)))


def fetch(item, root):
    url, rel = item
    dst = root / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(dst.name + ".part")
    h = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=600) as r, open(tmp, "wb") as f:
        while chunk := r.read(1 << 20):
            f.write(chunk)
            h.update(chunk)
    tmp.replace(dst)
    return f"{h.hexdigest()}  {rel}"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("outdir", type=Path)
    p.add_argument("--check", type=Path, help="manifest the mirror must match")
    args = p.parse_args()

    root = args.outdir / "external_media"
    files = []
    walk(MEDIA_URL, "", files)
    with ThreadPoolExecutor(6) as ex:
        lines = sorted(ex.map(lambda it: fetch(it, root), files), key=lambda l: l.split("  ", 1)[1])
    manifest = args.outdir / "external_media.sha256"
    manifest.write_text("\n".join(lines) + "\n")
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    print(f"{len(lines)} files, manifest sha256 {digest}")
    if args.check and args.check.read_bytes() != manifest.read_bytes():
        print(f"manifest differs from {args.check}")
        sys.exit(1)


if __name__ == "__main__":
    main()
