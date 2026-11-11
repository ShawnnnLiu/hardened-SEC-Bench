"""Write WAVE test inputs for gpac.cve-2023-5586 into OUTDIR.

Usage: python3 make_wav_cases.py OUTDIR

Two groups of files are written, all deterministic:
  valid_*.wav  well-formed files covering every format branch of the rfpcm
               WAVE header parser (PCM 8/16/24/32, float 32/64,
               WAVE_FORMAT_EXTENSIBLE, extra chunks before fmt), including
               headers that end after gpac's first 5000-byte input block
  bad_*.wav    malformed headers: the published PoC fields (sample rate 0)
               and the other values that make pcmreframe_configure_pid()
               fail or return without an output pid (channels 0, unknown
               format tag, data before fmt, no fmt chunk), alone and
               combined, the same values in a second fmt chunk and in a
               header spanning input blocks, plus a header the parser
               already rejected

OUTDIR/expected.tsv holds the expected result of each file, computed here
from the bytes written and not from gpac: for a valid file "decode" with
sample rate, channel count, gpac audio format name, frame count, the size
and MPEG-2 CRC32 (the CRC gpac's inspect filter prints) of each packet of
1024 frames (the rfpcm default framelen), and the sha256 of the data chunk
payload; for a bad file "reject". The PCM payloads are also read back with
the Python wave module where it supports the format (tag 1 and
WAVE_FORMAT_EXTENSIBLE PCM), and the result of that check is printed.

The files bad_tag2_sr0_s16, bad_tag2_ch0_s16, bad_tag6_alaw, bad_no_fmt,
bad_fmt_twice_ch0, bad_sr0_u8 and bad_ch0_float64 and expected.tsv were
added on 2026-10-12, after the first case run; the other files are
byte-identical to that run.
"""
import hashlib
import math
import struct
import sys
import wave
from pathlib import Path

FRAMELEN = 1024
AFMT = {(1, 8): "u8", (1, 16): "s16", (1, 24): "s24", (1, 32): "s32", (3, 32): "flt", (3, 64): "dbl"}


def _crc_table():
    t = []
    for i in range(256):
        c = i << 24
        for _ in range(8):
            c = ((c << 1) ^ 0x04C11DB7) if c & 0x80000000 else (c << 1)
        t.append(c & 0xFFFFFFFF)
    return t


CRC_TABLE = _crc_table()


def crc32_mpeg2(b):
    c = 0xFFFFFFFF
    for x in b:
        c = ((c << 8) & 0xFFFFFFFF) ^ CRC_TABLE[((c >> 24) ^ x) & 0xFF]
    return c


def fmt_chunk(tag, ch, sr, bps, ext=None):
    block = ch * bps // 8
    body = struct.pack("<HHIIHH", tag, ch, sr, sr * block, block, bps)
    if ext is not None:
        valid_bits, mask, guid_tag = ext
        guid = struct.pack("<H", guid_tag) + bytes.fromhex("000000001000800000aa00389b71")
        body += struct.pack("<HHI", 22, valid_bits, mask) + guid
    return b"fmt " + struct.pack("<I", len(body)) + body


def riff(chunks):
    payload = b"WAVE" + b"".join(chunks)
    return b"RIFF" + struct.pack("<I", len(payload)) + payload


def data_chunk(raw):
    pad = b"\x00" if len(raw) % 2 else b""
    return b"data" + struct.pack("<I", len(raw)) + raw + pad


def samples(tag, ch, sr, bps, n):
    """n frames of a per-channel sine, encoded as the given format."""
    out = bytearray()
    for i in range(n):
        for c in range(ch):
            v = 0.5 * math.sin(2 * math.pi * (220 * (c + 1)) * i / sr)
            if tag == 3 and bps == 32:
                out += struct.pack("<f", v)
            elif tag == 3 and bps == 64:
                out += struct.pack("<d", v)
            elif bps == 8:
                out += struct.pack("<B", int(128 + 127 * v))
            elif bps == 16:
                out += struct.pack("<h", int(32767 * v))
            elif bps == 24:
                out += struct.pack("<i", int(8388607 * v))[:3]
            elif bps == 32:
                out += struct.pack("<i", int(2147483647 * v))
    return bytes(out)


def valid_cases():
    # (name, format tag, channels, sample rate, bits, extensible info)
    specs = [
        ("valid_pcm_u8_mono_8k", 1, 1, 8000, 8, None),
        ("valid_pcm_s16_stereo_44k", 1, 2, 44100, 16, None),
        ("valid_pcm_s24_stereo_48k", 1, 2, 48000, 24, None),
        ("valid_pcm_s32_mono_48k", 1, 1, 48000, 32, None),
        ("valid_pcm_s16_6ch_48k", 1, 6, 48000, 16, None),
        ("valid_float32_stereo_48k", 3, 2, 48000, 32, None),
        ("valid_float64_mono_22k", 3, 1, 22050, 64, None),
        ("valid_ext_s16_stereo_48k", 0xFFFE, 2, 48000, 16, (16, 0x3, 1)),
        ("valid_ext_s24_5p1_48k", 0xFFFE, 6, 48000, 24, (24, 0x3F, 1)),
    ]
    for name, tag, ch, sr, bps, ext in specs:
        n = sr // 5  # 0.2 s, several 1024-sample frames
        raw = samples(ext[2] if ext else tag, ch, sr, bps, n)
        yield name, riff([fmt_chunk(tag, ch, sr, bps, ext), data_chunk(raw)])
    # extra LIST chunk before fmt: exercises the chunk-skip loop
    raw = samples(1, 2, 44100, 16, 8820)
    info = b"INFOISFT" + struct.pack("<I", 6) + b"gpac\x00\x00"
    lst = b"LIST" + struct.pack("<I", len(info)) + info
    yield "valid_list_before_fmt_s16", riff([lst, fmt_chunk(1, 2, 44100, 16), data_chunk(raw)])
    # LIST chunks of 4900, 5000 and 8000 bytes put the end of the header
    # (data chunk header) at byte 4952, 5052 and 8052. gpac reads files in
    # 5000-byte blocks by default, so the last two are parsed from
    # accumulated packets (the probe_data branch)
    for n in (4900, 5000, 8000):
        yield f"valid_list{n}_before_fmt_s16", riff([big_list(n), fmt_chunk(1, 2, 44100, 16), data_chunk(raw)])


def big_list(n=8000):
    """A LIST chunk of n payload bytes, so fmt starts at byte 20 + n."""
    return b"LIST" + struct.pack("<I", n) + b"INFO" + b"\x00" * (n - 4)


def bad_cases():
    raw = samples(1, 1, 16000, 16, 4096)
    # the published PoC header fields: tag 1, 256 channels, sample rate 0, 16 bits
    yield "bad_sr0_ch256_s16", riff([fmt_chunk(1, 256, 0, 16), data_chunk(raw)])
    yield "bad_sr0_mono_s16", riff([fmt_chunk(1, 1, 0, 16), data_chunk(raw)])
    yield "bad_ch0_16k_s16", riff([fmt_chunk(1, 0, 16000, 16), data_chunk(raw)])
    yield "bad_ch0_sr0_s16", riff([fmt_chunk(1, 0, 0, 16), data_chunk(raw)])
    yield "bad_sr0_float32", riff([fmt_chunk(3, 2, 0, 32), data_chunk(raw)])
    yield "bad_ext_sr0_s16", riff([fmt_chunk(0xFFFE, 2, 0, 16, (16, 0x3, 1)), data_chunk(raw)])
    yield "bad_ext_ch0_s16", riff([fmt_chunk(0xFFFE, 0, 48000, 16, (16, 0x3, 1)), data_chunk(raw)])
    # a second fmt chunk overrides a valid first one
    yield "bad_fmt_twice_sr0", riff([fmt_chunk(1, 1, 16000, 16), fmt_chunk(1, 1, 0, 16), data_chunk(raw)])
    # sample rate 0 in a header parsed from accumulated packets (probe_data)
    yield "bad_list8k_sr0_s16", riff([big_list(), fmt_chunk(1, 1, 0, 16), data_chunk(raw)])
    # data before fmt: the parser stops at data, fmt is never read, safmt stays 0
    yield "bad_data_before_fmt", riff([data_chunk(raw), fmt_chunk(1, 1, 16000, 16)])
    # format tag 2 (ADPCM) is not handled: safmt stays 0 and wav_ok stays true
    yield "bad_tag2_mono_16k", riff([fmt_chunk(2, 1, 16000, 16), data_chunk(raw)])
    # 12-bit PCM: rejected by the parser before the developer patch as well
    yield "bad_bps12_mono_16k", riff([fmt_chunk(1, 1, 16000, 12), data_chunk(raw)])
    # unknown format tag combined with a zero field: configure_pid() checks
    # the format before the sample rate and channel count
    yield "bad_tag2_sr0_s16", riff([fmt_chunk(2, 1, 0, 16), data_chunk(raw)])
    yield "bad_tag2_ch0_s16", riff([fmt_chunk(2, 0, 16000, 16), data_chunk(raw)])
    # format tag 6 (A-law) is not handled either
    yield "bad_tag6_alaw", riff([fmt_chunk(6, 1, 8000, 8), data_chunk(raw)])
    # no fmt chunk at all: safmt stays 0, sr and ch keep the filter defaults
    yield "bad_no_fmt", riff([data_chunk(raw)])
    # channel count 0 in a second fmt chunk; zero fields with other formats
    yield "bad_fmt_twice_ch0", riff([fmt_chunk(1, 1, 16000, 16), fmt_chunk(1, 0, 16000, 16), data_chunk(raw)])
    yield "bad_sr0_u8", riff([fmt_chunk(1, 1, 0, 8), data_chunk(raw)])
    yield "bad_ch0_float64", riff([fmt_chunk(3, 0, 22050, 64), data_chunk(raw)])


def reference(blob):
    """Expected decode of a well-formed file, from the RIFF chunks."""
    assert blob[:4] == b"RIFF" and blob[8:12] == b"WAVE"
    pos, fmt, payload = 12, None, None
    while pos + 8 <= len(blob):
        cid, size = blob[pos:pos + 4], struct.unpack("<I", blob[pos + 4:pos + 8])[0]
        body = blob[pos + 8:pos + 8 + size]
        if cid == b"fmt ":
            tag, ch, sr, _, _, bps = struct.unpack("<HHIIHH", body[:16])
            if tag == 0xFFFE:
                tag = struct.unpack("<H", body[24:26])[0]  # sub-format GUID
            fmt = (tag, ch, sr, bps)
        elif cid == b"data":
            payload = body
        pos += 8 + size + (size & 1)
    tag, ch, sr, bps = fmt
    block = ch * bps // 8
    frame = FRAMELEN * block
    pk = [f"{len(payload[i:i + frame])}:{crc32_mpeg2(payload[i:i + frame]):08X}"
          for i in range(0, len(payload), frame)]
    return [AFMT[(tag, bps)], str(sr), str(ch), str(len(payload) // block), ",".join(pk),
            hashlib.sha256(payload).hexdigest()]


def wave_check(path, blob):
    """Read the payload back with the wave module; None if unsupported."""
    try:
        with wave.open(str(path)) as w:
            got = w.readframes(w.getnframes())
            params = (w.getframerate(), w.getnchannels(), w.getsampwidth() * 8)
    except wave.Error:
        return None
    exp = reference(blob)
    return bool(got) and hashlib.sha256(got).hexdigest() == exp[5] and params == (int(exp[1]), int(exp[2]), {"u8": 8, "s16": 16, "s24": 24, "s32": 32}[exp[0]])


def main():
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    rows, checked, agreed = [], 0, 0
    for name, blob in list(valid_cases()) + list(bad_cases()):
        path = out / f"{name}.wav"
        path.write_bytes(blob)
        print(f"{name}.wav {len(blob)}")
        if name.startswith("valid_"):
            rows.append([name, "decode"] + reference(blob))
            ok = wave_check(path, blob)
            if ok is not None:
                checked += 1
                agreed += bool(ok)
        else:
            rows.append([name, "reject"] + ["-"] * 6)
    with open(out / "expected.tsv", "w") as f:
        f.write("name\texpect\tafmt\tsr\tch\tframes\tpackets\tpayload_sha256\n")
        for r in rows:
            f.write("\t".join(r) + "\n")
    print(f"oracle: expected.tsv sha256 {hashlib.sha256((out / 'expected.tsv').read_bytes()).hexdigest()}; "
          f"wave module (Python {sys.version.split()[0]}) agrees on {agreed} of {checked} PCM payloads it reads")


if __name__ == "__main__":
    main()
