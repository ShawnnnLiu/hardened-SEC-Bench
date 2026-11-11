"""Predicted result class of every scripts/rfpcm_wav_cases.py run under
each hypothesis, for scripts/check_predictions.py (gpac.cve-2023-5586).

Prints a TSV with one column per <model>:<variant>. A case is
<input>.<consumer> for the dataset PoC (poc2_null) and the files of
scripts/make_wav_cases.py, each through the consumers poc, add, inspect
and pcm. Classes are OK, WRONG, ASAN, INV (RFPCM-INVARIANT, the check of
scripts/rfpcm_wav_invariant.diff) or - (not modelled). Every hypothesis
below gives the same class for all four consumers, since all four load
the same rfpcm filter and the failure happens before any consumer-specific
step.

dev: the developer's model, from issue #2632 (the PoC log shows
  "[PCMReframe] Missing audio sample rate, cannot parse" before the NULL
  pid access) and from the patch, which rejects channel count 0 and
  sample rate 0 in the WAVE header: a header with sample rate 0 or
  channel count 0 makes pcmreframe_configure_pid() fail before it creates
  the output pid, and the packet loop then uses the NULL pid. It predicts
  ASAN for every input whose fmt chunk has sample rate 0 or channel count
  0, whatever the format tag, OK for every other input, and OK for every
  input after the patch.
ours: H1, the CVE path. pcmreframe_configure_pid() creates the output pid
  only if the sample format is known (safmt != 0, checked first, at base
  line 80), the sample rate is not 0 (line 87) and the channel count is
  not 0 (line 91). The WAVE branch of pcmreframe_process() accepts a
  header without checking any of the three, ignores what
  pcmreframe_configure_pid() did (line 377), and continues as if the
  output pid existed. The invariant: a header the parser accepts leaves
  an output pid. Two ways to violate it:
  (a) known format, sample rate or channel count 0: configure_pid returns
      GF_BAD_PARAM, probe_wave stays 2, the packet loop calls
      gf_filter_pck_new_alloc() with a NULL pid: ASAN (SEGV).
  (b) unknown format (tag other than 1, 3, 0xFFFE; or no fmt chunk before
      data, which leaves sr and ch at the filter defaults 44100 and 2):
      configure_pid takes its probing branch, sets probe_wave back to 1
      and returns GF_OK without a pid, so the same packet is parsed again
      on every call: WRONG (timeout or the filter watchdog). With an
      unknown format, (b) applies whatever sr and ch are, because the
      format is checked first.
  The developer patch rejects (a) and every input of (b) that also has a
  zero field; (b) with non-zero fields stays WRONG. The `safmt` variant
  (the check of 3d9c5de08b alone) rejects all of (b) and leaves (a). The
  root-cause patch (developer patch + that check) rejects both.
  H2, residual: a header whose fmt chunk starts after the first 5000-byte
  input block is parsed from accumulated blocks; the header offset is
  then applied to the current block instead of the accumulated buffer:
  ASAN for the two valid long-header files in every variant, including
  upstream master (no variant fixes it).
  H3, residual: the early return for an incomplete header leaks the
  bitstream reader; LeakSanitizer reports it (ASAN) when the process
  exits normally after such a return, i.e. for bad_list8k_sr0_s16 once
  the zero sample rate is rejected (after, root), and not when 3fe087c39d
  is applied (leak, root_leak, upstream_master). In the base build the
  same input crashes first (H1).
  12-bit PCM is rejected by the parser in every build (OK).
  assert_before: the RFPCM-INVARIANT check fires for every input of (a)
  and (b), including bad_list8k_sr0_s16 (the check exits with _exit, so
  no leak report follows); valid inputs pass the check (H2 still ASAN).
  assert_root: the check fires for no input; bad_list8k_sr0_s16 is ASAN
  (H3) as in root.

Written 2026-10-12T23:50Z. Before this file existed, 25 of the 32
generated files and the PoC had been run through the four consumers on
the before, after and upstream_master builds with the earlier runner
(scripts/gpac_wav_cases.sh, first case run), and the new runner had been
tried on the PoC and 3 valid files on the developer-patch build. The 7
files added on 2026-10-12 (bad_tag2_sr0_s16, bad_tag2_ch0_s16,
bad_tag6_alaw, bad_no_fmt, bad_fmt_twice_ch0, bad_sr0_u8,
bad_ch0_float64) and the variants safmt, root, leak, root_leak,
assert_before and assert_root had not been run on any build.
"""

# input -> (kind, dev zero field)
# kinds: zero (H1a), zero_long (H1a + H3), fmt0 (H1b), fmt0_zero (H1b with a
# zero field), valid, valid_long (H2), parser_reject
INPUTS = [
    ("poc2_null", "zero", True),
    ("bad_sr0_ch256_s16", "zero", True),
    ("bad_sr0_mono_s16", "zero", True),
    ("bad_ch0_16k_s16", "zero", True),
    ("bad_ch0_sr0_s16", "zero", True),
    ("bad_sr0_float32", "zero", True),
    ("bad_ext_sr0_s16", "zero", True),
    ("bad_ext_ch0_s16", "zero", True),
    ("bad_fmt_twice_sr0", "zero", True),
    ("bad_list8k_sr0_s16", "zero_long", True),
    ("bad_data_before_fmt", "fmt0", False),
    ("bad_tag2_mono_16k", "fmt0", False),
    ("bad_bps12_mono_16k", "parser_reject", False),
    ("bad_tag2_sr0_s16", "fmt0_zero", True),
    ("bad_tag2_ch0_s16", "fmt0_zero", True),
    ("bad_tag6_alaw", "fmt0", False),
    ("bad_no_fmt", "fmt0", False),
    ("bad_fmt_twice_ch0", "zero", True),
    ("bad_sr0_u8", "zero", True),
    ("bad_ch0_float64", "zero", True),
    ("valid_pcm_u8_mono_8k", "valid", False),
    ("valid_pcm_s16_stereo_44k", "valid", False),
    ("valid_pcm_s24_stereo_48k", "valid", False),
    ("valid_pcm_s32_mono_48k", "valid", False),
    ("valid_pcm_s16_6ch_48k", "valid", False),
    ("valid_float32_stereo_48k", "valid", False),
    ("valid_float64_mono_22k", "valid", False),
    ("valid_ext_s16_stereo_48k", "valid", False),
    ("valid_ext_s24_5p1_48k", "valid", False),
    ("valid_list_before_fmt_s16", "valid", False),
    ("valid_list4900_before_fmt_s16", "valid", False),
    ("valid_list5000_before_fmt_s16", "valid_long", False),
    ("valid_list8000_before_fmt_s16", "valid_long", False),
]

VARIANTS = ["before", "after", "safmt", "root", "leak", "root_leak", "upstream_master",
            "assert_before", "assert_root"]

# ours, per kind, in the order of VARIANTS
OURS = {
    "zero":          ["ASAN", "OK", "ASAN", "OK", "ASAN", "OK", "OK", "INV", "OK"],
    "zero_long":     ["ASAN", "ASAN", "ASAN", "ASAN", "ASAN", "OK", "OK", "INV", "ASAN"],
    "fmt0":          ["WRONG", "WRONG", "OK", "OK", "WRONG", "OK", "OK", "INV", "OK"],
    "fmt0_zero":     ["WRONG", "OK", "OK", "OK", "WRONG", "OK", "OK", "INV", "OK"],
    "valid":         ["OK"] * 9,
    "valid_long":    ["ASAN"] * 9,
    "parser_reject": ["OK"] * 9,
}

cols = ["dev:before", "dev:after"] + [f"ours:{v}" for v in VARIANTS]
print("\t".join(["case"] + cols))
for name, kind, zero_field in INPUTS:
    for consumer in ("poc", "add", "inspect", "pcm"):
        dev = ["ASAN" if zero_field else "OK", "OK"]
        print("\t".join([f"{name}.{consumer}"] + dev + OURS[kind]))
