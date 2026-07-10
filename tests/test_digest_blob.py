"""Tests for the blob digest path - describes unrecognized bytes.

Pins the architectural rails of Gate 2:
- O(sample): the profiler reads a bounded sample, never the whole file.
- Zero field extraction: no timestamp, no fields - bytes and shape-guesses.
- Shared banner: blob's RunSummary routes through _render_run_summary like
  schema cards, via the additive record_label / data_window seams.
- Vanish-don't-dash: optional slots that don't apply are omitted entirely.
- Sniff-only entry: blob is reached via the sniff floor, never an operator
  token.

All synthetic content. Per the project's data-privacy rule, no real network
artifacts.
"""

from __future__ import annotations

import gzip
import io
import math
from pathlib import Path
from typing import Any

import pandas as pd
import pytest

import sigwood.cli as cli
import sigwood.outputs.text as text_module
import sigwood.runner as runner
from sigwood.common.errors import DigestEmpty
from sigwood.common.finding import BlobCard, RunSummary
from sigwood.digest import blob as blob_digest
from sigwood.outputs.text import TextHandler


# ─── Helpers ────────────────────────────────────────────────────────────────

_DATA_CONTROLS = ("\x1b", "\x00", "\x07", "\r", "\x9b")


def _assert_no_data_controls(text: str) -> None:
    for ch in _DATA_CONTROLS:
        assert ch not in text


def _render(card: BlobCard, source_name: str = "mystery.txt") -> str:
    """Render a blob card. source_name is overridden on the card before
    render so older fixtures still pin identity-line-1 to a known name."""
    card.source_name = source_name
    stream = io.StringIO()
    handler = TextHandler(stream=stream, verbose_level=0)
    handler.render_blob(card)
    return stream.getvalue()


def _binary_blob_card() -> BlobCard:
    """A BlobCard shaped like a terminal-magic binary hit (PNG)."""
    return BlobCard(
        source_name="mystery.bin",
        byte_size=4096,
        sampled_line_count=0,
        sample_read_count=1,
        is_compressed=False,
        printable_pct=0.1,
        nonprintable_pct=99.9,
        utf8_clean=False,
        file_type_guess="PNG image",
        file_type_magic=b"\x89PNG\r\n\x1a\n",
        shape_guess=None,
    )


def _text_blob_card(
    *,
    shape_guess: str = "freeform text",
    sampled_line_count: int = 1000,
    utf8_clean: bool = True,
    has_templates: bool = True,
    has_tokens: bool = True,
) -> BlobCard:
    """A BlobCard shaped like a text path with all text slots populated."""
    return BlobCard(
        source_name="mystery.txt",
        byte_size=64_000,
        sampled_line_count=sampled_line_count,
        sample_read_count=6,
        is_compressed=False,
        printable_pct=99.7,
        nonprintable_pct=0.3,
        utf8_clean=utf8_clean,
        file_type_guess=None,
        file_type_magic=None,
        shape_guess=shape_guess,
        mean_line_length=412.0,
        median_line_length=400.0,
        line_length_p95=980,
        max_line_length=4201,
        line_length_stdev=120.0,
        line_length_shape="varied",
        top_tokens=(
            [("level", 200), ("ts", 200), ("msg", 200), ("service", 200), ("trace_id", 200)]
            if has_tokens else None
        ),
        distinct_templates=140 if has_templates else None,
        top_template_coverage_pct=78.0 if has_templates else None,
        top_template_n=6 if has_templates else None,
        singleton_template_count=12 if has_templates else None,
    )


# ─── O(sample) rail (PRIMARY: deterministic byte counter) ───────────────────


def test_o_sample_rail_bounded_byte_budget(tmp_path, monkeypatch) -> None:
    """The profiler reads a bounded sample regardless of file size. Wrap the
    low-level reads so we can count bytes pulled off disk; assert the total
    is within the head + seek budget. This is the PRIMARY rail enforcement -
    a determinism gate, not a wall-clock smoke test."""
    big = tmp_path / "big.log"
    payload = b"a" * 64 + b"\n"  # 65-byte lines
    # ~5 MB - enough to exercise the seek path (well above _SEEK_MIN_SIZE).
    with big.open("wb") as fh:
        for _ in range(80_000):
            fh.write(payload)

    bytes_read = 0
    readline_bytes = 0

    real_open = Path.open

    def spy_open(self, mode="r", *args, **kwargs):
        fh = real_open(self, mode, *args, **kwargs)
        if "b" in mode and self == big:
            real_read = fh.read
            real_readline = fh.readline

            def counted_read(n=-1):
                nonlocal bytes_read
                data = real_read(n)
                bytes_read += len(data)
                return data

            def counted_readline(*a, **kw):
                nonlocal readline_bytes
                data = real_readline(*a, **kw)
                readline_bytes += len(data)
                return data

            fh.read = counted_read
            fh.readline = counted_readline
        return fh

    monkeypatch.setattr(Path, "open", spy_open)

    card = blob_digest.summarize_blob(big)

    head = blob_digest._HEAD_BYTES
    seeks = blob_digest._SEEK_COUNT
    seek_bytes = blob_digest._SEEK_BYTES
    # Hard budget: head + seeks * seek_bytes - NO slack for readline,
    # because the seek skip is now a bounded read, not a readline scan.
    budget = head + seeks * seek_bytes
    total = bytes_read + readline_bytes
    assert total <= budget, (
        f"profiler pulled {total:,} bytes "
        f"(read={bytes_read:,}, readline={readline_bytes:,}); "
        f"budget {budget:,}"
    )
    # And the card still characterises the file.
    assert card.shape_guess is not None
    assert card.sampled_line_count > 0


def test_o_sample_rail_holds_on_long_line_no_newline_file(tmp_path) -> None:
    """REGRESSION: an earlier impl used fh.readline() to discard the partial
    first line after each seek. With a 5 MB single-line file, that pulled
    13 MB through readline() (scanning to EOF) - violating the rail and
    invisible to the read()-only spy.

    The fix is a hard-bounded seek window: read EXACTLY _SEEK_BYTES, find
    the first newline within it, return the post-newline slice; if no
    newline in the window, return empty and let the head sample carry the
    cascade. Total disk I/O per seek is _SEEK_BYTES - no more.

    This test asserts via the spy on bytes-mode .read() AND on .readline().
    Both must total within budget. Long lines are a real shape for
    minified logs, single-line dumps, and certain export formats - the
    rail has to hold there too.
    """
    big = tmp_path / "longline.log"
    # 5 MB of a single line - no newline anywhere except at the end.
    payload = b"a" * (5 * 1024 * 1024) + b"\n"
    big.write_bytes(payload)

    bytes_read = 0
    readline_bytes = 0

    real_open = Path.open

    def spy_open(self, mode="r", *args, **kwargs):
        fh = real_open(self, mode, *args, **kwargs)
        if "b" in mode and self == big:
            real_read = fh.read
            real_readline = fh.readline

            def counted_read(n=-1):
                nonlocal bytes_read
                data = real_read(n)
                bytes_read += len(data)
                return data

            def counted_readline(*a, **kw):
                nonlocal readline_bytes
                data = real_readline(*a, **kw)
                readline_bytes += len(data)
                return data

            fh.read = counted_read
            fh.readline = counted_readline
        return fh

    import unittest.mock
    with unittest.mock.patch.object(Path, "open", spy_open):
        card = blob_digest.summarize_blob(big)

    head = blob_digest._HEAD_BYTES
    seeks = blob_digest._SEEK_COUNT
    seek_bytes = blob_digest._SEEK_BYTES
    # Hard budget: head once + at most seek_bytes per seek. No readline.
    budget = head + seeks * seek_bytes
    total = bytes_read + readline_bytes
    assert total <= budget, (
        f"long-line file pulled {total:,} bytes "
        f"(read={bytes_read:,}, readline={readline_bytes:,}); "
        f"budget {budget:,}"
    )
    # And readline() must contribute zero - the fix is "no readline at all".
    assert readline_bytes == 0
    # Card still well-formed even with all-empty body chunks.
    assert isinstance(card, BlobCard)


def test_determinism_same_file_yields_identical_card(tmp_path) -> None:
    """Seek offsets must be derived from file size - no unseeded randomness.
    Same file → same sample → identical card."""
    p = tmp_path / "log.txt"
    with p.open("wb") as fh:
        for i in range(20_000):
            fh.write(f"event {i} payload alpha beta gamma\n".encode())

    a = blob_digest.summarize_blob(p)
    b = blob_digest.summarize_blob(p)
    assert a.sampled_line_count == b.sampled_line_count
    assert a.sample_read_count == b.sample_read_count
    assert a.top_tokens == b.top_tokens
    assert a.mean_line_length == b.mean_line_length
    assert a.line_length_p95 == b.line_length_p95
    assert a.shape_guess == b.shape_guess


# ─── Magic-byte identification ──────────────────────────────────────────────


def test_terminal_magic_png_skips_text_cascade(tmp_path) -> None:
    p = tmp_path / "img.png"
    # PNG header + arbitrary binary tail.
    p.write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 64)

    card = blob_digest.summarize_blob(p)
    assert card.file_type_guess == "PNG image"
    assert card.file_type_magic == b"\x89PNG\r\n\x1a\n"
    # Text slots vanish.
    assert card.shape_guess is None
    assert card.mean_line_length is None
    assert card.top_tokens is None
    assert card.distinct_templates is None


def test_char_class_binary_no_magic_summarizes_as_binary(tmp_path) -> None:
    """A signature-less sample that is not clean UTF-8 and predominantly
    non-printable is a BINARY verdict (text slots vanish), NOT 'freeform text'
    with mojibake tokens - the honesty rail extended to a magic-less binary."""
    p = tmp_path / "mystery.bin"
    # 37.5% printable ASCII interleaved with 0xFF (non-printable, invalid UTF-8);
    # no leading magic signature matches.
    data = bytes(0x41 + (i % 26) if i % 8 < 3 else 0xFF for i in range(4000))
    p.write_bytes(data)

    card = blob_digest.summarize_blob(p)
    assert card.file_type_guess is None        # no magic signature matched
    assert card.shape_guess is None            # binary verdict - text cascade skipped
    assert card.printable_pct < 70.0
    assert card.utf8_clean is False
    # text slots vanish, exactly like a terminal-magic binary
    assert card.mean_line_length is None
    assert card.top_tokens is None
    assert card.distinct_templates is None


def test_char_class_binary_renders_binary_headline_without_magic() -> None:
    """A magic-less binary card renders the generic 'binary data' headline and a
    bytes slot with NO magic clause (distinguishing it from a signature hit), and
    is never mislabeled as text."""
    card = BlobCard(
        source_name="mystery.bin", byte_size=4096, sampled_line_count=0,
        sample_read_count=1, is_compressed=False, printable_pct=37.5,
        nonprintable_pct=62.5, utf8_clean=False,
        file_type_guess=None, file_type_magic=None, shape_guess=None,
    )
    out = _render(card, source_name="mystery.bin")
    assert "This looks like binary data, not a log." in out
    assert "binary (37.5% printable)" in out
    assert "magic" not in out            # no signature → no magic clause
    assert "freeform text" not in out    # never mislabeled as a text log
    assert "binary, sampled from head" in out


@pytest.mark.parametrize(
    "magic,label",
    [
        (b"%PDF-1.4\n", "PDF document"),
        (b"\x7fELF\x02\x01\x01", "ELF binary"),
        (b"PK\x03\x04stuff", "zip archive"),
    ],
)
def test_terminal_magic_set_identifies(tmp_path, magic, label) -> None:
    p = tmp_path / "f.bin"
    p.write_bytes(magic + bytes(range(256)) * 16)

    card = blob_digest.summarize_blob(p)
    assert card.file_type_guess == label
    assert card.shape_guess is None
    assert card.mean_line_length is None


def test_container_gzip_decompresses_and_profiles_content(tmp_path) -> None:
    """gzip is a CONTAINER, not terminal - decompress the prefix and
    profile the content shape underneath, label as compressed."""
    p = tmp_path / "data.log.gz"
    with gzip.open(p, "wt", encoding="utf-8") as fh:
        for i in range(1000):
            fh.write(f'{{"event": "login", "user": "u{i}"}}\n')

    card = blob_digest.summarize_blob(p)
    assert card.is_compressed is True
    assert card.shape_guess == "JSON"
    # Terminal magic is NOT set - gzip is a container, not a final answer.
    assert card.file_type_guess is None
    # byte_size is the on-disk size (compressed), NOT the decompressed total.
    on_disk = p.stat().st_size
    assert card.byte_size == on_disk


def test_container_bz2_decompresses_and_profiles_content(tmp_path) -> None:
    """bzip2 is a CONTAINER - decompress the prefix via stdlib bz2 and
    profile the content shape underneath."""
    import bz2 as bz2_mod
    p = tmp_path / "data.log.bz2"
    with bz2_mod.open(p, "wt", encoding="utf-8") as fh:
        for i in range(1000):
            fh.write(f'{{"event": "login", "user": "u{i}"}}\n')

    card = blob_digest.summarize_blob(p)
    assert card.is_compressed is True
    assert card.shape_guess == "JSON"
    assert card.file_type_guess is None
    assert card.byte_size == p.stat().st_size


def test_container_xz_decompresses_and_profiles_content(tmp_path) -> None:
    """xz is a CONTAINER - decompress the prefix via stdlib lzma and
    profile the content shape underneath."""
    import lzma as lzma_mod
    p = tmp_path / "data.log.xz"
    with lzma_mod.open(p, "wt", encoding="utf-8") as fh:
        for i in range(1000):
            fh.write(f'{{"event": "login", "user": "u{i}"}}\n')

    card = blob_digest.summarize_blob(p)
    assert card.is_compressed is True
    assert card.shape_guess == "JSON"
    assert card.file_type_guess is None
    assert card.byte_size == p.stat().st_size


def test_misnamed_xz_routes_by_magic_not_suffix(tmp_path) -> None:
    """An xz-compressed file written with a non-.xz suffix (e.g. mystery.log)
    is identified by magic and decompressed via the correct opener - proves
    the magic table actually drives routing rather than being ornamental.

    Without this, only correctly-suffixed containers would work, and the
    bz2/xz magic-table entries would be vestigial."""
    import lzma as lzma_mod
    p = tmp_path / "mystery.log"
    with lzma_mod.open(p, "wt", encoding="utf-8") as fh:
        for i in range(1000):
            fh.write(f'{{"event": "login", "user": "u{i}"}}\n')

    card = blob_digest.summarize_blob(p)
    # Magic ID detected xz via "\xfd7zXZ\x00"; opener routed via lzma.open.
    assert card.is_compressed is True
    assert card.shape_guess == "JSON"
    assert card.file_type_guess is None


def test_misnamed_bz2_routes_by_magic_not_suffix(tmp_path) -> None:
    """A bzip2-compressed file with a non-.bz2 suffix is identified by
    magic ("BZh") and decompressed via the correct opener."""
    import bz2 as bz2_mod
    p = tmp_path / "unknown.dat"
    with bz2_mod.open(p, "wt", encoding="utf-8") as fh:
        for i in range(1000):
            fh.write(f'{{"event": "login", "user": "u{i}"}}\n')

    card = blob_digest.summarize_blob(p)
    assert card.is_compressed is True
    assert card.shape_guess == "JSON"
    assert card.file_type_guess is None


# ─── Shape cascade ──────────────────────────────────────────────────────────


def test_shape_cascade_json(tmp_path) -> None:
    p = tmp_path / "j.log"
    with p.open("w") as fh:
        for i in range(500):
            fh.write(f'{{"k": {i}, "v": "x"}}\n')

    card = blob_digest.summarize_blob(p)
    assert card.shape_guess == "JSON"


def test_shape_cascade_csv_recognized_from_body_not_header(tmp_path) -> None:
    """A CSV-like single header line with non-CSV body must NOT be
    mis-classified as CSV. The cascade prefers body (seek) lines."""
    p = tmp_path / "fake.csv"
    # Single comma-rich header followed by a large freeform body.
    header = "a,b,c,d,e,f,g,h\n"
    body_line = "this is a freeform line with no commas in it\n"
    # Large enough to trigger seeks (above _SEEK_MIN_SIZE).
    with p.open("w") as fh:
        fh.write(header)
        for _ in range(20_000):
            fh.write(body_line)

    card = blob_digest.summarize_blob(p)
    assert card.shape_guess != "CSV"
    # Probably freeform; at least, the comma count test must fail.
    assert "CSV" not in (card.shape_guess or "")


def test_shape_cascade_tsv_recognized_from_body(tmp_path) -> None:
    p = tmp_path / "data.tsv"
    with p.open("w") as fh:
        # Body lines: 6 tabs = 7 columns each.
        for i in range(2000):
            fh.write("\t".join(["x"] * 7) + f"\t{i}\n")

    card = blob_digest.summarize_blob(p)
    assert card.shape_guess is not None
    assert "TSV" in card.shape_guess
    assert "~" in card.shape_guess and "columns" in card.shape_guess


def test_shape_cascade_html(tmp_path) -> None:
    p = tmp_path / "page.html"
    with p.open("w") as fh:
        for _ in range(500):
            fh.write("<div><span>some content</span></div>\n")

    card = blob_digest.summarize_blob(p)
    assert card.shape_guess == "HTML/XML"


def test_shape_cascade_key_value(tmp_path) -> None:
    p = tmp_path / "kv.log"
    with p.open("w") as fh:
        for i in range(500):
            fh.write(f"key1=val{i} key2=alpha key3=beta key4=gamma\n")

    card = blob_digest.summarize_blob(p)
    assert card.shape_guess == "key-value text"


def test_shape_cascade_freeform(tmp_path) -> None:
    p = tmp_path / "free.log"
    with p.open("w") as fh:
        for i in range(1000):
            fh.write(f"plain prose sentence number {i} with no structure.\n")

    card = blob_digest.summarize_blob(p)
    assert card.shape_guess == "freeform text"


# ─── Shape cascade: BATCH 5a over-claim tightening ──────────────────────────
# Synthetic shapes only (NO real Apple-log content); RFC 5737 / placeholders.


def test_shape_cascade_apple_space_ts_is_freeform(tmp_path) -> None:
    """A timestamp-led install-shaped line (SPACE ts, mid-line `prog[pid]: subsys:`)
    is a false positive for key-value - it must fall to the freeform floor."""
    p = tmp_path / "install.log"
    with p.open("w") as fh:
        for i in range(500):
            fh.write(f"2024-06-28 12:00:00-07:00 host installd[123]: PackageKit: step {i}\n")
    card = blob_digest.summarize_blob(p)
    assert card.shape_guess == "freeform text"


def test_shape_cascade_apple_iso_t_ts_is_freeform(tmp_path) -> None:
    """The ISO `T` timestamp form rejects too - a digit-led key never matches."""
    p = tmp_path / "keybagd.log"
    with p.open("w") as fh:
        for i in range(500):
            fh.write(f"2024-06-28T12:00:00-07:00 host prog[7]: Subsys: event {i}\n")
    card = blob_digest.summarize_blob(p)
    assert card.shape_guess == "freeform text"


def test_shape_cascade_repeated_program_prefix_is_freeform(tmp_path) -> None:
    """Single program-prefix log lines (`kernel: prose` / `sshd: prose`) carry ONE
    bareword colon pair each → below the strict ≥2 density → freeform, not
    key-value. GUARDS the accepted tradeoff (a single-pair colon config reads
    freeform) against a future broadening of the `:` form (the prompt's explicit
    "do NOT broaden the colon form to recover it"). The discriminator
    - a ≥2-colon line whose colons are NON-bareword - is pinned by the apple
    space/T-timestamp tests above (which a bareword-blind colon check would
    mis-claim as key-value)."""
    p = tmp_path / "messages.log"
    with p.open("w") as fh:
        for i in range(250):
            fh.write(f"kernel: ring buffer note {i}\n")
            fh.write(f"sshd: accepted connection {i}\n")
    card = blob_digest.summarize_blob(p)
    assert card.shape_guess == "freeform text"


def test_shape_cascade_midline_angle_token_not_html(tmp_path) -> None:
    """A mid-line `<private>` token (NOT line-leading) must not be claimed HTML/XML."""
    p = tmp_path / "wifi.log"
    with p.open("w") as fh:
        for i in range(500):
            fh.write(f"2024-06-28 12:00:00 host wifi: client <private> assoc {i}\n")
    card = blob_digest.summarize_blob(p)
    assert card.shape_guess == "freeform text"
    assert card.shape_guess != "HTML/XML"


def test_shape_cascade_html_leading_tag_variants(tmp_path) -> None:
    """The tightened HTML test still accepts markup whose lines lead with
    `<!DOCTYPE` / `<tag` / `</tag` (the `<!`, `<`, `</` arms of the char class)."""
    p = tmp_path / "doc.html"
    variants = ["<!DOCTYPE html>", "<html>", "<body>", "</body>", "</html>"]
    with p.open("w") as fh:
        for i in range(500):
            fh.write(variants[i % len(variants)] + "\n")
    card = blob_digest.summarize_blob(p)
    assert card.shape_guess == "HTML/XML"


def test_shape_cascade_colon_config_is_key_value(tmp_path) -> None:
    """A ≥2 bareword colon-pair config block → key-value text (the strict `:` form;
    RFC 5737 placeholder host value)."""
    p = tmp_path / "cfg.log"
    with p.open("w") as fh:
        for i in range(500):
            fh.write(f"host: 192.0.2.{i % 250} port: 443 proto: tcp\n")
    card = blob_digest.summarize_blob(p)
    assert card.shape_guess == "key-value text"


def test_shape_cascade_colon_keys_with_dots_dashes_ignore_non_bareword_colons(tmp_path) -> None:
    """The strict colon form accepts dotted/dashed bareword keys (`status.code`,
    `retry-after`) and counts ONLY bareword colon-SPACE pairs - a `:8080` port colon
    (no following space) and a `://` scheme colon never count. Three real pairs
    (url / status.code / retry-after) clear the ≥2 density → key-value text."""
    p = tmp_path / "kv_edge.log"
    with p.open("w") as fh:
        for i in range(500):
            fh.write(f"url: http://example.test:8080/p{i} status.code: 200 retry-after: 5\n")
    card = blob_digest.summarize_blob(p)
    assert card.shape_guess == "key-value text"


def test_shape_cascade_logfmt_is_key_value(tmp_path) -> None:
    """A leading `key=value` logfmt block → key-value text (the `=` form)."""
    p = tmp_path / "logfmt.log"
    with p.open("w") as fh:
        for i in range(500):
            fh.write(f"level=info msg=started id={i} dur=5ms\n")
    card = blob_digest.summarize_blob(p)
    assert card.shape_guess == "key-value text"


# ─── Char-class / UTF-8 honesty ────────────────────────────────────────────


def test_char_class_flags_nonprintable_in_sample(tmp_path) -> None:
    """Char-class is computed over the sample bytes BEFORE decode - a binary-
    heavy sample produces a low printable fraction even without a magic hit."""
    p = tmp_path / "binary.bin"
    # No known magic; just a mass of non-printable bytes.
    p.write_bytes(b"\x01\x02\x03\xfe\xfd\xfc" * 1024)

    card = blob_digest.summarize_blob(p)
    assert card.printable_pct < 20.0
    assert card.nonprintable_pct > 80.0
    assert math.isclose(
        card.printable_pct + card.nonprintable_pct, 100.0, abs_tol=0.01
    )


def test_utf8_clean_true_on_ascii(tmp_path) -> None:
    p = tmp_path / "ascii.log"
    p.write_text("hello world\n" * 100)
    card = blob_digest.summarize_blob(p)
    assert card.utf8_clean is True


def test_utf8_clean_false_on_latin1_high_bytes(tmp_path) -> None:
    """Bytes that fail strict UTF-8 decode set utf8_clean=False; the
    renderer's Bytes row drops the 'UTF-8 clean' tail."""
    p = tmp_path / "latin1.log"
    # 0xc0 alone is an invalid UTF-8 start; 0xa3 (£) without lead is also bad.
    p.write_bytes(b"hello \xc0\xa3 world\n" * 200)
    card = blob_digest.summarize_blob(p)
    assert card.utf8_clean is False

    out = _render(card)
    assert "UTF-8 clean" not in out
    assert "% printable" in out


def test_utf8_clean_true_renders_clean_tail(tmp_path) -> None:
    p = tmp_path / "clean.log"
    p.write_text("alpha beta gamma\n" * 200)
    card = blob_digest.summarize_blob(p)
    assert card.utf8_clean is True
    out = _render(card)
    assert "UTF-8 clean" in out


# ─── Line-length p95 ────────────────────────────────────────────────────────


def test_line_length_shape_returns_p95() -> None:
    """The lifted helper grows a 6-tuple with p95 inserted between median
    and max. Card field line_length_p95 is populated from it."""
    lengths = list(range(1, 101))  # 1..100
    mean, median, p95, max_len, stdev, shape = blob_digest._line_length_shape(
        lengths
    )
    assert mean == pytest.approx(50.5)
    assert median == 50.5
    assert max_len == 100
    # 95th percentile of 1..100 with quantiles(n=20)[18] ≈ 95 or 96.
    assert 90 <= p95 <= 100
    assert shape in ("uniform", "varied")


def test_p95_never_exceeds_max_on_tiny_sample() -> None:
    """REGRESSION: statistics.quantiles(n=20) interpolates exclusively and
    EXTRAPOLATES past max on small samples - lengths=[1, 100] yielded
    p95=184 with max=100, which is nonsense (p95 must be an order
    statistic from the sample). The fix is to fall back to max when the
    sample is smaller than 20 lines, plus a defensive clamp."""
    mean, median, p95, max_len, stdev, shape = blob_digest._line_length_shape(
        [1, 100]
    )
    assert max_len == 100
    assert p95 == 100, f"p95 must not exceed max; got p95={p95}, max={max_len}"


@pytest.mark.parametrize(
    "lengths",
    [
        [10],                       # single line
        [10, 1000],                 # 2-line extreme spread
        [1, 2, 3, 4, 5],            # tiny ascending
        [100, 100, 100, 100, 100],  # tiny uniform
        [1] * 19,                   # just below the n=20 threshold
        list(range(1, 21)),         # exactly at threshold
        list(range(1, 1001)),       # plenty of data
    ],
)
def test_p95_le_max_invariant(lengths) -> None:
    """Invariant: p95 <= max for any non-empty sample, big or small."""
    _, _, p95, max_len, _, _ = blob_digest._line_length_shape(lengths)
    assert p95 <= max_len, (
        f"p95={p95} exceeded max={max_len} for lengths={lengths!r}"
    )


# ─── drain3 quarantine + meaninglessness floor ──────────────────────────────


def test_quarantine_drain3_dormant_vanishes_templates(monkeypatch, tmp_path) -> None:
    """_BLOB_DRAIN3_ENABLED=False → no template fields, card otherwise OK."""
    monkeypatch.setattr(blob_digest, "_BLOB_DRAIN3_ENABLED", False)

    p = tmp_path / "rep.log"
    p.write_text("host svc: event N\n" * 500)
    card = blob_digest.summarize_blob(p)
    assert card.distinct_templates is None
    assert card.top_template_coverage_pct is None
    assert card.top_template_n is None
    assert card.singleton_template_count is None
    # Card otherwise renders fine. Lowercase labels under flat grammar.
    out = _render(card)
    assert "templates:" not in out
    assert "shape:" in out


def test_meaninglessness_floor_vanishes_templates_on_freeform(tmp_path) -> None:
    """Near-1:1 templates/lines → suppress Templates (better silent than
    vacuous '~480 distinct over 500 lines')."""
    p = tmp_path / "free.log"
    with p.open("w") as fh:
        # Each line structurally distinct.
        for i in range(500):
            fh.write(
                f"line{i:04d} verb_{i % 7} adverb_{i % 11} "
                f"noun_{i % 13} {chr(65 + i % 26)}\n"
            )

    card = blob_digest.summarize_blob(p)
    # On a deliberately-freeform input the floor should hit.
    assert card.distinct_templates is None or (
        card.distinct_templates is not None
        and card.distinct_templates / max(card.sampled_line_count, 1)
        < blob_digest._TEMPLATE_RATIO_FLOOR
    )


# ─── Renderer: no banner, no Lines: / Data found: rows in flat grammar ─────
#
# The flat grammar has no banner: blob uses its identity-line provenance and
# never renders Lines: / Records: / Data found: rows.


def test_blob_card_has_no_banner_lines_or_data_found_rows() -> None:
    """The flat blob card has no banner rows at all."""
    for card in (_binary_blob_card(), _text_blob_card()):
        out = _render(card)
        assert "Lines:" not in out
        assert "Records:" not in out
        assert "Data found:" not in out
        assert "Threat Hunt" not in out


# ─── Renderer: flat-grammar vanish-don't-dash ───────────────────────────────


def test_render_binary_vanishes_text_slots() -> None:
    """Terminal binary magic → only the `bytes:` row remains; shape /
    lines / tokens / templates are absent (vanish-don't-dash)."""
    out = _render(_binary_blob_card())
    assert "bytes:" in out
    assert "PNG image" in out
    assert "binary" in out
    assert "shape:" not in out
    assert "lines:" not in out
    assert "tokens:" not in out
    assert "templates:" not in out


def test_render_text_blob_shows_all_text_slots() -> None:
    card = _text_blob_card()
    out = _render(card)
    for label in ("bytes:", "shape:", "lines:", "tokens:", "templates:"):
        assert label in out
    assert "[literal]" in out


def test_render_text_blob_with_no_templates_vanishes_only_that_slot() -> None:
    card = _text_blob_card(has_templates=False)
    out = _render(card)
    assert "shape:" in out
    assert "lines:" in out
    assert "tokens:" in out
    assert "templates:" not in out


def test_render_no_footer_no_header_rule_no_trailing_sep() -> None:
    """Flat grammar: no `── digest · blob ─` header, no `inner_sep`, no
    `No parser claims…` footer, no trailing `_SEP`."""
    for card in (_binary_blob_card(), _text_blob_card()):
        out = _render(card)
        assert "── digest" not in out
        assert "No parser claims" not in out
        assert "─" not in out


def test_render_headline_labels_guess(tmp_path) -> None:
    """Headline always labels itself as a guess. Under the flat grammar
    the headline is flush-left (no leading indent)."""
    text_out = _render(_text_blob_card(shape_guess="JSON"))
    assert "looks like JSON" in text_out
    # Flush-left - no two-space indent prefix.
    headline = next(ln for ln in text_out.splitlines() if "looks like JSON" in ln)
    assert not headline.startswith(" ")

    bin_out = _render(_binary_blob_card())
    assert "looks like a PNG image, not a log" in bin_out


def test_render_provenance_line_plain_text() -> None:
    """Plain-text provenance reports the sampled count and reads."""
    out = _render(_text_blob_card())
    assert "sampled" in out
    assert "lines across" in out
    assert "reads" in out


def test_render_provenance_line_compressed() -> None:
    """Compressed provenance labels 'compressed' and 'sampled from head'."""
    base = _text_blob_card()
    compressed = BlobCard(**{**base.__dict__, "is_compressed": True})
    out = _render(compressed)
    assert "compressed" in out
    assert "from head" in out


def test_render_provenance_line_terminal_binary() -> None:
    """Terminal-binary provenance: 'binary, sampled from head'. Does NOT
    count lines (a binary has no line concept)."""
    out = _render(_binary_blob_card())
    # Identity line 1 = source name; line 2 = provenance.
    lines = out.splitlines()
    assert "binary, sampled from head" in lines[1]
    assert "lines across" not in lines[1]
    assert "reads" not in lines[1]


def test_render_identity_line_is_source_name_flush_left() -> None:
    """Identity line 1 = card.source_name, flush-left, no banner above."""
    out = _render(_text_blob_card(), source_name="mystery.txt")
    assert out.splitlines()[0] == "mystery.txt"


def test_render_blob_strips_control_bytes_from_json_shape_values() -> None:
    card = _text_blob_card(
        shape_guess="JSON\x1b[31m\x00\x07\r\x9b",
        has_tokens=False,
    )
    card.json_field_names = ["ts\x1b[31m\x00\x07\r\x9b", "uid"]
    card.line_length_shape = "varied\x1b[31m\x00\x07\r\x9b"

    out = _render(card, source_name="ssh\x1b[31m\x00\x07\r\x9b.log")

    _assert_no_data_controls(out)
    assert out.splitlines()[0] == "ssh[31m.log"
    assert "looks like JSON[31m" in out
    assert "fields:" in out and "ts[31m" in out
    assert "varied[31m" in out


def test_render_blob_strips_control_bytes_from_top_tokens() -> None:
    card = _text_blob_card(
        shape_guess="key-value",
        has_tokens=True,
    )
    card.top_tokens = [("level\x1b[31m\x00\x07\r\x9b", 10), ("msg", 8)]

    out = _render(card)

    _assert_no_data_controls(out)
    assert '"level[31m"' in out


def test_round_2sf_helper_is_gone() -> None:
    """_round_2sf existed only for the 'Lines: sampled ~N' rendering that
    earlier work removed. Pin its removal so it does not creep back."""
    assert not hasattr(text_module, "_round_2sf")


# ─── JSON blob: `fields:` (names) replaces `tokens:` (record dump) ──────────
#
# Glob-digest of a Zeek directory routes every non-claimed NDJSON log
# (http, ssl, ssh, dhcp, ntp, weird, …) to the blob floor. A raw tokens
# row would dump raw records (and sometimes mid-value garbage from
# whitespace splits inside string fields). The `fields:` line lists
# top-level JSON KEY NAMES only - structural description, no values.

def _write_json_lines(path, lines: list[str]) -> None:
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")


def test_json_blob_renders_fields_row_not_tokens_row(tmp_path) -> None:
    """JSON blob: fields: line present, tokens: line absent. Union of
    keys across rows preserves first-seen order and catches an optional
    key that only appears on one row."""
    p = tmp_path / "ssh.log"
    _write_json_lines(p, [
        '{"ts": 1779750000.0, "uid": "C001", "id.orig_h": "192.0.2.10"}',
        '{"ts": 1779750001.0, "uid": "C002", "id.orig_h": "192.0.2.11",'
        ' "auth_attempts": 3}',
    ] * 3)
    card = blob_digest.summarize_blob(p)
    assert card.shape_guess == "JSON"
    assert card.json_field_names == [
        "ts", "uid", "id.orig_h", "auth_attempts",
    ]
    out = _render(card, source_name="ssh.log")
    assert "fields:" in out
    assert "tokens:" not in out
    fields_line = next(l for l in out.splitlines() if l.startswith("fields:"))
    # Names emitted in first-seen order, comma-separated.
    assert "ts, uid, id.orig_h, auth_attempts" in fields_line


def test_json_arrays_and_scalars_fall_back_to_tokens_row(tmp_path) -> None:
    """Top-level JSON arrays / scalars / mixed have no object keys to
    list; helper returns None; renderer falls back to the existing
    `tokens:` row."""
    p = tmp_path / "weird.log"
    _write_json_lines(p, ['[1, 2, 3]', '42', '"hello"'] * 5)
    card = blob_digest.summarize_blob(p)
    # Helper-level: None
    assert blob_digest._json_field_names([
        '[1, 2, 3]', '42', '"hello"',
    ]) is None
    assert card.json_field_names is None
    out = _render(card, source_name="weird.log")
    # The exact shape-guess is JSON or freeform depending on the cascade;
    # what matters is no `fields:` row when names is None.
    assert "fields:" not in out


def _json_keys_line(n: int) -> str:
    """One JSON record with N generic placeholder keys."""
    pairs = ", ".join(f'"field_{i:02d}": {i}' for i in range(n))
    return "{" + pairs + "}"


def test_fields_row_clamps_to_two_lines_with_correct_remainder(tmp_path) -> None:
    """30 generic keys → exactly two lines, second hang-indented to the
    value column, ends with `… +N more`, and N equals total minus rendered."""
    p = tmp_path / "wide.log"
    _write_json_lines(p, [_json_keys_line(30)] * 5)
    card = blob_digest.summarize_blob(p)
    assert card.json_field_names is not None
    assert len(card.json_field_names) == 30

    out = _render(card, source_name="wide.log")
    lines = out.splitlines()
    fields_idx = next(i for i, l in enumerate(lines) if l.startswith("fields:"))
    line1 = lines[fields_idx]
    line2 = lines[fields_idx + 1]

    # Compute the actual label column from a single-line slot rendered
    # alongside this card - the column is `max(label_w) + 2`, where the
    # blob card's longest label is `templates`, not `fields`. Slicing by
    # `len("fields: ")` would land mid-padding and corrupt the first name.
    bytes_line = next(l for l in lines if l.startswith("bytes:"))
    label_col = len(bytes_line) - len(bytes_line.lstrip()) + len("bytes:")
    # Actually compute from the leading-whitespace gap after the `bytes:`
    # prefix: `bytes:` is 6 chars, value column starts at `label_col`.
    label_col = bytes_line.index(bytes_line.lstrip()[len("bytes: ".rstrip()):][0:1] or "t")
    # Simpler: column where the value starts is the position of the first
    # non-space char AFTER the `:` on a single-line slot.
    after_colon = bytes_line.find(":") + 1
    while after_colon < len(bytes_line) and bytes_line[after_colon] == " ":
        after_colon += 1
    label_col = after_colon

    # Line 2 hang-indents to label_col.
    assert line2.startswith(" " * label_col)
    # Line 2 ends with the truncation suffix and an accurate N.
    import re
    m = re.search(r"… \+(\d+) more$", line2)
    assert m is not None, f"expected `… +N more` suffix; got {line2!r}"
    n_more = int(m.group(1))

    # Count the field names that actually rendered across both lines.
    rendered_text = (
        line1[label_col:]
        + ", "
        + line2[label_col:].rsplit("… +", 1)[0].rstrip(", ")
    )
    rendered_names = [n for n in rendered_text.split(", ") if n.startswith("field_")]
    assert len(rendered_names) + n_more == 30
    # Each rendered name appears whole - no mid-name break.
    for name in rendered_names:
        assert name.startswith("field_") and len(name) == len("field_NN")


def test_fields_row_renders_single_line_no_suffix_when_narrow(tmp_path) -> None:
    """Short list fits one line → one line, no suffix."""
    p = tmp_path / "narrow.log"
    _write_json_lines(p, [_json_keys_line(4)] * 5)
    card = blob_digest.summarize_blob(p)
    out = _render(card, source_name="narrow.log")
    fields_lines = [
        i for i, l in enumerate(out.splitlines()) if l.startswith("fields:")
    ]
    assert len(fields_lines) == 1
    line = out.splitlines()[fields_lines[0]]
    assert "more" not in line
    assert "…" not in line


def test_fields_row_wrap_never_splits_a_name(tmp_path) -> None:
    """Wrap respects part boundaries - every field name appears whole on
    exactly one rendered line."""
    p = tmp_path / "mixed.log"
    # Mix short and longer names; enough to wrap.
    names = (
        ["ts", "uid", "id.orig_h", "id.resp_h"]
        + [f"long_field_name_{i:02d}" for i in range(20)]
    )
    record = "{" + ", ".join(f'"{n}": {i}' for i, n in enumerate(names)) + "}"
    _write_json_lines(p, [record] * 3)
    card = blob_digest.summarize_blob(p)
    out = _render(card, source_name="mixed.log")
    lines = out.splitlines()
    fields_idx = next(i for i, l in enumerate(lines) if l.startswith("fields:"))
    # Concatenate the rendered lines and check every original name
    # appears either whole somewhere in the rendered text OR is one of
    # the suppressed-by-suffix names. The strong check: NO substring of
    # any rendered line splits a name (a partial like "long_field_name_0"
    # without its trailing digit would indicate a mid-name break).
    rendered = lines[fields_idx] + " " + (lines[fields_idx + 1]
                                          if fields_idx + 1 < len(lines) else "")
    # For each name, if it appears at all, it appears in full.
    for name in names:
        # Search for the prefix and assert the next char is not alnum/_
        # (so we'd catch a mid-name break like "long_field_name_0" cut
        # off before its decade digit).
        import re
        for m in re.finditer(re.escape(name) + r"(\w)", rendered):
            # An extension of `name` by a word char is only OK if the
            # extended-name is itself an emitted name (e.g. "ts" prefix
            # of "ts_extra"). Names list has no such overlap, so flag it.
            extended = name + m.group(1)
            assert extended in names, (
                f"field name appears to be split: {name!r} extended by "
                f"{m.group(1)!r} in rendered output"
            )


# ─── Cross-helper regression: schema-card values stay UN-clamped ────────────

def test_schema_card_long_value_renders_full_no_truncation() -> None:
    """The blob two-line clamp must NOT leak into schema-card rendering.

    A long densest-tuple flow on a conn DigestCard must render in full
    (no `… +N more`, no truncation). _render_label_value_block stays the
    shared label-aligned helper for schema cards; the wrap lives only
    in render_blob via _wrap_blob_slot_value.
    """
    from datetime import datetime, timezone
    from sigwood.common.finding import DigestCard, DigestSlot
    long_flow = (
        "192.0.2.10:51234 → 198.51.100.20:443 (very-long-tag-padding-out-"
        "to-exceed-the-eighty-col-line-frame-on-purpose)"
    )
    assert len(long_flow) > 80
    cliff = DigestSlot(
        label="densest-tuple", statistic="cliff",
        cells=[long_flow, "482", "3.7x"],
        entity=long_flow, magnitude=482.0, ratio=3.7,
    )
    now = datetime(2026, 6, 14, tzinfo=timezone.utc)
    card = DigestCard(
        schema="conn",
        source_name="conn.log",
        data_window=(now, now),
        record_count=1000,
        histogram_counts=[1, 2, 3],
        histogram_unit="hr",
        histogram_peak=3,
        zone1_extras=[("hosts", "5")],
        insights=[],
        fields=[cliff],
        data_size_bytes=0,
    )
    stream = io.StringIO()
    TextHandler(stream=stream).render_digest(card)
    out = stream.getvalue()
    # Full flow string survives in the rendered output, no truncation suffix.
    assert long_flow in out
    assert "… +" not in out
    assert "more" not in out.split(long_flow)[1]


# ─── Runner fold + CLI invariants ───────────────────────────────────────────


def test_run_digest_blob_no_longer_exists() -> None:
    """Blob has no standalone runner - it is handled inside run_digest's
    terminal branch."""
    assert not hasattr(runner, "_run_digest_blob")


def test_cli_digest_blob_token_is_rejected(monkeypatch) -> None:
    """There is no `digest blob PATH` token - schema cannot be selected from CLI."""
    monkeypatch.setattr(cli.cfg, "load", lambda _path: {"sigwood": {}})
    # Token "blob" treated as a path; the path doesn't exist → errored=1.
    rc = cli._main(["digest", "blob"])
    assert rc == 1


def test_cli_sniff_floor_routes_to_blob_path(tmp_path, monkeypatch) -> None:
    """Unrecognized text positional → schema=blob via sniff floor; sets
    blob_path on the runner kwargs."""
    captured: dict[str, Any] = {}

    def _fake(**kwargs: Any) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(runner, "run_digest", _fake)
    monkeypatch.setattr(cli.cfg, "load", lambda _path: {"sigwood": {}})

    f = tmp_path / "mystery.txt"
    f.write_text("hello world\nlorem ipsum\n")
    cli._main(["digest", str(f)])
    assert captured.get("schema") == "blob"
    assert captured.get("blob_path") == f
    assert captured.get("zeek_dir") is None
    assert captured.get("pihole_dir") is None
    assert captured.get("syslog_dir") is None
    assert captured.get("cloudtrail_dir") is None


def test_cli_blob_path_not_advertised(monkeypatch) -> None:
    """--blob-path is not advertised - operator cannot set blob_path
    directly. Sniff routing is the only producer."""
    monkeypatch.setattr(cli.cfg, "load", lambda _path: {"sigwood": {}})
    with pytest.raises(ValueError, match=r"unknown flag --blob-path"):
        cli._main(["digest", "--blob-path=/tmp/x"])


def test_run_digest_blob_requires_blob_path() -> None:
    with pytest.raises(ValueError, match=r"PATH not provided"):
        runner.run_digest(config={"sigwood": {}}, schema="blob")


def test_run_digest_blob_rejects_directory(tmp_path) -> None:
    """The blob terminal branch requires a single file; the sniff path
    only ever produces single files. A directory is a programmer error."""
    with pytest.raises(ValueError, match=r"not a file"):
        runner.run_digest(
            config={"sigwood": {}}, schema="blob", blob_path=tmp_path,
        )


def test_run_digest_blob_path_only_valid_for_blob_schema(tmp_path) -> None:
    """blob_path passed with a schema-card schema is rejected."""
    with pytest.raises(
        ValueError,
        match=r"blob_path is only valid for the blob schema",
    ):
        runner.run_digest(
            config={"sigwood": {}}, schema="conn",
            blob_path=tmp_path / "input.txt",
        )


# ─── Recognized-but-empty seam ──────────────────────────────────────────────


def test_digest_empty_is_not_value_error_subclass() -> None:
    """DigestEmpty is a control signal, not an error. Real per-path
    failures (corrupt gzip, parser errors) are ValueErrors; DigestEmpty
    must not be consumed by the ValueError arm."""
    assert not issubclass(DigestEmpty, ValueError)


def test_digest_empty_carries_basename_and_schema() -> None:
    exc = DigestEmpty(basename="conn.log", schema="conn")
    assert exc.basename == "conn.log"
    assert exc.schema == "conn"
    assert "conn.log" in str(exc)
    assert "conn" in str(exc)


def test_run_digest_raises_digest_empty_on_empty_frame(
    tmp_path, monkeypatch,
) -> None:
    """Frame-based check: an empty frame returned by the loader raises
    DigestEmpty, not a zero-row schema card."""
    from sigwood.common import loader

    fake = loader.LoadResult(
        logs={"conn*.log*": pd.DataFrame()},
        record_counts={},
        data_window=None,
        warnings=[],
        data_size_bytes=0,
    )
    monkeypatch.setattr(loader, "load_required_logs", lambda *a, **k: fake)

    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    with pytest.raises(DigestEmpty) as exc_info:
        runner.run_digest(
            config={"sigwood": {}}, schema="conn", zeek_dir=zeek_dir,
        )
    assert exc_info.value.basename == "zeek"
    assert exc_info.value.schema == "conn"


def test_run_digest_raises_digest_empty_when_frame_missing(
    tmp_path, monkeypatch,
) -> None:
    """`frame is None` (load_result.logs missing the key) is also an empty
    state - same DigestEmpty raise."""
    from sigwood.common import loader

    fake = loader.LoadResult(
        logs={},  # pattern key missing entirely
        record_counts={},
        data_window=None,
        warnings=[],
        data_size_bytes=0,
    )
    monkeypatch.setattr(loader, "load_required_logs", lambda *a, **k: fake)

    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    with pytest.raises(DigestEmpty):
        runner.run_digest(
            config={"sigwood": {}}, schema="conn", zeek_dir=zeek_dir,
        )


def test_cli_fanout_recognized_empty_narrates_and_exits_zero(
    tmp_path, monkeypatch, capsys,
) -> None:
    """Fan-out: DigestEmpty raised from run_digest → narrated to stderr,
    no card rendered, exit 0."""
    monkeypatch.setattr(cli.cfg, "load", lambda _path: {"sigwood": {}})

    def _empty(**kwargs):
        raise DigestEmpty(basename="conn.log", schema="conn")

    monkeypatch.setattr(runner, "run_digest", _empty)

    f = tmp_path / "conn.log"
    f.write_text("#fields\tts\tsrc\n")
    # Force sniff to classify as conn.
    import sigwood.common.loader as loader_mod
    monkeypatch.setattr(
        loader_mod,
        "sniff_format_detailed",
        lambda p: loader_mod.SniffResult(
            state="classified", schema="conn", origin="zeek",
        ),
    )

    rc = cli._main(["digest", str(f)])
    err = capsys.readouterr().err
    assert "recognized as conn, no parseable records" in err
    assert rc == 0


def test_cli_bare_config_recognized_empty_narrates_and_exits_zero(
    tmp_path, monkeypatch, capsys,
) -> None:
    """Bare-config (no positional): DigestEmpty caught at the entry point,
    narrated, exit 0 - no traceback."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    monkeypatch.setattr(
        cli.cfg, "load",
        lambda _path: {"sigwood": {"zeek_dir": str(zeek_dir)}},
    )

    def _empty(**kwargs):
        raise DigestEmpty(basename=zeek_dir.name, schema="conn")

    monkeypatch.setattr(runner, "run_digest", _empty)

    rc = cli._main(["digest"])
    err = capsys.readouterr().err
    assert "recognized as conn, no parseable records" in err
    assert rc == 0


def test_cli_fanout_corrupt_gzip_exits_clean(tmp_path, monkeypatch, capsys) -> None:
    """REGRESSION: a corrupt .gz raises gzip.BadGzipFile (OSError subclass)
    inside sniff_format_detailed BEFORE run_digest is called. The fan-out
    arm must catch it as a per-path failure - no traceback, no leak to
    main(). Exit 1 because rendered=0 and errored=1."""
    monkeypatch.setattr(cli.cfg, "load", lambda _path: {"sigwood": {}})

    bad = tmp_path / "broken.gz"
    bad.write_bytes(b"not a real gzip stream, just text")

    rc = cli._main(["digest", str(bad)])
    err = capsys.readouterr().err
    assert rc == 1
    # Per-path message format: "digest: <name>: <reason>".
    assert "broken.gz" in err
    # And no Python traceback markers.
    assert "Traceback" not in err


def test_cli_fanout_permission_denied_lone_path_exits_clean(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    """A denied digest file exits 1 with actionable guidance, not raw errno."""
    import sigwood.common.loader as loader_mod

    monkeypatch.setattr(cli.cfg, "load", lambda _path: {"sigwood": {}})
    denied = tmp_path / "pihole.log"
    denied.write_text("unreadable placeholder\n", encoding="utf-8")
    monkeypatch.setattr(
        loader_mod,
        "sniff_format_detailed",
        lambda _path: (_ for _ in ()).throw(PermissionError("synthetic denied")),
    )
    monkeypatch.setattr(
        loader_mod,
        "_permission_denied_message",
        lambda path: (
            f"{path.name}: permission denied - owned loguser:logreaders "
            "(mode 0640); add your user to the 'logreaders' group "
            "(sudo usermod -aG logreaders $USER) and log back in"
        ),
    )

    with pytest.raises(SystemExit) as exc:
        cli.main(["digest", str(denied)])

    err = capsys.readouterr().err
    assert exc.value.code == 1
    assert (
        "sigwood: pihole.log: permission denied - owned "
        "loguser:logreaders (mode 0640)" in err
    )
    assert "[Errno" not in err
    assert "Traceback" not in err


def test_cli_fanout_permission_denied_path_exits_one_and_continues(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    """A denied digest path does not abort rendering of readable siblings."""
    import sigwood.common.loader as loader_mod

    monkeypatch.setattr(cli.cfg, "load", lambda _path: {"sigwood": {}})
    denied = tmp_path / "pihole.log"
    denied.write_text("unreadable placeholder\n", encoding="utf-8")
    readable = tmp_path / "mystery.log"
    readable.write_text("hello world\n", encoding="utf-8")

    def _fake_sniff(path: Path):
        if path == denied:
            raise PermissionError("synthetic denied")
        return loader_mod.SniffResult(
            state="classified", schema="blob", origin=None,
        )

    def _fake_run_digest(**kwargs):
        kwargs["stream"].write("readable card rendered\n")

    monkeypatch.setattr(loader_mod, "sniff_format_detailed", _fake_sniff)
    monkeypatch.setattr(
        loader_mod,
        "_permission_denied_message",
        lambda path: (
            f"{path.name}: permission denied - owned loguser:logreaders "
            "(mode 0640); add your user to the 'logreaders' group "
            "(sudo usermod -aG logreaders $USER) and log back in"
        ),
    )
    monkeypatch.setattr(runner, "run_digest", _fake_run_digest)

    rc = cli._main(["digest", str(denied), str(readable)])

    captured = capsys.readouterr()
    assert rc == 1
    assert "readable card rendered" in captured.out
    assert "sigwood: pihole.log: permission denied" in captured.err
    assert "[Errno" not in captured.err
    assert "Traceback" not in captured.err


def test_cli_bare_config_corrupt_gzip_handled_gracefully(
    tmp_path, monkeypatch, capsys,
) -> None:
    """REGRESSION: a corrupt .gz inside the configured zeek_dir does NOT
    leak as a traceback. The loader skips the bad file with a warning, the
    resulting empty frame raises DigestEmpty, and the bare-config arm
    catches it and narrates cleanly. Exit 0 (file was understood, just
    nothing to read after the skip)."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "conn.log.gz").write_bytes(b"not gzip, just text")

    monkeypatch.setattr(
        cli.cfg, "load",
        lambda _path: {
            "sigwood": {
                "zeek_dir": str(zeek_dir),
                "default_window": "all",
            }
        },
    )

    rc = cli._main(["digest"])
    err = capsys.readouterr().err
    assert rc == 0
    assert "Traceback" not in err
    # The loader surfaces a graceful skip; the recognized-empty seam takes over.
    assert "could not be read" in err or "incomplete or corrupt" in err
    assert "recognized as conn, no parseable records" in err


def test_main_oserror_arm_translates_to_exit_one(monkeypatch, capsys) -> None:
    """Defensive: any OSError that escapes _main() (e.g. an I/O failure that
    no per-path arm catches) MUST be translated to a clean 'sigwood:' exit 1
    by main(), not bubble as a traceback. Pin the arm independently of the
    digest code paths so it stays in place across future refactors."""
    def _raise_os_error(_argv):
        raise OSError("synthetic disk failure for test")

    monkeypatch.setattr(cli, "_main", _raise_os_error)
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["digest", "/nonexistent"])
    assert exit_info.value.code == 1
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert "sigwood:" in err
    assert "synthetic disk failure" in err


def test_cli_fanout_value_error_still_exits_one(tmp_path, monkeypatch, capsys) -> None:
    """A real per-path failure (ValueError) still flows through the
    existing arm - exit 1 when nothing rendered."""
    monkeypatch.setattr(cli.cfg, "load", lambda _path: {"sigwood": {}})

    def _boom(**kwargs):
        raise ValueError("simulated parser failure")

    monkeypatch.setattr(runner, "run_digest", _boom)

    f = tmp_path / "data.log"
    f.write_text("hello world\n")
    import sigwood.common.loader as loader_mod
    monkeypatch.setattr(
        loader_mod,
        "sniff_format_detailed",
        lambda p: loader_mod.SniffResult(
            state="classified", schema="blob", origin=None,
        ),
    )

    rc = cli._main(["digest", str(f)])
    err = capsys.readouterr().err
    assert "simulated parser failure" in err
    assert rc == 1


# ─── End-to-end: run_digest blob terminal branch through the renderer ──────


def test_run_digest_blob_end_to_end_renders_card(tmp_path, capsys) -> None:
    """Programmatic call to run_digest with schema=blob renders a flat
    card to the configured stream (stdout by default)."""
    f = tmp_path / "free.log"
    f.write_text("alpha beta gamma\ndelta epsilon\n" * 200)

    runner.run_digest(
        config={"sigwood": {}}, schema="blob", blob_path=f,
    )
    out = capsys.readouterr().out
    # Flat blob card: identity line 1 = source basename, headline names
    # the best-guess shape, fields block carries the lowercase labels.
    assert out.splitlines()[0] == "free.log"
    assert "Unrecognized source" in out
    assert "bytes:" in out
    # No banner, no header rule, no footer in the flat grammar.
    assert "Threat Hunt" not in out
    assert "── digest" not in out
    assert "No parser claims" not in out


def test_run_digest_blob_dry_run_skips_render(tmp_path, capsys) -> None:
    """Dry-run prints a plan note and returns without sampling or rendering."""
    f = tmp_path / "free.log"
    f.write_text("hello\n")
    runner.run_digest(
        config={"sigwood": {}}, schema="blob", blob_path=f, dry_run=True,
    )
    out = capsys.readouterr().out
    assert "digest  ·  dry run" in out
    assert "schema:" in out and "blob" in out
    assert "── digest · blob" not in out
    assert "No parser claims" not in out
