"""Cross-cutting output voice & format consistency invariants.

Locks the cross-cutting invariants the per-surface tests don't individually
guard: single ``sigwood:`` prefixing (no double-prefix), the usage pointer
appearing ONLY for argument errors, the per-format timestamp contracts (json
always ISO-8601 UTC; csv ISO-8601 with the display-timezone offset; html on the
display-labeled ``fmt_window``), and the brand/install-string fixes.
"""

from __future__ import annotations

import io
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sigwood import cli
from sigwood import runner
from sigwood.common.errors import DigestEmpty


def _err_lines(capsys) -> list[str]:
    return [ln for ln in capsys.readouterr().err.splitlines() if ln.strip()]


# ── report-content shape tripwire ──────────────────────────────────────────────


def assert_report_voice(findings) -> None:
    """VOICE report-content shape check over SHIPPED detector findings.

    Checks ``description`` + ``next_steps`` ONLY - never ``title`` (entity titles
    are values, and the aws synthetic prose title intentionally stays lowercase).
    Called from the per-detector tests that already build findings from RFC 5737
    fixtures, so it introspects real output rather than hand-coded strings.

    - non-empty ``description`` → sentence case (first char upper) + terminal period;
    - every ``next_steps`` entry → capital first word, NO terminal ``.``/``!``/``?``.
    A finding with an empty description/next_steps is fine (be-like-water) - skipped.
    """
    for f in findings:
        desc = (f.description or "").strip()
        if desc:
            assert desc[0].isupper(), f"description must be sentence-case: {desc!r}"
            assert desc.endswith("."), f"description must end with a period: {desc!r}"
        for step in f.next_steps:
            s = step.strip()
            assert s, "next_steps entry must be non-empty"
            assert s[0].isupper(), f"next_steps must start capitalized: {s!r}"
            assert not s.endswith((".", "!", "?")), (
                f"next_steps must not end with terminal punctuation: {s!r}"
            )


# ── no double-prefix ──────────────────────────────────────────────────────────


def test_operational_error_single_sigwood_prefix(capsys) -> None:
    """A config error surfaces through cli.main as exactly ONE ``sigwood:``
    prefix - never ``sigwood: sigwood …`` - and carries NO usage pointer."""
    with pytest.raises(SystemExit) as exc:
        cli.main(["beacon", "conn.log", "--config=/no/such/config.toml"])
    assert exc.value.code == 1
    lines = _err_lines(capsys)
    assert lines[0].startswith("sigwood: config file not found")
    assert "sigwood: sigwood" not in "\n".join(lines)
    assert not any("sigwood --help" in ln for ln in lines)


def test_digest_recognized_empty_single_prefix(tmp_path, monkeypatch, capsys) -> None:
    """The digest recognized-but-empty skip is an error-tier diagnostic - ONE
    ``sigwood:`` prefix, no internal ``digest:`` tag, no double-prefix."""
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    monkeypatch.setattr(
        cli.cfg, "load",
        lambda _path: {"sigwood": {"zeek_dir": str(zeek_dir)}},
    )

    def _empty(**kwargs):
        raise DigestEmpty(basename="conn.log", schema="conn")

    monkeypatch.setattr(runner, "run_digest", _empty)
    cli._main(["digest"])
    err = capsys.readouterr().err
    assert "sigwood: conn.log: recognized as conn, no parseable records - skipping" in err
    assert "sigwood: sigwood" not in err
    assert "digest:" not in err


# ── usage pointer ONLY on argument errors ─────────────────────────────────────


def test_usage_pointer_on_argument_error(capsys) -> None:
    """A bad flag is a UsageError → the usage pointer is appended."""
    with pytest.raises(SystemExit) as exc:
        cli.main(["beacon", "--nonsuch"])
    assert exc.value.code == 1
    lines = _err_lines(capsys)
    assert lines[0] == "sigwood: unknown flag --nonsuch"
    assert lines[1] == "run 'sigwood --help' for usage"


def test_usage_pointer_absent_on_unknown_output_format(capsys) -> None:
    """Unknown output format is OPERATIONAL, not a usage error - no pointer."""
    with pytest.raises(SystemExit) as exc:
        cli.main(["beacon", "conn.log", "--format=xml"])
    assert exc.value.code == 1
    joined = "\n".join(_err_lines(capsys))
    assert "unknown output format 'xml'" in joined
    assert "sigwood --help" not in joined


# ── explicit positional that doesn't exist → fail fast (operational error) ─────


def test_single_detector_missing_positional_fails_fast(capsys) -> None:
    """`sigwood dns /no/such/file` exits 1 with `sigwood: <path>: not found`
    - NOT the source-discovery cascade, and NO --help pointer (operational)."""
    with pytest.raises(SystemExit) as exc:
        cli.main(["dns", "/no/such/file"])
    assert exc.value.code == 1
    joined = "\n".join(_err_lines(capsys))
    assert "sigwood: /no/such/file: not found" in joined
    # negative space: no source-skip cascade, no "nothing ran", no usage pointer
    assert "no source found" not in joined
    assert "no detectors could run" not in joined
    assert "sigwood --help" not in joined


def test_analyze_missing_positional_fails_fast(capsys) -> None:
    """`sigwood /no/such/file` (analyze path) - same fail-fast behavior."""
    with pytest.raises(SystemExit) as exc:
        cli.main(["/no/such/file"])
    assert exc.value.code == 1
    joined = "\n".join(_err_lines(capsys))
    assert "sigwood: /no/such/file: not found" in joined
    assert "no source found" not in joined
    assert "no detectors could run" not in joined
    assert "sigwood --help" not in joined


# ── format timestamp contracts ────────────────────────────────────────────────
#   json -> ISO-8601 UTC always (lossless machine; never reads the display switch)
#   csv  -> ISO-8601 with the DISPLAY-timezone offset (local by default, +00:00
#           under --utc/use_utc; == +00:00 here under the TZ=UTC pin)
#   html -> the human fmt_window with the display label (local by default, UTC
#           under the switch), not machine-ISO


def _run_summary():
    from sigwood.common.finding import RunSummary
    return RunSummary(
        data_window=(
            datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc),
            datetime(2026, 6, 1, 18, 30, tzinfo=timezone.utc),
        ),
        record_counts={"conn*.log*": 3},
        data_size_bytes=0,
        detectors_run=["beacon"],
        detectors_skipped={},
        notes=[],
    )


def _finding():
    from sigwood.common.finding import Finding, Severity
    return Finding(
        detector="beacon",
        severity=Severity.HIGH,
        title="192.0.2.10 → 192.0.2.20:443/tcp",
        description="",
        evidence={},
        next_steps=[],
        ts_generated=datetime(2026, 6, 1, 18, 30, tzinfo=timezone.utc),
        data_window=(
            datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc),
            datetime(2026, 6, 1, 18, 30, tzinfo=timezone.utc),
        ),
    )


def test_json_window_stays_iso_utc() -> None:
    """The human renderer (` local`) must never leak into json output."""
    from sigwood.outputs.json import JsonHandler
    buf = io.StringIO()
    h = JsonHandler(stream=buf, verbose_level=0)
    h.begin(_run_summary())
    h.write([_finding()])
    h.end()
    out = buf.getvalue()
    assert "2026-06-01T12:00:00+00:00" in out
    assert " local" not in out
    assert " → " not in out


def test_csv_window_is_iso_with_local_offset() -> None:
    """csv timestamps are ISO-8601 with the DISPLAY-timezone offset (the single
    tz conversion point, ``to_display_timezone``; local with the switch off -
    the default state here). Under the TZ=UTC pin the local offset is
    ``+00:00``; the human ` local` label must NOT leak in."""
    from sigwood.outputs.csv import CsvHandler
    buf = io.StringIO()
    h = CsvHandler(stream=buf, verbose_level=0)
    h.begin(_run_summary())
    h.write([_finding()])
    h.end()
    out = buf.getvalue()
    assert "2026-06-01T12:00:00+00:00" in out  # ISO with an explicit offset
    assert " local" not in out


def test_html_window_uses_local_fmt_window() -> None:
    """html is a HUMAN reading surface: its header window renders through the
    display-labeled ``fmt_window`` (``local`` with the switch off - the default
    state here), NOT ISO-8601 UTC. Under the TZ=UTC pin local == UTC."""
    from sigwood.outputs.html import render_report_html
    out = render_report_html([_finding()], _run_summary(), verbose_level=0)
    assert "2026-06-01 12:00 → 2026-06-01 18:30 local" in out
    assert "2026-06-01T12:00:00+00:00" not in out  # no machine ISO in the header


# ── brand / install-string fixes ──────────────────────────────────────────────


_SRC_ROOT = Path(__file__).resolve().parent.parent


def _read(rel: str) -> str:
    return (_SRC_ROOT / rel).read_text(encoding="utf-8")


def test_install_strings_use_sigwood_extras() -> None:
    assert "sigwood[cloudtrail]" in _read("sigwood/exporters/cloudtrail.py")
    assert "sigwood[splunk]" in _read("sigwood/exporters/splunk.py")
    assert "sigwood[fast]" in _read("sigwood/common/clustering.py")


def test_no_dead_spiralbend_install_string() -> None:
    for rel in (
        "sigwood/exporters/cloudtrail.py",
        "sigwood/exporters/splunk.py",
        "sigwood/common/clustering.py",
        "sigwood/cli_init.py",
    ):
        text = _read(rel)
        assert "spiralbend" not in text


def test_docs_url_and_pyproject_urls_point_at_helixmap() -> None:
    from sigwood.cli_init import _DOCS_URL
    assert _DOCS_URL == "https://github.com/helixmap/sigwood"
    pyproject = _read("pyproject.toml")
    assert "[project.urls]" in pyproject
    assert "https://github.com/helixmap/sigwood" in pyproject


# ── docs-example flag form tripwire ───────────────────────────────────────────
#
# The parser accepts ONE value syntax: --flag=value / -x=value. A docs example
# showing the space form (`-f html`) teaches a command that exits 1, so every
# sigwood command example in the public docs must use the = form. The flag
# set derives from cli._FLAG_LIST (takes_value=True), so a future value flag
# inherits enforcement without touching this test.


def _value_flag_forms() -> frozenset[str]:
    forms: set[str] = set()
    for spec in cli._FLAG_LIST:
        if spec.takes_value:
            forms.add(spec.long)
            if spec.short:
                forms.add(f"-{spec.short}")
    return frozenset(forms)


def _iter_code_fragments(md_text: str) -> list[str]:
    """Every code fragment in the markdown - fenced-block lines plus inline code
    spans - extracted PER non-fenced LINE. Running the inline-span regex over the
    whole document would let fence-marker backtick runs shift the pair matching and
    silently drop real spans, so each line is scanned on its own. A leading ``$ ``
    prompt is NOT stripped here - callers strip it."""
    fragments: list[str] = []
    in_fence = False
    for raw in md_text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            fragments.append(stripped)
        else:
            fragments.extend(
                m.group(1).strip() for m in re.finditer(r"`([^`]+)`", raw)
            )
    return fragments


def _sigwood_examples(md_text: str) -> list[str]:
    """sigwood command candidates from markdown - the code fragments whose FIRST
    token is ``sigwood`` (an optional leading ``$ `` stripped), so prose
    mentioning a bare flag never false-positives."""
    out: list[str] = []
    for cand in _iter_code_fragments(md_text):
        if cand.startswith("$ "):
            cand = cand[2:]
        if cand.split()[:1] == ["sigwood"]:
            out.append(cand)
    return out


def _space_form_violations(cmd: str, forms: frozenset[str]) -> list[str]:
    """Value-taking flag tokens followed by a whitespace-separated value token."""
    toks = cmd.split()
    return [
        tok
        for i, tok in enumerate(toks)
        if tok in forms and i + 1 < len(toks) and not toks[i + 1].startswith("-")
    ]


def test_docs_examples_use_equals_form_for_value_flags() -> None:
    docs = [
        _SRC_ROOT / "README.md",
        _SRC_ROOT / "demo" / "README.md",
        *sorted((_SRC_ROOT / "docs").glob("*.md")),
    ]
    forms = _value_flag_forms()
    violations: list[str] = []
    extracted = 0
    for doc in docs:
        for cmd in _sigwood_examples(doc.read_text(encoding="utf-8")):
            extracted += 1
            for flag in _space_form_violations(cmd, forms):
                violations.append(f"{doc.name}: {cmd!r} ({flag} without =)")
    assert extracted >= 20, (
        f"docs-example extractor matched only {extracted} sigwood commands - "
        "an extractor keyed on a stale command name scans nothing and enforces nothing"
    )
    assert not violations, (
        "space-form flag values in docs examples:\n" + "\n".join(violations)
    )


def test_docs_example_tripwire_catches_space_form() -> None:
    """Negative self-test: the tripwire must FLAG the space form, both directly
    and through the markdown extraction path - proven live, not assumed."""
    forms = _value_flag_forms()
    bad = "sigwood dns -f html > report.html"
    assert _space_form_violations(bad, forms) == ["-f"]
    assert _space_form_violations("sigwood dns -f=html > report.html", forms) == []

    fixture_md = (
        "Redirect to save (`" + bad + "`).\n"
        "```bash\n"
        "$ " + bad + "\n"
        "```\n"
    )
    extracted = _sigwood_examples(fixture_md)
    assert extracted == [bad, bad]
    assert all(_space_form_violations(cmd, forms) == ["-f"] for cmd in extracted)


# ── docs-example range-flag form tripwire ─────────────────────────────────────
#
# Range-valued flags (--days / --hours) accept ONLY an N-M range; a bare
# --days=7 raises at runtime. A docs example - anywhere, not just inside a
# sigwood command - must show a concrete N-M range or the literal N-M
# placeholder. The flag set and placeholder derive from cli._FLAG_LIST
# (metavar == "N-M"), so a future range flag inherits enforcement.


def _range_flag_forms_and_placeholders() -> tuple[frozenset[str], frozenset[str]]:
    flags: set[str] = set()
    placeholders: set[str] = set()
    for spec in cli._FLAG_LIST:
        if spec.metavar == "N-M":
            flags.add(spec.long)
            placeholders.add(spec.metavar)
    return frozenset(flags), frozenset(placeholders)


def _range_flag_violations(
    fragment: str, flags: frozenset[str], placeholders: frozenset[str]
) -> list[str]:
    """Range-flag tokens whose value is neither a concrete N-M range (\\d+-\\d+)
    nor the metavar placeholder N-M."""
    if not flags:
        return []
    pat = re.compile(r"(" + "|".join(re.escape(f) for f in sorted(flags)) + r")=(\S+)")
    out: list[str] = []
    for m in pat.finditer(fragment):
        value = m.group(2)
        if re.fullmatch(r"\d+-\d+", value) or value in placeholders:
            continue
        out.append(f"{m.group(1)}={value}")
    return out


def test_docs_examples_use_range_form_for_range_flags() -> None:
    docs = [
        _SRC_ROOT / "README.md",
        _SRC_ROOT / "demo" / "README.md",
        *sorted((_SRC_ROOT / "docs").glob("*.md")),
    ]
    flags, placeholders = _range_flag_forms_and_placeholders()
    violations: list[str] = []
    for doc in docs:
        for frag in _iter_code_fragments(doc.read_text(encoding="utf-8")):
            for bad in _range_flag_violations(frag, flags, placeholders):
                violations.append(f"{doc.name}: {bad}")
    assert not violations, (
        "single-value range-flag examples in docs (need an N-M range):\n"
        + "\n".join(violations)
    )


def test_range_flag_tripwire_catches_single_value() -> None:
    """Negative self-test: the range checker FLAGS a single value in BOTH an inline
    span and a fenced line (a FAQ-shaped snippet), and passes a concrete range or
    the N-M placeholder. The invalid --days=7 / --hours=5 here are the checker's own
    fixtures, deliberately isolated from the docs the tripwire scans."""
    flags, placeholders = _range_flag_forms_and_placeholders()
    assert _range_flag_violations("--days=7", flags, placeholders) == ["--days=7"]
    assert _range_flag_violations("--days=2-4", flags, placeholders) == []
    assert _range_flag_violations("--days=N-M", flags, placeholders) == []

    bad_md = (
        "widen with `--days=7` or `--all` when the span is short.\n"
        "```bash\n"
        "$ sigwood --hours=5 ~/zeek\n"
        "```\n"
    )
    flagged = [
        v
        for frag in _iter_code_fragments(bad_md)
        for v in _range_flag_violations(frag, flags, placeholders)
    ]
    assert flagged == ["--days=7", "--hours=5"]

    good_md = (
        "look 2 to 4 days back with `--days=2-4`.\n"
        "```bash\n"
        "$ sigwood --hours=N-M ~/zeek\n"
        "```\n"
    )
    clean = [
        v
        for frag in _iter_code_fragments(good_md)
        for v in _range_flag_violations(frag, flags, placeholders)
    ]
    assert clean == []


_PRIVATE_DOCS_DIR = "priv" + "docs"
_RESIDUE_TOKEN_FILE = _SRC_ROOT / _PRIVATE_DOCS_DIR / "residue_tokens.txt"


def _strip_residue_token_line(line: str) -> str:
    out: list[str] = []
    escaped = False
    for ch in line:
        if ch == "#" and not escaped:
            break
        out.append(ch)
        escaped = (ch == "\\") and not escaped
        if ch != "\\":
            escaped = False
    return "".join(out).strip()


def _load_residue_regexes() -> list[re.Pattern[str]]:
    if not _RESIDUE_TOKEN_FILE.exists():
        pytest.skip("residue token list not present - dev-box enforced, public CI skips")
    patterns: list[str] = []
    for line in _RESIDUE_TOKEN_FILE.read_text(encoding="utf-8").splitlines():
        pattern = _strip_residue_token_line(line)
        if pattern:
            patterns.append(pattern)
    return [re.compile(pattern) for pattern in patterns]


def test_no_internal_workflow_residue_in_source() -> None:
    """No internal-workflow provenance in committed source comments/docstrings.

    Comments and docstrings state current constraints without workflow provenance;
    this pins the mechanical tokens. Reviewer names, review-cycle codes, and
    references to internal gitignored docs are session residue to a public reader.
    Some history-shaped phrasing has legitimate runtime uses and is deliberately
    not machine-pinned here.
    """
    regexes = _load_residue_regexes()
    dirs = ("sigwood", "tests", "notebooks", "demo")
    this_file = Path(__file__).resolve()
    violations: list[str] = []
    scanned_files = 0
    for d in dirs:
        for path in sorted((_SRC_ROOT / d).rglob("*")):
            if path.suffix not in (".py", ".ipynb"):
                continue
            if any(part in ("__pycache__", ".ipynb_checkpoints") for part in path.parts):
                continue
            if path.resolve() == this_file:
                continue  # this test names the external token-file path
            scanned_files += 1
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                for rx in regexes:
                    m = rx.search(line)
                    if m:
                        rel = path.relative_to(_SRC_ROOT)
                        violations.append(f"{rel}:{lineno}: {m.group(0)!r}")
    assert scanned_files > 100, (
        f"residue scan walked only {scanned_files} files - a scan root naming a "
        "missing directory rglobs nothing and enforces nothing"
    )
    assert not violations, "internal-workflow residue in source:\n" + "\n".join(violations)
