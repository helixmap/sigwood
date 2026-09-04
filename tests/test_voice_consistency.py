"""Cross-cutting output voice & format consistency invariants.

Locks the cross-cutting invariants the per-surface tests don't individually
guard: single ``sigwood:`` prefixing (no double-prefix), the usage pointer
appearing ONLY for argument errors, the per-format timestamp contracts (json
always ISO-8601 UTC; csv ISO-8601 with the display-timezone offset; html on the
display-labeled ``fmt_window``), and the brand/install-string fixes.
"""

from __future__ import annotations

from collections import Counter
import io
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sigwood import cli
from sigwood import runner
from sigwood.common import config as cfg
from tests import dash_rule
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


def test_config_disclosure_is_warning_voice_not_error_voice() -> None:
    lines = cfg.config_disclosure_lines({"sigwood": {"zeek_dri": "/placeholder"}})

    assert lines == [
        "config: ignoring unknown setting [sigwood].zeek_dri "
        "(did you mean zeek_dir?)",
    ]
    assert all(line.startswith("config:") for line in lines)
    assert all(not line.startswith("sigwood:") for line in lines)
    assert all(not line.endswith(".") for line in lines)
    assert all("sigwood: sigwood" not in line for line in lines)


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
        severity=Severity.MEDIUM,
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


# Public prose states what the tool does and does not do; it never characterizes
# the tool's own virtue. A virtue-word whose deletion leaves the sentence's facts
# intact ("the honest ledger", "stated plainly") reads as a plea to be believed,
# and a reader told twice that the tool is honest starts asking why it insists.
# The budget below holds the SYMPTOMATIC token family at its three-use floor: two
# CONTRIBUTING uses define a contributor value and its guidance, while one
# CHANGELOG use names a change whose whole point was a disclosure's truthfulness
# (the word is the subject there, not seasoning). The path-plus-exact-match table
# drains both ways: a new use argues with this comment, and a removed use shrinks
# its row in the same change. Case and inflection changes deliberately require a
# table decision. Moving the same exact token within one file remains invisible;
# catching that would require brittle context or position anchors. Whether a
# sentence pleads in OTHER words is a prose judgment no scan decides; that half
# is review-enforced.
_PLEADING_TOKEN_RE = re.compile(
    r"\bhonest(?:y|ly)?\b|\btruthful(?:ly|ness)?\b", re.IGNORECASE
)
_PLEADING_BUDGET = {
    "CHANGELOG.md": Counter({"truthfully": 1}),
    "CONTRIBUTING.md": Counter({"honest": 1, "Honesty": 1}),
}
# Root pages are enumerated, never globbed - a root glob follows local agent
# symlinks into untracked space; docs/ is walked recursively so subdirectories
# (docs/evidence/) stay covered.
_PLEADING_ROOT_DOCS = (
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
    "demo/README.md",
)


def _pleading_token_counts(src_root: Path = _SRC_ROOT) -> dict[str, Counter[str]]:
    files = [src_root / rel for rel in _PLEADING_ROOT_DOCS]
    files += sorted((src_root / "docs").rglob("*.md"))
    counts: dict[str, Counter[str]] = {}
    for path in files:
        matches = Counter(_PLEADING_TOKEN_RE.findall(path.read_text(encoding="utf-8")))
        if matches:
            counts[path.relative_to(src_root).as_posix()] = matches
    return counts


def test_public_prose_holds_the_pleading_token_budget() -> None:
    """Public docs carry the honest/truthful token family at exactly the budgeted
    floor - a new use fails here and argues with the budget's comment, and a
    removed use shrinks the table in the same change so it cannot re-permit."""
    assert _pleading_token_counts() == _PLEADING_BUDGET


def test_pleading_token_scan_counts_a_seeded_use() -> None:
    """Positive control: the scanner counts the token family it exists to hold,
    across case and inflection, and ignores mid-word collisions."""
    seeded = "an Honest ledger, honestly truthful, dishonest but a chestnut"
    assert len(_PLEADING_TOKEN_RE.findall(seeded)) == 3


def _write_pleading_test_corpus(
    tmp_path: Path, contributing_text: str
) -> dict[str, Counter[str]]:
    for rel in _PLEADING_ROOT_DOCS:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    (tmp_path / "docs").mkdir(exist_ok=True)
    (tmp_path / "CHANGELOG.md").write_text("truthfully\n", encoding="utf-8")
    (tmp_path / "CONTRIBUTING.md").write_text(contributing_text, encoding="utf-8")
    return _pleading_token_counts(tmp_path)


def test_pleading_token_budget_rejects_an_inflection_substitution(
    tmp_path: Path,
) -> None:
    """A same-file substitution cannot hide behind an unchanged total count."""
    observed = _write_pleading_test_corpus(tmp_path, "honest truthfully\n")
    allowed = _PLEADING_BUDGET["CONTRIBUTING.md"]
    substituted = observed["CONTRIBUTING.md"]

    assert substituted.total() == allowed.total()  # The old integer budget passed.
    assert observed != _PLEADING_BUDGET
    assert substituted - allowed == Counter({"truthfully": 1})
    assert allowed - substituted == Counter({"Honesty": 1})


def test_pleading_token_budget_rejects_an_unused_allowance(tmp_path: Path) -> None:
    """Removing a legitimate use requires shrinking its exact-text table row."""
    observed = _write_pleading_test_corpus(tmp_path, "honest\n")
    allowed = _PLEADING_BUDGET["CONTRIBUTING.md"]
    after_removal = observed["CONTRIBUTING.md"]

    assert observed != _PLEADING_BUDGET
    assert after_removal - allowed == Counter()
    assert allowed - after_removal == Counter({"Honesty": 1})


# This test is the one tracked file that names the private token-file path; the
# residue scan below excludes this file from itself, so the literal is sanctioned here.
_RESIDUE_TOKEN_FILE = _SRC_ROOT / "private" / "residue_tokens.txt"
_RESIDUE_ALLOW_PREFIX = "allow:"
_RESIDUE_PUBLIC_PREFIX = "public:"
_RESIDUE_NAME_PREFIX = "name:"
_RESIDUE_CODE_DIRS = ("sigwood", "tests", "notebooks", "demo", "tools")
_RESIDUE_YAML_DIRS = (".github",)
_RESIDUE_ROOT_DOCS = ("README.md", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md")
_RESIDUE_JUNK_DIRS = ("__pycache__", ".ipynb_checkpoints")
_RESIDUE_MARKDOWN_FLOOR = 11
_RESIDUE_NAME_FILE_FLOOR = 200

ResidueKey = tuple[str, str]


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


def _residue_pattern_accepts_payload(rx: re.Pattern[str], payload: str) -> bool:
    # An allowance stores the regex match, not its surrounding source text. The
    # identifier pattern deliberately uses a separator lookbehind, so validate
    # its exact payload in each permitted left context as well as in isolation.
    for prefix in ("", "_", "-"):
        framed = prefix + payload
        for match in rx.finditer(framed):
            if match.start() == len(prefix) and match.end() == len(framed):
                return True
    return False


def _parse_residue_policy(
    text: str,
) -> tuple[
    list[re.Pattern[str]],
    list[re.Pattern[str]],
    list[re.Pattern[str]],
    Counter[ResidueKey],
]:
    patterns: list[re.Pattern[str]] = []
    public_patterns: list[re.Pattern[str]] = []
    name_patterns: list[re.Pattern[str]] = []
    allowances: Counter[ResidueKey] = Counter()
    for lineno, line in enumerate(text.splitlines(), 1):
        entry = _strip_residue_token_line(line)
        if not entry:
            continue
        if entry.startswith(_RESIDUE_ALLOW_PREFIX):
            payload = entry.removeprefix(_RESIDUE_ALLOW_PREFIX)
            if "\t" not in payload:
                raise AssertionError(
                    f"residue policy line {lineno}: allow row needs path<TAB>matched text"
                )
            rel_text, matched_text = payload.split("\t", 1)
            rel = Path(rel_text)
            if (
                not rel_text
                or rel.is_absolute()
                or rel.as_posix() != rel_text
                or any(part in ("", ".", "..") for part in rel.parts)
                or (rel.parts and rel.parts[0] == "private")
            ):
                raise AssertionError(
                    f"residue policy line {lineno}: invalid repository-relative path"
                )
            if not matched_text or matched_text != matched_text.strip():
                raise AssertionError(
                    f"residue policy line {lineno}: invalid exact matched text"
                )
            allowances[(rel_text, matched_text)] += 1
            continue
        public = entry.startswith(_RESIDUE_PUBLIC_PREFIX)
        named = entry.startswith(_RESIDUE_NAME_PREFIX)
        if public:
            pattern_text = entry.removeprefix(_RESIDUE_PUBLIC_PREFIX)
        elif named:
            pattern_text = entry.removeprefix(_RESIDUE_NAME_PREFIX)
        else:
            pattern_text = entry
        if not pattern_text:
            kind = "name" if named else "public" if public else "content"
            raise AssertionError(f"residue policy line {lineno}: empty {kind} pattern")
        try:
            compiled = re.compile(pattern_text)
        except re.error as exc:
            raise AssertionError(f"residue policy line {lineno}: {exc}") from exc
        if named:
            name_patterns.append(compiled)
        else:
            patterns.append(compiled)
            if public:
                public_patterns.append(compiled)

    if not patterns:
        raise AssertionError("residue policy contains no regex patterns")
    if not public_patterns:
        raise AssertionError("residue policy contains no public-surface regex patterns")
    if not name_patterns:
        raise AssertionError("residue policy contains no filename regex patterns")
    for _rel, matched_text in allowances:
        named = matched_text.startswith(_RESIDUE_NAME_PREFIX)
        payload = matched_text.removeprefix(_RESIDUE_NAME_PREFIX) if named else matched_text
        validation_patterns = name_patterns if named else patterns
        if not payload or not any(
            _residue_pattern_accepts_payload(rx, payload) for rx in validation_patterns
        ):
            raise AssertionError(
                f"residue allowance text is not a full policy match: {matched_text!r}"
            )
    return patterns, public_patterns, name_patterns, allowances


def _load_residue_policy(
) -> tuple[
    list[re.Pattern[str]],
    list[re.Pattern[str]],
    list[re.Pattern[str]],
    Counter[ResidueKey],
]:
    if not _RESIDUE_TOKEN_FILE.exists():
        pytest.skip("residue token list not present - dev-box enforced, public CI skips")
    return _parse_residue_policy(_RESIDUE_TOKEN_FILE.read_text(encoding="utf-8"))


def _residue_regular_files(root: Path) -> list[Path]:
    # Measured before this inventory shipped: 387 of 664 files in the scoped
    # directory roots were compiled artifacts under __pycache__. Letting those
    # basenames into the name view produced ten interpreter- and pytest-version
    # dependent hits, so the allowance table failed with both new occurrences
    # and stale rows on another maintainer's box. This exclusion is portability,
    # not cleanup.
    return [
        path
        for path in sorted(root.rglob("*"))
        if path.is_file() and not any(part in _RESIDUE_JUNK_DIRS for part in path.parts)
    ]


def _residue_inventory_paths(source_root: Path = _SRC_ROOT) -> list[Path]:
    for dirname in (*_RESIDUE_CODE_DIRS, *_RESIDUE_YAML_DIRS):
        root = source_root / dirname
        assert root.is_dir(), f"residue scan root is missing: {root}"

    docs_root = source_root / "docs"
    assert docs_root.is_dir(), f"residue docs root is missing: {docs_root}"
    for name in _RESIDUE_ROOT_DOCS:
        path = source_root / name
        assert path.is_file(), f"residue root document is missing: {name}"

    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=source_root,
        check=True,
        capture_output=True,
    )
    selected_roots = {*_RESIDUE_CODE_DIRS, *_RESIDUE_YAML_DIRS, "docs"}
    paths: list[Path] = []
    for raw_rel in result.stdout.split(b"\0"):
        if not raw_rel:
            continue
        rel = Path(os.fsdecode(raw_rel))
        if rel.as_posix() not in _RESIDUE_ROOT_DOCS and (
            not rel.parts or rel.parts[0] not in selected_roots
        ):
            continue
        path = source_root / rel
        if not path.is_file() or any(part in _RESIDUE_JUNK_DIRS for part in rel.parts):
            continue
        nested_directories = rel.parts[1:-1] if rel.parts[0] == ".github" else rel.parts[:-1]
        if any(part.startswith(".") for part in nested_directories):
            continue
        paths.append(path)

    private_root = (source_root / "private").resolve()
    for path in paths:
        resolved = path.resolve()
        assert resolved != private_root and private_root not in resolved.parents, (
            f"public residue scan path resolves inside private/: {path}"
        )
    return paths


def _residue_scan_paths(
    inventory: list[Path] | None = None,
    *,
    source_root: Path = _SRC_ROOT,
) -> list[Path]:
    raw_paths = _residue_inventory_paths(source_root) if inventory is None else inventory
    paths: list[Path] = []
    for path in raw_paths:
        rel = path.relative_to(source_root)
        if rel.parts[0] in _RESIDUE_CODE_DIRS:
            if path.suffix in (".py", ".ipynb"):
                paths.append(path)
        elif rel.parts[0] in _RESIDUE_YAML_DIRS:
            if path.suffix in (".yml", ".yaml"):
                paths.append(path)
        elif rel.parts[0] == "docs":
            if path.suffix == ".md":
                paths.append(path)
        else:
            paths.append(path)
    return paths


def _residue_occurrences_for_text(
    rel: str,
    text: str,
    regexes: list[re.Pattern[str]],
) -> tuple[Counter[ResidueKey], dict[ResidueKey, list[int]]]:
    observed: Counter[ResidueKey] = Counter()
    locations: dict[ResidueKey, list[int]] = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        for rx in regexes:
            for match in rx.finditer(line):
                key = (rel, match.group(0))
                observed[key] += 1
                locations.setdefault(key, []).append(lineno)
    return observed, locations


def _residue_occurrences_for_name(
    rel: str,
    name: str,
    regexes: list[re.Pattern[str]],
) -> Counter[ResidueKey]:
    observed: Counter[ResidueKey] = Counter()
    for rx in regexes:
        for match in rx.finditer(name):
            observed[(rel, _RESIDUE_NAME_PREFIX + match.group(0))] += 1
    return observed


def _residue_policy_delta(
    observed: Counter[ResidueKey],
    allowed: Counter[ResidueKey],
) -> tuple[Counter[ResidueKey], Counter[ResidueKey]]:
    unexpected = observed - allowed
    # This subtraction is deliberately two-sided. An unused allowance can look
    # like harmless bookkeeping, but rejecting it is what makes grandfathering
    # shrink-only instead of a permanent permission for residue to return.
    unused = allowed - observed
    return unexpected, unused


def _format_residue_counter(
    heading: str,
    counter: Counter[ResidueKey],
    locations: dict[ResidueKey, list[int]] | None = None,
) -> list[str]:
    lines: list[str] = []
    for key, count in sorted(counter.items()):
        rel, matched_text = key
        where = ""
        if locations and key in locations:
            where = f" at lines {locations[key]}"
        lines.append(f"{heading}: {rel}: {matched_text!r} x{count}{where}")
    return lines


def test_no_internal_workflow_residue_in_source() -> None:
    """No internal-workflow provenance in committed source comments/docstrings.

    Comments and docstrings state current constraints without workflow provenance;
    this pins the mechanical tokens. Reviewer names, review-cycle codes, and
    references to internal gitignored docs are session residue to a public reader.
    Some history-shaped phrasing has legitimate runtime uses and is deliberately
    not machine-pinned here.
    """
    regexes, public_regexes, name_regexes, allowed = _load_residue_policy()
    this_file = Path(__file__).resolve()
    observed: Counter[ResidueKey] = Counter()
    locations: dict[ResidueKey, list[int]] = {}
    scanned_code_files = 0
    scanned_markdown = 0
    inventory = _residue_inventory_paths()
    for path in inventory:
        rel = path.relative_to(_SRC_ROOT).as_posix()
        observed.update(_residue_occurrences_for_name(rel, path.name, name_regexes))
    for path in _residue_scan_paths(inventory):
        if path.resolve() == this_file:
            continue  # this test names and exercises the external policy grammar
        if path.suffix == ".md":
            scanned_markdown += 1
        else:
            scanned_code_files += 1
        rel = path.relative_to(_SRC_ROOT).as_posix()
        active_regexes = public_regexes if path.suffix == ".md" else regexes
        found, found_locations = _residue_occurrences_for_text(
            rel, path.read_text(encoding="utf-8"), active_regexes
        )
        observed.update(found)
        for key, line_numbers in found_locations.items():
            locations.setdefault(key, []).extend(line_numbers)
    assert scanned_code_files > 100, (
        f"residue scan walked only {scanned_code_files} code/notebook files - a scan root naming a "
        "missing directory rglobs nothing and enforces nothing"
    )
    assert scanned_markdown >= _RESIDUE_MARKDOWN_FLOOR, (
        f"residue scan walked only {scanned_markdown} public Markdown files; "
        f"expected at least {_RESIDUE_MARKDOWN_FLOOR}"
    )
    assert len(inventory) > _RESIDUE_NAME_FILE_FLOOR, (
        f"residue name view walked only {len(inventory)} files - a scan root naming a "
        "missing directory rglobs nothing and leaves an empty filename rule unenforced"
    )
    unexpected, unused = _residue_policy_delta(observed, allowed)
    problems = _format_residue_counter("unexpected residue", unexpected, locations)
    problems.extend(_format_residue_counter("unused allowance", unused))
    assert not problems, "internal-workflow residue policy mismatch:\n" + "\n".join(problems)


@pytest.mark.parametrize(
    ("text", "matched_text"),
    [
        ("# D99 campaign marker", "D99"),
        ("# old re-decision note", "re-decision"),
        ("# stale sealed C1 choice", "sealed C1"),
    ],
)
def test_residue_campaign_patterns_flag_independent_seeds(
    text: str, matched_text: str
) -> None:
    _regexes, public_regexes, _name_regexes, _allowed = _load_residue_policy()
    observed, _locations = _residue_occurrences_for_text(
        "sigwood/seed.py", text, public_regexes
    )
    assert observed == Counter({("sigwood/seed.py", matched_text): 1})


def test_residue_campaign_patterns_keep_legitimate_controls() -> None:
    _regexes, public_regexes, _name_regexes, _allowed = _load_residue_policy()
    patterns = [rx.pattern for rx in public_regexes]
    campaign_patterns = [
        r"\b[BDRU]\d{2}\b",
        "re-decision",
        r"\bsealed\s+C\d\b",
        r"era[-_]u\d",
    ]
    for expected in campaign_patterns:
        assert expected in patterns
    # The one further public pattern guards references into the repository's
    # gitignored private/ tree on the shipped-Markdown surface. It is pinned by
    # BEHAVIOR, never by its literal: embedding that pattern's text here would
    # put the vocabulary it exists to keep out of tracked bytes into this file.
    extras = [p for p in patterns if p not in campaign_patterns]
    assert len(extras) == 1, f"unexpected public pattern count: {patterns}"
    guard = re.compile(extras[0])
    hit = guard.search("see private/example for the details")
    assert hit is not None and hit.group(0) == "private/example"
    assert guard.search("linked from ../private/example.md") is not None
    assert guard.search("under sigwood/private/example") is not None
    # Absolute OS paths and a bare `private/` with no component are not
    # references into the repository tree and must stay clean.
    assert guard.search("a 1777 /private/tmp symlink target") is None
    assert guard.search("grep -iE 'private/|scratch'") is None
    controls = "\n".join(
        [
            "Strip the Unicode C0 and C1 control classes.",
            "Zeek fixture uid is C1.",
            "The lifecycle is sealed after output.",
            "The alias set is ratified for reconciliation.",
            "Return the canonical closure payload.",
            "Public prose may use a load-bearing dash without process residue.",
            "macOS resolves /tmp to the /private/tmp directory.",
        ]
    )
    observed, _locations = _residue_occurrences_for_text(
        "sigwood/controls.py", controls, public_regexes
    )
    assert observed == Counter()

    markdown_seed, _locations = _residue_occurrences_for_text(
        "docs/seed.md", "Stale D99 explanation.", public_regexes
    )
    assert markdown_seed == Counter({("docs/seed.md", "D99"): 1})


def test_residue_allowances_are_occurrence_exact_and_shrink_only() -> None:
    key = ("sigwood/seed.py", "D99")
    stale = ("tests/gone.py", "R99")

    unexpected, unused = _residue_policy_delta(Counter({key: 2}), Counter({key: 1}))
    assert unexpected == Counter({key: 1})
    assert unused == Counter()

    unexpected, unused = _residue_policy_delta(Counter({key: 1}), Counter({stale: 1}))
    assert unexpected == Counter({key: 1})
    assert unused == Counter({stale: 1})

    unexpected, unused = _residue_policy_delta(Counter(), Counter({stale: 1}))
    assert unexpected == Counter()
    assert unused == Counter({stale: 1})

    unexpected, unused = _residue_policy_delta(Counter(), Counter())
    assert unexpected == Counter()
    assert unused == Counter()


def test_residue_scan_surface_includes_only_public_markdown() -> None:
    paths = _residue_scan_paths()
    rels = {path.relative_to(_SRC_ROOT).as_posix() for path in paths}
    assert "docs/SCHEMA.md" in rels
    assert set(_RESIDUE_ROOT_DOCS) <= rels
    assert {"CODE.md", "AGENTS.md", "CLAUDE.md"}.isdisjoint(rels)
    private_root = (_SRC_ROOT / "private").resolve()
    assert all(private_root not in path.resolve().parents for path in paths)


def test_residue_new_public_roots_catch_untracked_seeded_tokens(tmp_path: Path) -> None:
    token = "D" + str(99)
    tools_seed = tmp_path / "tools/u10_seed_probe.py"
    form_seed = tmp_path / ".github/ISSUE_TEMPLATE/u10_seed_probe.yml"
    tools_seed.parent.mkdir(parents=True)
    form_seed.parent.mkdir(parents=True)
    tools_seed.write_text(f"# {token} marker\n", encoding="utf-8")
    form_seed.write_text(f"description: {token} marker\n", encoding="utf-8")

    paths = _residue_scan_paths(
        [tools_seed, form_seed],
        source_root=tmp_path,
    )
    assert paths == [tools_seed, form_seed]

    regexes, _public_regexes, _name_regexes, _allowed = _load_residue_policy()
    observed = Counter()
    for path in paths:
        found, _locations = _residue_occurrences_for_text(
            path.relative_to(tmp_path).as_posix(),
            path.read_text(encoding="utf-8"),
            regexes,
        )
        observed.update(found)
    assert observed == Counter(
        {
            ("tools/u10_seed_probe.py", token): 1,
            (".github/ISSUE_TEMPLATE/u10_seed_probe.yml", token): 1,
        }
    )


def test_residue_inventory_uses_public_git_projection_and_skips_junk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relative_paths = [
        "sigwood/live.py",
        "tools/u10_seed_probe.py",
        "tools/.cache/hidden.py",
        "tests/__pycache__/junk.pyc",
        ".github/ISSUE_TEMPLATE/live.yml",
        "private/secret.py",
        *_RESIDUE_ROOT_DOCS,
        "docs/INDEX.md",
    ]
    for dirname in (*_RESIDUE_CODE_DIRS, *_RESIDUE_YAML_DIRS, "docs"):
        (tmp_path / dirname).mkdir(parents=True, exist_ok=True)
    for rel in relative_paths:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")

    def _git_inventory(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert command == [
            "git",
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ]
        assert kwargs["cwd"] == tmp_path
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=b"\0".join(rel.encode() for rel in relative_paths) + b"\0",
        )

    monkeypatch.setattr(subprocess, "run", _git_inventory)
    rels = {
        path.relative_to(tmp_path).as_posix()
        for path in _residue_inventory_paths(tmp_path)
    }
    assert "tools/u10_seed_probe.py" in rels
    assert ".github/ISSUE_TEMPLATE/live.yml" in rels
    assert "tools/.cache/hidden.py" not in rels
    assert "tests/__pycache__/junk.pyc" not in rels
    assert "private/secret.py" not in rels


def test_residue_inventory_excludes_interpreter_junk(tmp_path: Path) -> None:
    root = tmp_path / "tests"
    kept = root / "seed.py"
    junk = root / "__pycache__" / "test_seed_u9.cpython-314.pyc"
    kept.parent.mkdir(parents=True)
    junk.parent.mkdir(parents=True)
    kept.write_text("", encoding="utf-8")
    junk.write_bytes(b"")

    assert _residue_regular_files(root) == [kept]


def test_residue_unit_code_patterns_hold_measured_boundaries() -> None:
    regexes, _public_regexes, name_regexes, _allowed = _load_residue_policy()
    prose, _locations = _residue_occurrences_for_text(
        "sigwood/seed.py", "Current U9 constraint.", regexes
    )
    identifier, _locations = _residue_occurrences_for_text(
        "tests/seed.py", "def test_seed_u9_route(): pass", regexes
    )
    control, _locations = _residue_occurrences_for_text(
        "demo/graph.js", "const u2 = Math.max(left, right);", regexes
    )
    basename = _residue_occurrences_for_name(
        "tests/test_seed_u9.txt", "test_seed_u9.txt", name_regexes
    )

    assert prose == Counter({("sigwood/seed.py", "U9"): 1})
    assert identifier == Counter({("tests/seed.py", "u9"): 1})
    assert control == Counter()
    assert basename == Counter({("tests/test_seed_u9.txt", "name:u9"): 1})


def test_residue_name_and_content_allowances_cannot_cross_consume() -> None:
    name_allowed = "\n".join(
        [
            "public:U[0-9]",
            "name:U[0-9]",
            "allow:tests/seed_U9.txt\tname:U9",
        ]
    )
    regexes, _public, name_regexes, allowed = _parse_residue_policy(name_allowed)
    content, _locations = _residue_occurrences_for_text(
        "tests/seed_U9.txt", "U9", regexes
    )
    unexpected, unused = _residue_policy_delta(content, allowed)
    assert unexpected == Counter({("tests/seed_U9.txt", "U9"): 1})
    assert unused == Counter({("tests/seed_U9.txt", "name:U9"): 1})

    content_allowed = "\n".join(
        [
            "public:U[0-9]",
            "name:U[0-9]",
            "allow:tests/seed_U9.txt\tU9",
        ]
    )
    regexes, _public, name_regexes, allowed = _parse_residue_policy(content_allowed)
    basename = _residue_occurrences_for_name(
        "tests/seed_U9.txt", "seed_U9.txt", name_regexes
    )
    unexpected, unused = _residue_policy_delta(basename, allowed)
    assert unexpected == Counter({("tests/seed_U9.txt", "name:U9"): 1})
    assert unused == Counter({("tests/seed_U9.txt", "U9"): 1})


# --------------------------------------------------------------------------
# Dash punctuation: hyphen-only house style
# --------------------------------------------------------------------------
# The rule and its ban list live in tests/dash_rule.py, which the git hooks in
# .githooks/ also call. One owner, so the suite and the hooks cannot disagree
# about what a banned dash is. These tests hold the rule, the gate that enforces
# it before a commit exists, and the guard's own freedom from self-exemption.

_FIGURE_DASH, _EN_DASH, _EM_DASH, _HORIZONTAL_BAR = dash_rule.DASH_CHARS

# Anchors proving the enumeration actually reached the tree. Without these the
# scan can pass by finding nothing to scan.
_DASH_SCAN_ANCHORS = (
    "README.md",
    "docs/CONTRACT.md",
    "docs/evidence/dns.md",
    "sigwood/runner.py",
    "tests/dash_rule.py",
    "tests/test_voice_consistency.py",
    ".githooks/pre-commit",
)


def test_tracked_files_use_hyphens_not_dash_punctuation() -> None:
    if not dash_rule.in_git_work_tree(_SRC_ROOT):
        pytest.skip("no git work tree: a tracked-file export has no inventory to scan")

    scanned = dash_rule.repo_text_files(_SRC_ROOT)
    seen = {rel for rel, _ in scanned}
    assert len(scanned) > 100, f"dash scan enumerated only {len(scanned)} files"
    for anchor in _DASH_SCAN_ANCHORS:
        assert anchor in seen, f"dash scan never reached {anchor}"

    violations: list[str] = []
    for rel, text in scanned:
        violations.extend(dash_rule.violations(rel, text))
    assert violations == [], f"{dash_rule.ADVICE}\n" + "\n".join(violations)


def test_dash_scan_never_reaches_private() -> None:
    """git's inventory is what keeps excluded working-tree entries out of a
    public assertion. A filesystem glob would follow them in, and some of them
    are symlinks pointing outside the repository."""
    if not dash_rule.in_git_work_tree(_SRC_ROOT):
        pytest.skip("no git work tree")

    private_root = (_SRC_ROOT / "private").resolve()
    for rel, _text in dash_rule.repo_text_files(_SRC_ROOT):
        resolved = (_SRC_ROOT / rel).resolve()
        assert resolved != private_root and private_root not in resolved.parents, (
            f"repository path resolves outside the tracked tree: {rel}"
        )


@pytest.mark.parametrize(
    "seed",
    [
        f"a line with an em dash {_EM_DASH} here",
        f"a line with an en dash {_EN_DASH} here",
        f"a line with a figure dash {_FIGURE_DASH} here",
        f"a line with a horizontal bar {_HORIZONTAL_BAR} here",
        'py escape "\\' + 'u2014" inside a string',
        'wide escape "\\' + 'U00002014" inside a string',
        'named escape "\\' + 'N{EM DASH}" inside a string',
        "constructed via ch" + "r(0x2014) at runtime",
        "constructed via ch" + "r(8212) at runtime",
        "markup &" + "mdash; entity",
        "markup &#" + "8212; entity",
        "markup &#x" + "2014; entity",
    ],
)
def test_dash_tripwire_catches_every_seeded_form(seed: str) -> None:
    """The guard must say yes on a known-true case, in each form that shipped
    here or could substitute for one."""
    assert dash_rule.violations("seed.py", seed), f"tripwire missed: {seed!r}"


def test_dash_tripwire_leaves_hyphen_and_minus_sign_alone() -> None:
    """Controls: the replacement character, and the mathematical operator this
    rule deliberately does not govern."""
    minus = chr(0x2212)
    assert dash_rule.violations("seed.py", "an ordinary - hyphen") == []
    assert dash_rule.violations("seed.py", f"f_max {minus} span") == []
    assert dash_rule.violations("seed.py", f'content: "{minus}"') == []


def test_dash_rule_and_this_module_need_no_self_exemption() -> None:
    """Both files name every banned form, and neither may flag itself. That
    property lets the rule ship with no exemption table to go stale."""
    for path in (Path(dash_rule.__file__), Path(__file__)):
        assert dash_rule.violations(path.name, path.read_text(encoding="utf-8")) == []


def test_commit_message_comment_lines_are_not_scanned() -> None:
    """git drops comment lines before recording a message, so scanning them
    would reject a dash the commit never carries."""
    body = dash_rule.message_body(f"a real subject\n# a comment {_EM_DASH} here\n")
    assert dash_rule.violations("commit message", body) == []
    assert dash_rule.violations(
        "commit message", dash_rule.message_body(f"subject {_EM_DASH} here")
    )


# ---- the gate itself, not only the rule ----------------------------------

_HOOKS = ("pre-commit", "commit-msg")


def test_hooks_will_travel_with_a_clone_and_are_executable() -> None:
    """A hook git ignores never reaches a clone, and one without the execute bit
    is skipped in silence rather than reported. Both are checked as properties
    of the file, so a hook added in this commit is judged now and not after it
    lands."""
    if not dash_rule.in_git_work_tree(_SRC_ROOT):
        pytest.skip("no git work tree")

    for name in _HOOKS:
        rel = f".githooks/{name}"
        path = _SRC_ROOT / rel
        assert path.is_file(), f"{rel} is missing"
        assert os.access(path, os.X_OK), f"{rel} is not executable"
        ignored = subprocess.run(
            ["git", "check-ignore", "-q", rel],
            cwd=_SRC_ROOT,
            capture_output=True,
        )
        assert ignored.returncode != 0, f"{rel} is gitignored and would not travel"


@pytest.mark.parametrize("name", _HOOKS)
def test_hooks_delegate_to_the_single_owner(name: str) -> None:
    """A hook that re-implemented the ban list would drift from the suite."""
    body = (_SRC_ROOT / ".githooks" / name).read_text(encoding="utf-8")
    assert "tests/dash_rule.py" in body
    for pattern in dash_rule.CONSTRUCTION_PATTERNS:
        assert pattern not in body, f"{name} carries its own copy of {pattern!r}"


def test_commit_msg_hook_rejects_a_dash_and_accepts_a_hyphen(tmp_path) -> None:
    """The gate is exercised through its real entry point, not its helpers."""
    hook = _SRC_ROOT / ".githooks" / "commit-msg"

    bad = tmp_path / "BAD_MSG"
    bad.write_text(f"fix the thing {_EM_DASH} properly\n", encoding="utf-8")
    rejected = subprocess.run(
        [str(hook), str(bad)], cwd=_SRC_ROOT, capture_output=True, text=True
    )
    assert rejected.returncode == 1
    assert dash_rule.ADVICE in rejected.stderr

    good = tmp_path / "GOOD_MSG"
    good.write_text("fix the thing - properly\n", encoding="utf-8")
    accepted = subprocess.run(
        [str(hook), str(good)], cwd=_SRC_ROOT, capture_output=True, text=True
    )
    assert accepted.returncode == 0, accepted.stderr


def test_contributing_documents_the_per_clone_hook_enable() -> None:
    """The hooks travel with a clone; git will not enable them by itself, so
    the one command that does has to be written down."""
    assert "core.hooksPath .githooks" in _read("CONTRIBUTING.md")
