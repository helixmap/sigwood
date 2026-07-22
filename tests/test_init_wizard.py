"""Coverage for the sigwood init wizard.

Sections:
  - Upsert matrix: section-bound transform inside the [sigwood] span.
  - R1 root non-clobber: re-init preserves an existing root (including "").
  - R5 _toml_str: literal/basic split, control-char rejection.
  - Profiler: families, size, fresh buckets, bounded cap, no-data, perm-tolerant.
  - Flow tests: drive the real _run_init with isolated HOME and monkeypatched
    candidate-path constants - no test reaches the developer's /var/log.
  - Verbatim line discipline: exact dialogue strings, no traceback leakage.
"""

from __future__ import annotations

import ast
import bz2
import gzip
import os
import re
import subprocess
import sys
import tomllib
from datetime import datetime, timedelta
from pathlib import Path

import pytest

# Init wizard helpers moved from sigwood.cli to sigwood.cli_init (a
# CLI-internal split - first-run UX remains CLI-layer ownership). This module
# is rebound to the alias ``cli`` so the existing tests keep their
# ``cli._foo(...)`` / ``monkeypatch.setattr(cli, "_FOO", …)`` shape unchanged.
from sigwood import cli_init as cli


# ── Test fixtures ──────────────────────────────────────────────────────────────

EXAMPLE_TEXT = (
    Path("sigwood/data/config_example.toml").read_text(encoding="utf-8")
)


def _isolated_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point HOME at tmp_path; return ~/.sigwood/ for asserting writes."""
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path / ".sigwood"


def _stage_inputs(monkeypatch: pytest.MonkeyPatch, answers: list[str]) -> None:
    """Drive builtins.input from a fixed list of answers."""
    it = iter(answers)
    monkeypatch.setattr("builtins.input", lambda *_a, **_kw: next(it))


def _stage_inputs_then_eof(monkeypatch: pytest.MonkeyPatch, answers: list[str]) -> None:
    """Drive builtins.input from answers, then raise EOFError when exhausted.

    ``_stage_inputs`` raises StopIteration past its list, which cannot exercise
    the closed-stdin (Ctrl-D / ``< /dev/null``) path - a real input() raises
    EOFError there.
    """
    it = iter(answers)

    def _next(*_a: object, **_kw: object) -> str:
        try:
            return next(it)
        except StopIteration:
            raise EOFError("EOF when reading a line") from None

    monkeypatch.setattr("builtins.input", _next)


def _stub_candidates(
    monkeypatch: pytest.MonkeyPatch,
    *,
    zeek: tuple[str, ...] = (),
    pihole: tuple[tuple[str, str], ...] = (),
    syslog: str = "/nonexistent-syslog-dir",
    journal_code: cli.journal_probe.JournalProbeCode | None = None,
    journal_stderr: bytes = b"",
) -> None:
    """Replace all live probes so tests never touch host logs or journal."""
    monkeypatch.setattr(cli, "_ZEEK_CANDIDATES", zeek)
    monkeypatch.setattr(cli, "_PIHOLE_CANDIDATES", pihole)
    monkeypatch.setattr(cli, "_SYSLOG_CANDIDATE", syslog)
    if journal_code is None:
        journal_code = cli.journal_probe.JournalProbeCode.EXECUTABLE_MISSING
    result = cli.journal_probe.JournalProbeResult(
        journal_code,
        stderr=journal_stderr,
    )
    monkeypatch.setattr(cli.journal_probe, "probe_journal", lambda: result)


# ════════════════════════════════════════════════════════════════════════════
# 1-11. Upsert matrix - section-bound transform
# ════════════════════════════════════════════════════════════════════════════


def test_upsert_fresh_from_example_provided_active_rewrite() -> None:
    out = cli._upsert_sigwood_key(
        EXAMPLE_TEXT, "zeek_dir", "/opt/zeek/logs", fresh=True,
    )
    parsed = tomllib.loads(out)
    assert parsed["sigwood"]["zeek_dir"] == "/opt/zeek/logs"
    # only one active zeek_dir line
    assert out.count('\nzeek_dir') == 1


def test_upsert_none_fresh_comments_active_line() -> None:
    # value=None + fresh=True is the `remove` action's comment/revert-to-default
    # path (a skip disables via _disable_sigwood_key, not here).
    out = cli._upsert_sigwood_key(
        EXAMPLE_TEXT, "zeek_dir", None, fresh=True,
    )
    parsed = tomllib.loads(out)
    assert "zeek_dir" not in parsed["sigwood"]
    assert "# zeek_dir" in out


def test_upsert_none_fresh_commented_source_noop() -> None:
    # pihole_dir is shipped commented; value=None finds no active line → no-op.
    out = cli._upsert_sigwood_key(
        EXAMPLE_TEXT, "pihole_dir", None, fresh=True,
    )
    assert out == EXAMPLE_TEXT


@pytest.mark.parametrize("key", ["zeek_dir", "syslog_dir"])
def test_disable_sigwood_key_active_writes_empty_disabled(key: str) -> None:
    # A skipped active-default source is written explicit-empty so config fallback
    # cannot re-expose the shipped default and re-enable it.
    out = cli._disable_sigwood_key(EXAMPLE_TEXT, key)
    parsed = tomllib.loads(out)
    assert parsed["sigwood"][key] == ""
    assert '# disabled during setup' in out
    assert out.count(f"\n{key}") == 1  # exactly one active line, not commented


def test_disable_sigwood_key_commented_source_noop() -> None:
    # pihole_dir ships commented (no active line) → disable is a no-op.
    assert cli._disable_sigwood_key(EXAMPLE_TEXT, "pihole_dir") == EXAMPLE_TEXT


@pytest.mark.parametrize("key", ["zeek_dir", "syslog_dir"])
def test_apply_action_skip_disables_remove_comments(key: str) -> None:
    # Split-guard: a fresh/reset SKIP writes explicit-empty (disable), while REMOVE
    # of the same active source keeps commenting/revert-to-default. The two must
    # diverge so the unsettled remove-of-configured sibling is never swept into the
    # skip fix.
    skipped = cli._apply_action(EXAMPLE_TEXT, key, cli._SKIP, fresh=True)
    assert tomllib.loads(skipped)["sigwood"][key] == ""

    removed = cli._apply_action(EXAMPLE_TEXT, key, cli._REMOVE, fresh=True)
    assert key not in tomllib.loads(removed)["sigwood"]
    assert f"# {key}" in removed

    # A merge skip (fresh=False) never disables - it preserves a user value.
    assert cli._apply_action(EXAMPLE_TEXT, key, cli._SKIP, fresh=False) == EXAMPLE_TEXT


def test_upsert_existing_active_key_updated() -> None:
    base = "[sigwood]\nzeek_dir = \"/x\"\nsyslog_dir = \"/var/log\"\n"
    out = cli._upsert_sigwood_key(base, "zeek_dir", "/y", fresh=False)
    parsed = tomllib.loads(out)
    assert parsed["sigwood"]["zeek_dir"] == "/y"
    # syslog_dir line preserved byte-identical
    assert 'syslog_dir = "/var/log"' in out


def test_compound_system_keys_preserve_inline_comments_and_section_bounds() -> None:
    base = (
        '[sigwood]\n'
        'syslog_source = "files"  # operator mode\n'
        'syslog_dir = "/var/log"  # operator fallback\n'
        '[export.splunk]\n'
        'syslog_source = "outside"\n'
    )
    out = cli._apply_action(
        base, "syslog_source", cli._set("journal"), fresh=False,
    )
    out = cli._apply_action(
        out, "syslog_dir", cli._set("/srv/system"), fresh=False,
    )
    assert 'syslog_source = "journal"  # operator mode' in out
    assert 'syslog_dir = "/srv/system"  # operator fallback' in out
    assert '[export.splunk]\nsyslog_source = "outside"\n' in out


def test_upsert_existing_commented_key_uncommented() -> None:
    base = '[sigwood]\n# zeek_dir = "/x"\nsyslog_dir = "/var/log"\n'
    out = cli._upsert_sigwood_key(base, "zeek_dir", "/y", fresh=False)
    parsed = tomllib.loads(out)
    assert parsed["sigwood"]["zeek_dir"] == "/y"


def test_upsert_existing_without_key_inserted_inside_span() -> None:
    base = "[sigwood]\nsyslog_dir = \"/var/log\"\n[allowlist]\n"
    out = cli._upsert_sigwood_key(base, "zeek_dir", "/y", fresh=False)
    parsed = tomllib.loads(out)
    assert parsed["sigwood"]["zeek_dir"] == "/y"
    # inserted INSIDE [sigwood], not in [allowlist]
    pre_allowlist = out.split("[allowlist]")[0]
    assert "zeek_dir" in pre_allowlist


def test_upsert_existing_full_file_outside_span_byte_identical() -> None:
    other_blocks = (
        "[allowlist]\ndomain_patterns = [\"~/x.txt\"]\n"
        "\n[export.splunk]\nhost = \"192.0.2.20\"\n"
        "\n[detectors.beacon]\nthreshold = 0.99\n"
        "\n# narrative comment about something\n"
    )
    base = "[sigwood]\nzeek_dir = \"/x\"\n\n" + other_blocks
    out = cli._upsert_sigwood_key(base, "zeek_dir", "/y", fresh=False)
    # everything from [allowlist] onward is byte-identical
    idx_in = base.index("[allowlist]")
    idx_out = out.index("[allowlist]")
    assert base[idx_in:] == out[idx_out:]


def test_upsert_existing_skipped_strict_noop() -> None:
    base = "[sigwood]\nzeek_dir = \"/x\"\n[allowlist]\n"
    out = cli._upsert_sigwood_key(base, "zeek_dir", None, fresh=False)
    assert out == base


def test_upsert_section_bound_token_in_another_stanza_active() -> None:
    """A `zeek_dir =` line inside [export.cloudtrail] must NEVER be matched."""
    base = (
        "[sigwood]\nzeek_dir = \"/x\"\n"
        "\n[export.cloudtrail]\n"
        "zeek_dir = \"/sneaky-active\"\n"
        "# zeek_dir = \"/sneaky-comment\"\n"
        "root = \"/sneaky-root\"\n"
    )
    out = cli._upsert_sigwood_key(base, "zeek_dir", "/y", fresh=False)
    out = cli._upsert_sigwood_key(out, "root", "/new", fresh=False)
    # the [export.cloudtrail] block is byte-identical
    idx_in = base.index("[export.cloudtrail]")
    idx_out = out.index("[export.cloudtrail]")
    assert base[idx_in:] == out[idx_out:]
    # the [sigwood] keys updated
    parsed = tomllib.loads(out)
    assert parsed["sigwood"]["zeek_dir"] == "/y"
    assert parsed["sigwood"]["root"] == "/new"


def test_upsert_section_bound_subtable_boundary() -> None:
    """`[sigwood.foo]` ends the span - its zeek_dir is untouched."""
    base = (
        "[sigwood]\n"
        "[sigwood.foo]\n"
        "zeek_dir = \"/sub\"\n"
    )
    out = cli._upsert_sigwood_key(base, "zeek_dir", "/y", fresh=False)
    # sub-table zeek_dir intact
    assert 'zeek_dir = "/sub"' in out
    # new zeek_dir was written inside [sigwood] (before the sub-table)
    idx_main = out.index("[sigwood]\n")
    idx_sub = out.index("[sigwood.foo]")
    between = out[idx_main:idx_sub]
    assert 'zeek_dir = "/y"' in between


def test_init_writes_bak_on_existing_config_update(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    cfg_path = home / "config.toml"
    original = "[sigwood]\nroot = \"/data/sigwood\"\nzeek_dir = \"/x\"\n"
    cfg_path.write_text(original, encoding="utf-8")

    _stub_candidates(monkeypatch)  # nothing detected
    # An existing config routes to merge/reset. Inputs: merge (Enter), 4 source
    # prompts (all skip), root prompt (Enter keeps the set root), accept (Enter).
    # Merge has no location prompt and writes the .bak back to the found config.
    _stage_inputs(monkeypatch, ["", "", "", "", "", "", ""])

    cli._run_init([])

    bak = cfg_path.with_suffix(".toml.bak")
    assert bak.read_text(encoding="utf-8") == original


# ════════════════════════════════════════════════════════════════════════════
# 12-15. R1 root non-clobber - MERGE now MANAGES root via a presence-based
# prompt. Root state keys on KEY PRESENCE: a present value (incl. "") is kept on
# Enter; an absent root routes through the HOME MENU (Enter/'a' writes the default
# ~/.sigwood). Explicit root = "" must survive as a set value (the user chose CWD).
# ════════════════════════════════════════════════════════════════════════════


def _merge_skip_all(monkeypatch: pytest.MonkeyPatch) -> None:
    """Existing config → merge; skip/keep all four sources; Enter the root prompt
    and the accept gate. Root by presence: a SET value is kept on Enter; an UNSET
    root routes through the HOME MENU, whose Enter writes the default ~/.sigwood."""
    _stub_candidates(monkeypatch)
    # merge, zeek, pihole, syslog, cloudtrail, root, accept.
    _stage_inputs(monkeypatch, ["", "", "", "", "", "", ""])
    cli._run_init([])


def test_root_non_clobber_existing_value_preserved_on_merge(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    (home / "config.toml").write_text(
        "[sigwood]\nroot = \"/data/sigwood\"\n", encoding="utf-8",
    )
    _merge_skip_all(monkeypatch)
    parsed = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert parsed["sigwood"]["root"] == "/data/sigwood"


def test_root_non_clobber_missing_root_prompts_writes_default_on_merge(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """An UNSET root PROMPTS via the HOME MENU on a
    merge; its Enter writes the explicit default ~/.sigwood (does not preserve
    rootless)."""
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    (home / "config.toml").write_text(
        "[sigwood]\nzeek_dir = \"/x\"\n", encoding="utf-8",
    )
    _merge_skip_all(monkeypatch)
    parsed = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert parsed["sigwood"]["root"] == "~/.sigwood"


def test_root_non_clobber_existing_empty_preserved_on_merge(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Explicit `root = ""` survives a merge - the user chose CWD."""
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    (home / "config.toml").write_text(
        "[sigwood]\nroot = \"\"\n", encoding="utf-8",
    )
    _merge_skip_all(monkeypatch)
    parsed = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert parsed["sigwood"]["root"] == ""


def test_reset_config_regenerates_in_place_preserving_split_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """reset-config regenerates the DISCOVERED config in place (no location
    prompt) and PRESERVES the existing data root - config home and SIGWOOD_ROOT are
    separate knobs, so a split must not relocate config.toml or orphan it."""
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    data_root = tmp_path / "dataroot"   # root != config home (the split)
    (home / "config.toml").write_text(
        f"[sigwood]\nroot = \"{data_root}\"\n\n[detectors.beacon]\nthreshold = 0.99\n",
        encoding="utf-8",
    )
    _stub_candidates(monkeypatch)
    # reset, scope=config, typed `reset`, 4 sources skip, root Enter (keeps the
    # split root), accept Enter. NO location prompt.
    _stage_inputs(monkeypatch, ["r", "c", "reset", "", "", "", "", "", ""])
    cli._run_init([])

    parsed = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert parsed["sigwood"]["root"] == str(data_root)       # root preserved
    assert "threshold" not in parsed.get("detectors", {}).get("beacon", {})  # fresh
    assert (home / "config.toml.bak").exists()                 # in-place .bak
    assert not (data_root / "config.toml").exists()            # no orphan at data root


# ════════════════════════════════════════════════════════════════════════════
# 16-21. R5 _toml_str
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("value", [
    "/var/log/zeek",
    "/var/log/My Logs",            # space
    "/var/log/o'brien",            # single quote → basic
    "C:\\Logs",                    # backslash
    '/var/log/"weird"',            # double quote
])
def test_toml_str_roundtrips(value: str) -> None:
    rendered = cli._toml_str(value)
    parsed = tomllib.loads(f"x = {rendered}")
    assert parsed["x"] == value


def test_toml_str_single_quote_uses_basic_form() -> None:
    assert cli._toml_str("/var/log/o'brien").startswith('"')


def test_toml_str_always_double_quoted_basic_form() -> None:
    # Every value renders as a double-quoted BASIC string, matching the
    # shipped example/comments.
    assert cli._toml_str("/var/log/zeek") == '"/var/log/zeek"'


def test_toml_str_rejects_control_char() -> None:
    with pytest.raises(ValueError, match="control character"):
        cli._toml_str("/var/log/\n")


# ════════════════════════════════════════════════════════════════════════════
# 22-27. Profiler
# ════════════════════════════════════════════════════════════════════════════


def _make_file(path: Path, *, size: int = 8, mtime: float | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    if mtime is not None:
        import os
        os.utime(path, (mtime, mtime))


def test_profile_zeek_logs_two_families(tmp_path: Path) -> None:
    _make_file(tmp_path / "conn.log")
    _make_file(tmp_path / "dns.log")
    p = cli._profile_dir(str(tmp_path), cli._ZEEK_GLOBS, logs_label=None)
    assert p is not None
    assert p["logs"] == "conn + dns"


def test_profile_zeek_logs_three_families(tmp_path: Path) -> None:
    _make_file(tmp_path / "conn.log")
    _make_file(tmp_path / "dns.log")
    _make_file(tmp_path / "ssl.log")
    p = cli._profile_dir(str(tmp_path), cli._ZEEK_GLOBS, logs_label=None)
    assert p is not None
    assert p["logs"] == "conn, dns, ssl"


def test_profile_zeek_excludes_derived_siblings(tmp_path: Path) -> None:
    """The profiler counts primary Zeek logs only, matching the loader: a derived
    sibling adds neither its family to the headline nor its bytes to the size."""
    _make_file(tmp_path / "conn.log", size=8)
    _make_file(tmp_path / "conn-summary.2026-06-14.log.gz", size=100)
    _make_file(tmp_path / "dns-summary.2026-06-14.log.gz", size=4096)
    p = cli._profile_dir(str(tmp_path), cli._ZEEK_GLOBS, logs_label=None)
    assert p is not None
    assert p["logs"] == "conn"  # dns-summary is not the dns family
    assert p["size_bytes"] == 8  # the derived siblings' bytes are not counted


def test_profile_syslog_uses_loader_content_universe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Syslog detection/profile use the loader's accepted-file universe:
    RFC-3164 and ISO-8601 streams count; package logs and binaries do not."""
    d = tmp_path / "var-log"
    d.mkdir()
    messages = "May 31 12:00:00 host-a kernel: link up\n"
    secure = "<134>May 31 12:01:00 host-b sshd[100]: Accepted publickey for user\n"
    iso_syslog = (
        "2026-06-28T14:34:43.200533-05:00 host-c systemd[1]: Started x\n"
    )
    (d / "messages").write_text(messages, encoding="utf-8")
    (d / "secure").write_text(secure, encoding="utf-8")
    (d / "syslog").write_text(iso_syslog, encoding="utf-8")
    (d / "boot.log").write_text("[  OK  ] Started Some Service.\n", encoding="utf-8")
    (d / "dpkg.log").write_text(
        "2026-06-01 12:00:00 status installed placeholder\n",
        encoding="utf-8",
    )
    (d / "dnf.log").write_text(
        "2026-06-01T12:00:00+0000 INFO --- logging initialized ---\n",
        encoding="utf-8",
    )
    (d / "alternatives.log").write_text(
        "update-alternatives 2026-06-01 placeholder\n",
        encoding="utf-8",
    )
    (d / "btmp").write_bytes(b"\x00\x01\x02")

    monkeypatch.setattr(cli, "_SYSLOG_CANDIDATE", str(d))

    assert cli._detect_syslog() == str(d)
    profile = cli._profile_dir(
        str(d), (cli._SYSLOG_GLOB,), logs_label=None,
        head_sniff=cli._looks_like_syslog_head,
    )
    assert profile is not None
    assert profile["size_bytes"] == (
        len(messages.encode()) + len(secure.encode()) + len(iso_syslog.encode())
    )

    only_non_syslog = tmp_path / "only-non-syslog"
    only_non_syslog.mkdir()
    (only_non_syslog / "boot.log").write_text(
        "[  OK  ] Started Some Service.\n", encoding="utf-8",
    )
    (only_non_syslog / "dpkg.log").write_text(
        "2026-06-01 12:00:00 status installed placeholder\n",
        encoding="utf-8",
    )
    (only_non_syslog / "dnf.log").write_text(
        "2026-06-01T12:00:00+0000 INFO --- logging initialized ---\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "_SYSLOG_CANDIDATE", str(only_non_syslog))

    assert cli._detect_syslog() is None
    assert cli._profile_dir(
        str(only_non_syslog), (cli._SYSLOG_GLOB,), logs_label=None,
        head_sniff=cli._looks_like_syslog_head,
    ) is None


def test_detect_syslog_short_circuits_on_first_accepted_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Syslog detection stops at the first accepted regular file."""
    d = tmp_path / "var-log"
    d.mkdir()
    first = d / "00-messages"
    second = d / "99-extra"
    first.write_text("<134>May 31 12:00:00 host-a kernel: x\n", encoding="utf-8")
    second.write_text("<134>May 31 12:01:00 host-b kernel: y\n", encoding="utf-8")
    calls: list[str] = []

    def _sniff(path: Path) -> bool:
        calls.append(path.name)
        if path == second:
            raise AssertionError("detection must not sniff after the first hit")
        return True

    monkeypatch.setattr(cli, "_SYSLOG_CANDIDATE", str(d))
    monkeypatch.setattr(cli, "_looks_like_syslog_head", _sniff)

    assert cli._detect_syslog() == str(d)
    assert calls == [first.name]


def test_profile_human_bytes_kb(tmp_path: Path) -> None:
    _make_file(tmp_path / "conn.log", size=12 * 1024)
    p = cli._profile_dir(str(tmp_path), ("conn*.log*",), logs_label=None)
    assert p is not None
    assert p["size_str"] == "~12 KB"


def test_profile_human_bytes_mb_and_gb() -> None:
    assert cli._human_bytes(340 * 1024 ** 2) == "~340 MB"
    assert cli._human_bytes(6 * 1024 ** 3) == "~6 GB"


@pytest.mark.parametrize("delta,expected", [
    (timedelta(minutes=30), "updated just now"),
    (timedelta(hours=12),   "fresh today"),
    (timedelta(days=3),     "active this week"),
    (timedelta(days=10),    "last activity ~10 days ago"),
    (timedelta(days=45),    "but it looks stale - nothing new in ~6 weeks"),
    (timedelta(days=75),    "but it looks stale - nothing new in ~2 months"),
])
def test_fresh_bucket_boundaries(delta: timedelta, expected: str) -> None:
    assert cli._fresh_bucket(delta) == expected


def test_profile_bounded_cap(tmp_path: Path) -> None:
    # Synthesize one more than the cap, all matching conn*.log*. The
    # bounded flag must surface.
    for i in range(cli._PROFILE_FILE_CAP + 50):
        _make_file(tmp_path / f"conn.{i}.log")
    p = cli._profile_dir(str(tmp_path), ("conn*.log*",), logs_label=None)
    assert p is not None
    assert p["bounded"] is True


def test_profile_no_data_returns_none(tmp_path: Path) -> None:
    # Dir exists but no matching files.
    assert cli._profile_dir(str(tmp_path), ("conn*.log*",), logs_label=None) is None


def test_profile_dir_missing_returns_none(tmp_path: Path) -> None:
    assert cli._profile_dir(
        str(tmp_path / "missing"), ("conn*.log*",), logs_label=None,
    ) is None


def test_profile_permission_error_silently_handled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _make_file(tmp_path / "conn.log", size=8)

    real_stat = Path.stat
    def _fail_stat(self, *args, **kwargs):
        if self.name.startswith("conn"):
            raise PermissionError("simulated")
        return real_stat(self, *args, **kwargs)
    monkeypatch.setattr(Path, "stat", _fail_stat)

    # Whichever file errored is skipped; no other files → no-data return.
    result = cli._profile_dir(str(tmp_path), ("conn*.log*",), logs_label=None)
    assert result is None


def test_detect_zeek_permission_error_continues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A probe that raises PermissionError on glob falls through to the
    next candidate, not the CLI error boundary."""
    bad = tmp_path / "bad-zeek"
    good = tmp_path / "good-zeek"
    bad.mkdir()
    good.mkdir()
    _make_file(good / "conn.log")

    monkeypatch.setattr(cli, "_ZEEK_CANDIDATES", (str(bad), str(good)))

    real_glob = Path.glob
    def _conditional_glob(self, pattern, *args, **kwargs):
        if self == bad:
            raise PermissionError("simulated")
        return real_glob(self, pattern, *args, **kwargs)
    monkeypatch.setattr(Path, "glob", _conditional_glob)

    assert cli._detect_zeek() == str(good)


def test_detect_zeek_dated_tree_detects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dated zeekctl tree (logs only in YYYY-MM-DD subdirs, none at the top
    level) detects at the candidate root."""
    cand = tmp_path / "zeek"
    (cand / "2026-06-14").mkdir(parents=True)
    _make_file(cand / "2026-06-14" / "conn.00:00:00-01:00:00.log.gz")
    monkeypatch.setattr(cli, "_ZEEK_CANDIDATES", (str(cand),))
    assert cli._detect_zeek() == str(cand)


def test_detect_zeek_dated_conn_only_in_current_spool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Under dated layout the conn tier probes every child dir - a conn hit in
    the current/ spool wins even when the date dirs carry none."""
    cand = tmp_path / "zeek"
    (cand / "2026-06-14").mkdir(parents=True)
    _make_file(cand / "2026-06-14" / "dns.log.gz")
    (cand / "current").mkdir()
    _make_file(cand / "current" / "conn.log")
    monkeypatch.setattr(cli, "_ZEEK_CANDIDATES", (str(cand),))
    assert cli._detect_zeek() == str(cand)


def test_detect_zeek_dated_symlinked_spool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A symlinked current/ spool is traversed: glob("*/…") follows symlinked
    child dirs, and an empty date dir classifies the layout by name alone -
    both mirroring the loader."""
    cand = tmp_path / "zeek"
    (cand / "2026-06-14").mkdir(parents=True)
    spool = tmp_path / "spool"
    spool.mkdir()
    _make_file(spool / "conn.log")
    (cand / "current").symlink_to(spool)
    monkeypatch.setattr(cli, "_ZEEK_CANDIDATES", (str(cand),))
    assert cli._detect_zeek() == str(cand)


def test_detect_zeek_subdir_conn_without_date_sibling_is_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Loader parity: without a date-named sibling the tree is FLAT - the
    loader reads only the top level and would load zero from these roots, so
    detection must not advertise them on subdir contents."""
    spool_only = tmp_path / "spool-only"
    (spool_only / "current").mkdir(parents=True)
    _make_file(spool_only / "current" / "conn.log")
    monkeypatch.setattr(cli, "_ZEEK_CANDIDATES", (str(spool_only),))
    assert cli._detect_zeek() is None

    archive_only = tmp_path / "archive-only"
    (archive_only / "old").mkdir(parents=True)
    _make_file(archive_only / "old" / "conn.log")
    monkeypatch.setattr(cli, "_ZEEK_CANDIDATES", (str(archive_only),))
    assert cli._detect_zeek() is None


def test_detect_zeek_dated_fallback_tier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dated tree with logs but no conn anywhere lands on the fallback tier
    at the dated depth."""
    cand = tmp_path / "zeek"
    (cand / "2026-06-14").mkdir(parents=True)
    _make_file(cand / "2026-06-14" / "dns.log.gz")
    monkeypatch.setattr(cli, "_ZEEK_CANDIDATES", (str(cand),))
    assert cli._detect_zeek() == str(cand)


def test_detect_zeek_dated_conn_beats_earlier_dated_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A later candidate's conn-tier hit outranks an earlier candidate's
    fallback-tier hit - precedence matches the flat rule."""
    a = tmp_path / "zeek-a"
    (a / "2026-06-14").mkdir(parents=True)
    _make_file(a / "2026-06-14" / "dns.log.gz")
    b = tmp_path / "zeek-b"
    (b / "2026-06-14").mkdir(parents=True)
    _make_file(b / "2026-06-14" / "conn.log.gz")
    monkeypatch.setattr(cli, "_ZEEK_CANDIDATES", (str(a), str(b)))
    assert cli._detect_zeek() == str(b)


def test_detect_zeek_flat_conn_summary_only_not_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A flat dir holding only a derived conn-summary is not a Zeek root: the conn
    tier and the primary-family fallback both reject it (the loader would load
    nothing there)."""
    cand = tmp_path / "zeek"
    cand.mkdir()
    _make_file(cand / "conn-summary.2026-06-14.log.gz")
    monkeypatch.setattr(cli, "_ZEEK_CANDIDATES", (str(cand),))
    assert cli._detect_zeek() is None


def test_detect_zeek_dated_conn_summary_only_not_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dated tree whose only log is a derived conn-summary does not detect."""
    cand = tmp_path / "zeek"
    (cand / "2026-06-14").mkdir(parents=True)
    _make_file(cand / "2026-06-14" / "conn-summary.2026-06-14.log.gz")
    monkeypatch.setattr(cli, "_ZEEK_CANDIDATES", (str(cand),))
    assert cli._detect_zeek() is None


def test_detect_zeek_flat_conn_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A flat dir with a real conn.log detects at the candidate root."""
    cand = tmp_path / "zeek"
    cand.mkdir()
    _make_file(cand / "conn.log")
    monkeypatch.setattr(cli, "_ZEEK_CANDIDATES", (str(cand),))
    assert cli._detect_zeek() == str(cand)


def test_detect_zeek_flat_dns_only_detected_via_primary_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A flat dir with a real dns.log (no conn) detects via the primary
    Zeek-family fallback - the rule rejects derived siblings, not real primaries."""
    cand = tmp_path / "zeek"
    cand.mkdir()
    _make_file(cand / "dns.log")
    monkeypatch.setattr(cli, "_ZEEK_CANDIDATES", (str(cand),))
    assert cli._detect_zeek() == str(cand)


def test_detect_zeek_flat_syslog_only_detected_via_primary_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A flat dir with only Zeek's syslog.log detects as Zeek - the syslog detector
    consumes `zeek_dir: syslog*.log*`, so the primary-family fallback must include it."""
    cand = tmp_path / "zeek"
    cand.mkdir()
    _make_file(cand / "syslog.log")
    monkeypatch.setattr(cli, "_ZEEK_CANDIDATES", (str(cand),))
    assert cli._detect_zeek() == str(cand)


def test_zeek_date_regex_mirrors_loader_pattern() -> None:
    """Drift tripwire: the wizard's date-dir pattern must equal the loader's
    (cli_init mirrors the string - it cannot import the loader itself)."""
    from sigwood.common.loader import discovery
    assert cli._ZEEK_DATE_DIR_RE.pattern == discovery._DATE_DIR_RE.pattern


def test_is_primary_zeek_name_mirrors_loader() -> None:
    """Drift tripwire: the wizard's primary-log-name rule must agree with the
    loader's on a shared sample set (cli_init mirrors the rule - it cannot import
    the loader itself)."""
    from sigwood.common.loader import discovery
    samples = [
        ("conn.log", "conn*.log*"),
        ("conn.2026-06-14.log.gz", "conn*.log*"),
        ("conn-summary.2026-06-14.log.gz", "conn*.log*"),
        ("conn_history.log", "conn*.log*"),
        ("dns.log", "dns*.log*"),
        ("dns-summary.log", "dns*.log*"),
        ("syslog.log", "syslog*.log*"),
        ("anything.log", "*.log*"),
    ]
    for name, pattern in samples:
        assert cli._is_primary_zeek_name(name, pattern) == (
            discovery._is_primary_zeek_name(name, pattern)
        ), (name, pattern)


def test_looks_like_syslog_head_mirrors_loader(tmp_path: Path) -> None:
    """Drift tripwire: the wizard's syslog head sniff agrees with the loader
    gate over text, compressed rotations, dnsmasq-bearing syslog, and negatives."""
    from sigwood.common.loader.sniff import _looks_like_syslog

    samples: list[Path] = []

    def _text(name: str, content: str) -> None:
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        samples.append(path)

    _text("messages", "May 31 12:00:00 host-a kernel: link up\n")
    _text(
        "dnsmasq.log",
        "<30>May 31 12:00:00 host-a dnsmasq[1]: query[A] example.test from 192.0.2.10\n",
    )
    _text(
        "syslog-iso-colon",
        "2026-06-28T14:34:43.200533-05:00 host-a systemd[1]: Started x\n",
    )
    _text(
        "syslog-iso-no-colon",
        "2026-07-15T17:04:24.321412-0500 host-a sshd[1]: session opened\n",
    )
    _text("boot.log", "[  OK  ] Started Some Service.\n")
    _text("dpkg.log", "2026-06-01 12:00:00 status installed placeholder\n")
    _text(
        "dnf.log",
        "2026-06-01T12:00:00+0000 INFO --- logging initialized ---\n",
    )
    _text(
        "embedded-colon.log",
        "2026-06-28T14:34:43-05:00 host-a key:value pair\n",
    )
    _text("alternatives.log", "update-alternatives 2026-06-01 placeholder\n")
    binary = tmp_path / "btmp"
    binary.write_bytes(b"\x00\x01\x02")
    samples.append(binary)

    gz = tmp_path / "messages.1.gz"
    with gzip.open(gz, "wt", encoding="utf-8") as fh:
        fh.write("<134>May 31 12:00:00 host-a kernel: rotated\n")
    samples.append(gz)

    bz = tmp_path / "messages.2.bz2"
    with bz2.open(bz, "wt", encoding="utf-8") as fh:
        fh.write("<134>May 31 12:00:00 host-a kernel: bz rotated\n")
    samples.append(bz)

    for sample in samples:
        assert cli._looks_like_syslog_head(sample) == _looks_like_syslog(sample), sample


def test_detect_zeek_mixed_root_files_ignored_under_dated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mixed-root parity: a date-named child makes the tree dated, and the
    loader then ignores root-level files - so a root conn.log (also a *.log*)
    must count for neither the conn tier nor the fallback tier."""
    cand = tmp_path / "zeek"
    (cand / "2026-06-14").mkdir(parents=True)
    _make_file(cand / "conn.log")
    monkeypatch.setattr(cli, "_ZEEK_CANDIDATES", (str(cand),))
    assert cli._detect_zeek() is None


# ════════════════════════════════════════════════════════════════════════════
# 28-34. Flow tests - drive _run_init end-to-end
# ════════════════════════════════════════════════════════════════════════════


def _setup_zeek_dir(tmp_path: Path) -> str:
    d = tmp_path / "fake-zeek"
    d.mkdir()
    _make_file(d / "conn.log")
    _make_file(d / "dns.log")
    return str(d)


def _setup_pihole(tmp_path: Path) -> tuple[str, tuple[tuple[str, str], ...]]:
    d = tmp_path / "fake-pihole"
    d.mkdir()
    _make_file(d / "pihole.log")
    return (str(d), ((str(d / "pihole.log"), str(d)),))


def _setup_syslog(tmp_path: Path) -> str:
    d = tmp_path / "fake-var-log"
    d.mkdir()
    (d / "messages").write_text(
        "<134>May 31 12:00:00 host-a kernel: link up\n",
        encoding="utf-8",
    )
    return str(d)


def test_flow_all_found_all_accepted_root_enter(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    zeek = _setup_zeek_dir(tmp_path)
    pihole_dir, pihole_candidates = _setup_pihole(tmp_path)
    syslog = _setup_syslog(tmp_path)
    _stub_candidates(monkeypatch, zeek=(zeek,), pihole=pihole_candidates, syslog=syslog)
    # zeek/pihole/syslog (Enter-keep), cloudtrail (Enter-skip), location Enter
    # (~/.sigwood - the home IS the root, asked once), accept Enter.
    _stage_inputs(monkeypatch, ["", "", "", "", "", ""])

    cli._run_init([])

    parsed = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert parsed["sigwood"]["root"] == "~/.sigwood"
    assert parsed["sigwood"]["zeek_dir"] == zeek
    assert parsed["sigwood"]["pihole_dir"] == pihole_dir
    assert parsed["sigwood"]["syslog_source"] == "files"
    assert parsed["sigwood"]["syslog_dir"] == syslog
    assert "cloudtrail_dir" not in parsed["sigwood"]  # skipped → commented


def test_flow_dated_zeek_detected_writes_candidate_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A dated zeekctl tree renders the DETECTED prompt variant, and accepting
    writes zeek_dir as the candidate ROOT - not the date child or the spool."""
    home = _isolated_home(monkeypatch, tmp_path)
    cand = tmp_path / "fake-zeek"
    (cand / "2026-06-14").mkdir(parents=True)
    _make_file(cand / "2026-06-14" / "conn.00:00:00-01:00:00.log.gz")
    (cand / "current").mkdir()
    _make_file(cand / "current" / "conn.log")
    _stub_candidates(monkeypatch, zeek=(str(cand),))
    # zeek (Enter-use), pihole/syslog/cloudtrail (Enter-skip), location Enter
    # (~/.sigwood), accept Enter.
    _stage_inputs(monkeypatch, ["", "", "", "", "", ""])

    cli._run_init([])

    out = capsys.readouterr().out
    assert "[Enter to use it  ·  type a path  ·  - to skip]" in out
    parsed = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert parsed["sigwood"]["zeek_dir"] == str(cand)


def test_flow_typed_pihole_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    zeek = _setup_zeek_dir(tmp_path)
    _, pihole_candidates = _setup_pihole(tmp_path)
    syslog = _setup_syslog(tmp_path)
    _stub_candidates(monkeypatch, zeek=(zeek,), pihole=pihole_candidates, syslog=syslog)
    # zeek Enter, pihole typed (absolute → stored as-is), syslog Enter, cloudtrail
    # skip, location Enter, accept Enter.
    _stage_inputs(monkeypatch, ["", "/custom/pihole", "", "", "", ""])

    cli._run_init([])
    parsed = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert parsed["sigwood"]["pihole_dir"] == "/custom/pihole"


def test_flow_pihole_not_found_typed_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    zeek = _setup_zeek_dir(tmp_path)
    syslog = _setup_syslog(tmp_path)
    _stub_candidates(monkeypatch, zeek=(zeek,), pihole=(), syslog=syslog)
    # zeek Enter, pihole not-found→typed, syslog Enter, cloudtrail skip, location
    # Enter, accept Enter.
    _stage_inputs(monkeypatch, ["", "/somewhere/pihole", "", "", "", ""])

    cli._run_init([])
    parsed = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert parsed["sigwood"]["pihole_dir"] == "/somewhere/pihole"


def test_flow_summary_redo_rebuilds_answers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    zeek = _setup_zeek_dir(tmp_path)
    _, pihole_candidates = _setup_pihole(tmp_path)
    syslog = _setup_syslog(tmp_path)
    _stub_candidates(monkeypatch, zeek=(zeek,), pihole=pihole_candidates, syslog=syslog)
    probes = iter(
        [
            _journal_result(cli.journal_probe.JournalProbeCode.EXECUTABLE_MISSING),
            _journal_result(cli.journal_probe.JournalProbeCode.READY),
        ]
    )
    monkeypatch.setattr(cli.journal_probe, "probe_journal", lambda: next(probes))
    # Redo discards pass-1 answers. Pass 1: zeek → type a sentinel path (the
    # would-be leak), pihole/syslog keep, cloudtrail skip, location Enter, redo.
    # Pass 2: keep zeek/pihole/syslog (Enter), skip cloudtrail, location, accept.
    _stage_inputs(monkeypatch, [
        "/stale/leak", "", "", "", "", "r",
        "", "", "", "", "", "",
    ])

    cli._run_init([])
    parsed = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert parsed["sigwood"]["zeek_dir"] == zeek   # pass-1 /stale/leak discarded
    assert parsed["sigwood"]["pihole_dir"] != ""  # set
    assert parsed["sigwood"]["syslog_source"] == "auto"
    assert parsed["sigwood"]["syslog_dir"] == syslog


def test_flow_all_skipped_proceeds_no_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    zeek = _setup_zeek_dir(tmp_path)
    _, pihole_candidates = _setup_pihole(tmp_path)
    syslog = _setup_syslog(tmp_path)
    _stub_candidates(monkeypatch, zeek=(zeek,), pihole=pihole_candidates, syslog=syslog)
    # Skip all four with the `-` drop sentinel (zeek/pihole/syslog detected,
    # cloudtrail nothing), location Enter, accept Enter. No gate.
    _stage_inputs(monkeypatch, ["-", "-", "-", "-", "", ""])

    cli._run_init([])
    parsed = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    # Fresh-from-example: skipping an ACTIVE default (zeek_dir/syslog_dir) writes an
    # explicit empty so config fallback can't re-enable it; a COMMENTED source
    # (pihole_dir/cloudtrail_dir) stays absent. All four resolve off.
    assert parsed["sigwood"]["zeek_dir"] == ""
    assert parsed["sigwood"]["syslog_source"] == "off"
    assert parsed["sigwood"]["syslog_dir"] == ""
    assert "pihole_dir" not in parsed["sigwood"]
    assert "cloudtrail_dir" not in parsed["sigwood"]


@pytest.mark.parametrize("key", ["zeek_dir", "syslog_dir"])
def test_fresh_skip_writes_explicit_empty_so_fallback_stays_disabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, key: str,
) -> None:
    """A fresh init that skips an active-default source disables it end-to-end: the
    written config loads and resolve_sources returns [] for that family, NOT the
    shipped default path a plain comment would re-expose."""
    from sigwood.common import config as cfg
    from sigwood.common.sources import resolve_sources

    home = _isolated_home(monkeypatch, tmp_path)
    zeek = _setup_zeek_dir(tmp_path)
    _, pihole_candidates = _setup_pihole(tmp_path)
    syslog = _setup_syslog(tmp_path)
    _stub_candidates(monkeypatch, zeek=(zeek,), pihole=pihole_candidates, syslog=syslog)
    _stage_inputs(monkeypatch, ["-", "-", "-", "-", "", ""])
    cli._run_init([])

    config = cfg.load(str(home / "config.toml"))
    resolved = resolve_sources(
        config,
        overrides={k: None for k in ("zeek_dir", "syslog_dir", "pihole_dir", "cloudtrail_dir")},
        scope=None,
    )
    assert getattr(resolved, key) == []


def test_fresh_skip_summary_reads_skipped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    """A fresh-skip reads `skipped` in the change summary (an intentional disable),
    not the ambiguous `(not set)`."""
    home = _isolated_home(monkeypatch, tmp_path)
    zeek = _setup_zeek_dir(tmp_path)
    _, pihole_candidates = _setup_pihole(tmp_path)
    syslog = _setup_syslog(tmp_path)
    _stub_candidates(monkeypatch, zeek=(zeek,), pihole=pihole_candidates, syslog=syslog)
    _stage_inputs(monkeypatch, ["-", "-", "-", "-", "", ""])
    cli._run_init([])
    out = capsys.readouterr().out
    assert re.search(r'zeek_dir\s+-\s+skipped', out)


def test_flow_reinit_preserves_custom_root_and_other_stanzas(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    existing = (
        "[sigwood]\nroot = \"/data/sigwood\"\nzeek_dir = \"/old/zeek\"\n"
        "\n[detectors.beacon]\nthreshold = 0.99\n"
    )
    (home / "config.toml").write_text(existing, encoding="utf-8")

    zeek = _setup_zeek_dir(tmp_path)
    _, pihole_candidates = _setup_pihole(tmp_path)
    syslog = _setup_syslog(tmp_path)
    _stub_candidates(monkeypatch, zeek=(zeek,), pihole=pihole_candidates, syslog=syslog)
    # Existing config → merge. merge; CONFIGURED zeek_dir → TYPE the new path to
    # update; pihole/syslog are unconfigured → Enter accepts the detected dirs;
    # cloudtrail skip; root Enter (keeps /data/sigwood); accept. No location prompt.
    _stage_inputs(monkeypatch, ["", zeek, "", "", "", "", ""])

    cli._run_init([])

    out = (home / "config.toml").read_text(encoding="utf-8")
    parsed = tomllib.loads(out)
    assert parsed["sigwood"]["root"] == "/data/sigwood"   # merge preserves root
    assert parsed["sigwood"]["zeek_dir"] == zeek       # dirs updated
    # the detectors stanza survives byte-identical
    assert "[detectors.beacon]\nthreshold = 0.99" in out
    # .bak exists with the original bytes
    assert (home / "config.toml.bak").read_text(encoding="utf-8") == existing


def test_flow_reinit_with_empty_root_preserved(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    (home / "config.toml").write_text(
        "[sigwood]\nroot = \"\"\n", encoding="utf-8",
    )
    _stub_candidates(monkeypatch)
    # merge, 4 sources skip, root Enter (explicit "" is a SET value, kept on
    # Enter - presence-based), accept. The user chose CWD; it must survive.
    _stage_inputs(monkeypatch, ["", "", "", "", "", "", ""])

    cli._run_init([])
    parsed = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert parsed["sigwood"]["root"] == ""


# ════════════════════════════════════════════════════════════════════════════
# 35. Verbatim line discipline
# ════════════════════════════════════════════════════════════════════════════


def test_verbatim_zeek_not_found_block(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    _isolated_home(monkeypatch, tmp_path)
    _stub_candidates(monkeypatch)
    # fresh: 4 sources skip, location Enter, accept Enter.
    _stage_inputs(monkeypatch, ["", "", "", "", "", ""])
    cli._run_init([])
    out = capsys.readouterr().out
    # The nothing-state nudge voice is preserved (only the footer is uniform).
    assert "Didn't find Zeek. You might like it: https://zeek.org" in out
    assert "If it's just hiding, tell me where." in out
    assert "[Enter to skip  ·  type a path]" in out


def test_verbatim_summary_advisory_and_confirm_blocks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    _stub_candidates(monkeypatch)
    # fresh: 4 sources skip, location Enter, accept Enter.
    _stage_inputs(monkeypatch, ["", "", "", "", "", ""])
    cli._run_init([])
    out = capsys.readouterr().out
    # The at-least-one gate is replaced by the no-source advisory in the summary.
    assert "About to write" in out
    assert "No sources set - sigwood will need files on the command line." in out
    assert "[Enter] accept  ·  [r] redo  ·  [a] abort" in out
    assert f"Done - settings written to {home / 'config.toml'}." in out
    assert "(none - pass files on the command line)" in out
    assert "data:     ~/.sigwood" in out
    assert "Good hunting!" in out
    # Confirm block has exactly one blank line between data line and docs URL.
    confirm_idx = out.index("Done - settings written")
    confirm_tail = out[confirm_idx:]
    lines = confirm_tail.splitlines()
    data_line_idx = next(i for i, line in enumerate(lines) if line.startswith("  data:"))
    assert lines[data_line_idx + 1] == ""
    assert lines[data_line_idx + 2].startswith("sigwood documentation lives here:")


def test_verbatim_detected_no_profile_single_line_headline(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """A detected source with no profile data renders the uniform single-line
    headline `Found <Source> at <path> - nothing there now. Use it?` (same
    fallback as configured - no assumed profile)."""
    _stage_inputs(monkeypatch, [""])  # Enter to use it (keep)
    action = cli._prompt_source(
        "Zeek", None, "/some/zeek", None, ("nudge",),
    )
    out = capsys.readouterr().out
    assert "Found Zeek at /some/zeek - nothing there now. Use it?" in out
    assert "Found Zeek at /some/zeek.\nUse it?" not in out
    assert action == cli._set("/some/zeek")


def test_verbatim_profiled_headline_uniform_single_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """The profiled headline folds the rich path into the uniform one-line
    grammar: `Found <Source> at <path> - <profile>. Use it?`."""
    profile = {
        "logs": "conn + dns", "size_str": "~12 KB",
        "fresh_str": "fresh today", "bounded": False, "size_bytes": 12_288,
    }
    _stage_inputs(monkeypatch, [""])
    cli._prompt_source("Zeek", None, "/some/zeek", profile, ("nudge",))
    out = capsys.readouterr().out
    assert "Found Zeek at /some/zeek - conn + dns, ~12 KB, fresh today. Use it?" in out


# ════════════════════════════════════════════════════════════════════════════
# Regression: upsert duplicate-key + .bak byte preservation
# ════════════════════════════════════════════════════════════════════════════


def test_upsert_active_wins_over_preceding_commented_sample() -> None:
    """A commented sample BEFORE an active value must not be uncommented -
    the active line is the one rewritten. Else we produce duplicate keys."""
    base = (
        "[sigwood]\n"
        "# zeek_dir = \"/default\"\n"
        "zeek_dir = \"/custom\"\n"
    )
    out = cli._upsert_sigwood_key(base, "zeek_dir", "/y", fresh=False)
    # the active line was rewritten (double-quoted basic form)
    assert 'zeek_dir = "/y"' in out
    # the commented sample is byte-preserved
    assert '# zeek_dir = "/default"' in out
    # produced TOML still parses (no duplicate keys)
    parsed = tomllib.loads(out)
    assert parsed["sigwood"]["zeek_dir"] == "/y"


def test_bak_byte_identical_for_crlf_existing_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """A user config with Windows line endings must round-trip through .bak
    byte-identical; the non-clobber promise covers CRLF callers too."""
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    cfg_path = home / "config.toml"
    # CRLF throughout; deliberate non-managed stanza we'll inspect after write.
    original_bytes = (
        b"[sigwood]\r\n"
        b"root = \"/data/sigwood\"\r\n"
        b"\r\n"
        b"[detectors.beacon]\r\n"
        b"threshold = 0.99\r\n"
    )
    cfg_path.write_bytes(original_bytes)

    _stub_candidates(monkeypatch)
    # Existing config → merge: merge, 4 sources skip, root Enter (keeps /data/sigwood),
    # accept Enter.
    _stage_inputs(monkeypatch, ["", "", "", "", "", "", ""])
    cli._run_init([])

    bak = cfg_path.with_suffix(".toml.bak")
    assert bak.read_bytes() == original_bytes
    # The untouched detectors stanza retains CRLF in the rewritten file.
    rewritten = cfg_path.read_bytes()
    assert b"[detectors.beacon]\r\nthreshold = 0.99\r\n" in rewritten


def test_no_traceback_on_corrupt_existing_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    (home / "config.toml").write_text("not = valid = toml = at = all", encoding="utf-8")
    _stub_candidates(monkeypatch)
    _stage_inputs(monkeypatch, [""])

    with pytest.raises(ValueError, match="existing config at"):
        cli._run_init([])


# ════════════════════════════════════════════════════════════════════════════
# init v2 - merge/reset · cloudtrail · seeding · location/discovery/shadow
# ════════════════════════════════════════════════════════════════════════════


def test_search_homes_mirror_cfg_search_paths() -> None:
    """Drift tripwire: cli_init's call-time home list must mirror the parents of
    cfg.SEARCH_PATHS (the discovery source of truth)."""
    from sigwood.common import config as cfg
    expected = tuple(str(p.parent) for p in cfg.SEARCH_PATHS)
    actual = tuple(str(Path(h).expanduser()) for h in cli._SEARCH_HOMES)
    assert actual == expected


def test_merge_keeps_export_stanza_and_tuning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    existing = (
        "[sigwood]\nroot = \"/data/sigwood\"\nzeek_dir = \"/old\"\n\n"
        "[detectors.beacon]\nthreshold = 0.99\n\n"
        "[export.cloudtrail]\npath = \"s3://example-bucket/prefix\"\n"
    )
    (home / "config.toml").write_text(existing, encoding="utf-8")
    zeek = _setup_zeek_dir(tmp_path)
    _stub_candidates(monkeypatch, zeek=(zeek,))
    # merge: a CONFIGURED zeek_dir shows the configured state (not re-detected) -
    # TYPE the new path to update it; pihole/syslog/cloudtrail skip; root Enter
    # (keep /data/sigwood); accept.
    _stage_inputs(monkeypatch, ["", zeek, "", "", "", "", ""])

    cli._run_init([])

    out = (home / "config.toml").read_text(encoding="utf-8")
    parsed = tomllib.loads(out)
    assert parsed["sigwood"]["zeek_dir"] == zeek           # dir updated
    assert "[detectors.beacon]\nthreshold = 0.99" in out      # tuning verbatim
    assert '[export.cloudtrail]\npath = "s3://example-bucket/prefix"' in out
    assert (home / "config.toml.bak").read_text(encoding="utf-8") == existing


def test_reset_config_regenerates_fresh_preserves_data_dirs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    original = "[sigwood]\nroot = \"~/.sigwood\"\n\n[detectors.beacon]\nthreshold = 0.99\n"
    (home / "config.toml").write_text(original, encoding="utf-8")
    (home / "exports").mkdir()
    (home / "exports" / "keep.log").write_text("x", encoding="utf-8")

    _stub_candidates(monkeypatch)
    # reset, scope=config, typed confirm, 4 sources skip, root Enter (keep set
    # root), accept Enter. NO location prompt in the reset path.
    _stage_inputs(monkeypatch, ["r", "c", "reset", "", "", "", "", "", ""])
    cli._run_init([])

    out = (home / "config.toml").read_text(encoding="utf-8")
    assert "threshold = 0.99" not in out                       # regenerated fresh
    assert (home / "config.toml.bak").read_text(encoding="utf-8") == original
    assert (home / "exports" / "keep.log").exists()            # data dir untouched


def test_reset_allowlist_removes_dropins_reseeds_preserves(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    (home / "config.toml").write_text("[sigwood]\nroot = \"~/.sigwood\"\n", encoding="utf-8")
    ad = home / "allowlist.d"
    ad.mkdir()
    (ad / "domains_extra").write_text("x.example.com\n", encoding="utf-8")
    (ad / "connections_local").write_text("192.0.2.1\n", encoding="utf-8")
    (ad / "hosts_lab").write_text("lab-*\n", encoding="utf-8")
    (ad / "keep.toml").write_text("[[allowlist.entry]]\nmatch = 'example.com'\n", encoding="utf-8")
    (ad / "notes.txt").write_text("personal notes\n", encoding="utf-8")
    (home / "exports").mkdir()
    (home / "exports" / "k").write_text("x", encoding="utf-8")

    _stub_candidates(monkeypatch)
    _stage_inputs(monkeypatch, ["r", "a", "reset"])
    cli._run_init([])

    assert not (ad / "domains_extra").exists()             # drop-in removed
    assert not (ad / "connections_local").exists()
    assert not (ad / "hosts_lab").exists()
    assert (ad / "domains_user").exists()                  # re-seeded blank
    assert (ad / "connections").exists()
    assert (ad / "hosts").exists()
    assert (ad / "keep.toml").exists()                         # stanza preserved
    assert (ad / "notes.txt").exists()                         # unrecognized preserved
    assert (home / "exports" / "k").exists()                   # data dir untouched


def test_reset_typed_confirmation_required(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    (home / "config.toml").write_text("[sigwood]\nroot = \"~/.sigwood\"\n", encoding="utf-8")
    ad = home / "allowlist.d"
    ad.mkdir()
    (ad / "domains_extra").write_text("x.example.com\n", encoding="utf-8")

    _stub_candidates(monkeypatch)
    _stage_inputs(monkeypatch, ["r", "a", "nope"])
    cli._run_init([])

    assert (ad / "domains_extra").exists()                 # NOT deleted
    assert "Aborted" in capsys.readouterr().out


def test_cloudtrail_typed_path_and_only_proceeds_no_gate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    _stub_candidates(monkeypatch)  # nothing detected
    # zeek/pihole/syslog skip, cloudtrail typed (absolute), location, accept.
    _stage_inputs(monkeypatch, ["", "", "", "/srv/ct", "", ""])
    cli._run_init([])

    parsed = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert parsed["sigwood"]["cloudtrail_dir"] == "/srv/ct"
    # A CloudTrail-only operator triggers no missing-source advisory.
    assert "No sources set" not in capsys.readouterr().out


def test_fresh_seeds_allowlist_d(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    _stub_candidates(monkeypatch)
    # 4 sources skip, location Enter, accept.
    _stage_inputs(monkeypatch, ["", "", "", "", "", ""])
    cli._run_init([])

    ad = home / "allowlist.d"
    assert (ad / "domains_user").exists()              # seeded
    assert (ad / "connections").exists()
    assert (ad / "hosts").exists()
    assert not (ad / "domains_common").exists()        # curated NOT copied


def test_allowlist_seed_is_idempotent_for_hosts(tmp_path: Path) -> None:
    allowlist_d = tmp_path / "allowlist.d"
    cli._seed_allowlist_d(allowlist_d)
    hosts = allowlist_d / "hosts"
    hosts.write_text("lab-*\n", encoding="utf-8")

    cli._seed_allowlist_d(allowlist_d)
    assert hosts.read_text(encoding="utf-8") == "lab-*\n"


def test_custom_home_redetect_discards_stale_source_answers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Typing a custom home whose config exists DISCARDS the pre-location source
    answers and re-enters merge/reset - the stale answers must not modify it."""
    monkeypatch.setattr(cli, "_SEARCH_HOMES", (str(tmp_path / "uh"), str(tmp_path / "sh")))
    custom = tmp_path / "custom"
    custom.mkdir()
    (custom / "config.toml").write_text(
        "[sigwood]\nzeek_dir = \"/orig/zeek\"\n", encoding="utf-8",
    )
    _stub_candidates(monkeypatch)  # nothing detected → fresh flow
    # Fresh sources: zeek TYPED /stale/zeek (the would-be leak), others skip;
    # location = custom home → REDIRECT (terminal, before any root/summary) →
    # merge → keep/skip all sources → root → accept.
    _stage_inputs(monkeypatch, [
        "/stale/zeek", "", "", "", str(custom),     # fresh source pass + location
        "", "", "", "", "", "", "",                  # merge, 4 sources, root, accept
    ])
    cli._run_init([])

    parsed = tomllib.loads((custom / "config.toml").read_text(encoding="utf-8"))
    assert parsed["sigwood"]["zeek_dir"] == "/orig/zeek"   # stale answer dropped


def test_custom_home_no_config_writes_fresh_with_disclosure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "_SEARCH_HOMES", (str(tmp_path / "uh"), str(tmp_path / "sh")))
    custom = tmp_path / "custom"
    _stub_candidates(monkeypatch)
    # 4 sources skip, location = custom (no config → fresh + disclosure), accept.
    _stage_inputs(monkeypatch, ["", "", "", "", str(custom), ""])
    cli._run_init([])

    assert (custom / "config.toml").exists()
    assert f"--config={custom}/config.toml" in capsys.readouterr().out


def test_preflight_shadow_refusal_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """The fresh-flow location preflight REFUSES a /etc home while a higher-
    priority user-home config exists, and the shadow check returns BEFORE any
    mkdir - so a refusal leaves no partial home. (Reset does not prompt for a
    location, so this guard is exercised at the helper.)"""
    user_home = tmp_path / "uh"
    sys_home = tmp_path / "sh"
    user_home.mkdir()
    (user_home / "config.toml").write_text("[sigwood]\nroot = \"~/.sigwood\"\n", encoding="utf-8")
    monkeypatch.setattr(cli, "_SEARCH_HOMES", (str(user_home), str(sys_home)))

    reason = cli._preflight(sys_home)
    assert reason is not None and "would shadow" in reason
    assert not sys_home.exists()                              # no partial home

    # The reverse (user home chosen while /etc exists) is the intended override.
    assert cli._shadow_refusal(user_home) is None


def test_writability_error_leaves_no_partial_home(tmp_path: Path) -> None:
    """A home under a non-directory path fails the writability probe with an
    actionable message and creates nothing."""
    blocker = tmp_path / "afile"
    blocker.write_text("x", encoding="utf-8")
    home = blocker / "sub"                                    # parent is a file
    reason = cli._writability_error(home)
    assert reason is not None and "can't write to" in reason
    assert not home.exists()


# ── reset-allowlist honors configured allowlist_dir;
#    invalid reset-scope aborts (no `both` default) ────────────────────────────


def test_reset_allowlist_honors_custom_allowlist_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """reset-allowlist must operate on the CONFIGURED [allowlist].allowlist_dir,
    not a hardcoded home/allowlist.d - even when it lives outside <root>."""
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    custom = tmp_path / "custom-allow"
    custom.mkdir()
    (custom / "domains_site").write_text("x.example.com\n", encoding="utf-8")
    (home / "config.toml").write_text(
        f'[sigwood]\nroot = "~/.sigwood"\n\n[allowlist]\nallowlist_dir = "{custom}"\n',
        encoding="utf-8",
    )

    _stub_candidates(monkeypatch)
    _stage_inputs(monkeypatch, ["r", "a", "reset"])
    cli._run_init([])

    assert not (custom / "domains_site").exists()         # configured dir reset
    assert (custom / "domains_user").exists()             # re-seeded there
    assert (custom / "connections").exists()
    assert (custom / "hosts").exists()
    assert not (home / "allowlist.d").exists()                # default dir NOT touched


def test_reset_config_preflights_writability_friendly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    """reset-config fails FAST with the friendly writability message (same as the
    allowlist arm) when the config home can't be written - not the rawer backup
    failure - and writes nothing."""
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    original = "[sigwood]\nroot = \"~/.sigwood\"\n"
    (home / "config.toml").write_text(original, encoding="utf-8")
    monkeypatch.setattr(
        cli, "_writability_error",
        lambda h, *, private=True: (
            "sigwood init: can't write to /etc/sigwood (denied). "
            "Re-run with sudo, or pick another location."
        ),
    )
    _stub_candidates(monkeypatch)
    # reset, scope=config, typed confirm - preflight fails before any source prompt.
    _stage_inputs(monkeypatch, ["r", "c", "reset"])
    cli._run_init([])

    assert "Re-run with sudo" in capsys.readouterr().out
    assert (home / "config.toml").read_text(encoding="utf-8") == original  # untouched
    assert not (home / "config.toml.bak").exists()


@pytest.mark.parametrize("scope_token", ["", "x"])
def test_reset_invalid_scope_aborts_no_changes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    capsys: pytest.CaptureFixture[str], scope_token: str,
) -> None:
    """A blank or unrecognized reset scope ABORTS with no changes - it must NOT
    fall through to the broadest `both` reset."""
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    original = "[sigwood]\nroot = \"~/.sigwood\"\n\n[detectors.beacon]\nthreshold = 0.99\n"
    (home / "config.toml").write_text(original, encoding="utf-8")
    ad = home / "allowlist.d"
    ad.mkdir()
    (ad / "domains_extra").write_text("x.example.com\n", encoding="utf-8")

    _stub_candidates(monkeypatch)
    _stage_inputs(monkeypatch, ["r", scope_token])
    cli._run_init([])

    assert "nothing changed" in capsys.readouterr().out
    assert (home / "config.toml").read_text(encoding="utf-8") == original  # config intact
    assert not (home / "config.toml.bak").exists()            # nothing written
    assert (ad / "domains_extra").exists()                # allowlist intact


# ════════════════════════════════════════════════════════════════════════════
# init v2 - root presence, summary annotations, no-mutation-before-accept,
# typed-path absolute normalization
# ════════════════════════════════════════════════════════════════════════════


def test_root_empty_summary_and_confirm_surfaces(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    """An explicit root = "" (CWD) survives across the SUMMARY and CONFIRM
    surfaces, never collapsed to the default by truthiness."""
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    (home / "config.toml").write_text("[sigwood]\nroot = \"\"\n", encoding="utf-8")
    _stub_candidates(monkeypatch)
    # merge, 4 sources skip, root Enter (keeps the explicit ""), accept.
    _stage_inputs(monkeypatch, ["", "", "", "", "", "", ""])
    cli._run_init([])

    out = capsys.readouterr().out
    # Empty root reads identically across summary and confirm: "(current
    # directory)" both places, annotated unchanged - never the cryptic "" / the
    # default ~/.sigwood.
    assert re.search(r'root\s+\(current directory\)\s+unchanged', out)
    assert "data:     (current directory)" in out
    assert "~/.sigwood" not in out
    parsed = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert parsed["sigwood"]["root"] == ""


def test_summary_annotations_added_changed_removed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    """The change-summary verbs: added / was:<old> / removed / (not set)."""
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    (home / "config.toml").write_text(
        "[sigwood]\nroot = \"/r\"\nzeek_dir = \"/old\"\n", encoding="utf-8",
    )
    _stub_candidates(monkeypatch)  # nothing detected
    # merge; zeek configured → type /new (was: /old); pihole nothing → type /p
    # (added); legacy system logs preserve the effective default; cloudtrail skips;
    # root present → `-` removes; accept.
    _stage_inputs(monkeypatch, ["", "/new", "/p", "", "", "-", ""])
    cli._run_init([])

    out = capsys.readouterr().out
    assert re.search(r'zeek_dir\s+/new\s+was: /old', out)
    assert re.search(r'pihole_dir\s+/p\s+added', out)
    assert re.search(
        r'file fallback\s+/var/log\s+preserved \(default; key not set\)', out,
    )
    assert re.search(r'system logs\s+auto\s+added', out)
    assert re.search(r'root\s+-\s+removed \(reverts to default\)', out)


def test_fresh_abort_after_typed_home_leaves_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    """E1 honesty: aborting the summary after typing a NEW custom home leaves no
    home dir, config, .bak, or allowlist seed (no FS mutation before accept)."""
    monkeypatch.setattr(cli, "_SEARCH_HOMES", (str(tmp_path / "uh"), str(tmp_path / "sh")))
    newhome = tmp_path / "newhome"  # does not exist
    _stub_candidates(monkeypatch)
    # fresh: 4 sources skip, location = newhome (typed custom), summary → abort.
    _stage_inputs(monkeypatch, ["", "", "", "", str(newhome), "a"])
    cli._run_init([])

    assert "Aborted - nothing changed." in capsys.readouterr().out
    assert not newhome.exists()                                # no partial home
    assert not (newhome / "config.toml").exists()
    assert not (newhome / "config.toml.bak").exists()
    assert not (newhome / "allowlist.d").exists()


def test_reset_both_rootless_config_resolves_allowlist_under_default_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """reset-both on a ROOTLESS config must reset allowlist.d under the DEFAULT
    root (~/.sigwood, where cfg.load places it) - never CWD-relative. The init
    allowlist resolver mirrors cfg.load's deep-merge for an absent root. The
    unset root prompts via the HOME MENU and Enter writes the default token, so
    the resolved allowlist.d still lands under ~/.sigwood."""
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    # Rootless config: no `root` key → cfg.load would run under ~/.sigwood.
    (home / "config.toml").write_text('[sigwood]\nzeek_dir = "/x"\n', encoding="utf-8")
    ad = home / "allowlist.d"
    ad.mkdir()
    (ad / "domains_extra").write_text("x.example.com\n", encoding="utf-8")
    # Isolate CWD so a CWD-relative bug would land in an inspectable place.
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)

    _stub_candidates(monkeypatch)
    # reset, scope=both, typed confirm; zeek configured (Enter keep), pihole/
    # syslog/cloudtrail skip; root UNSET → HOME MENU Enter (writes default); accept.
    _stage_inputs(monkeypatch, ["r", "b", "reset", "", "", "", "", "", ""])
    cli._run_init([])

    parsed = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert parsed["sigwood"]["root"] == "~/.sigwood"       # menu Enter → default
    assert not (cwd / "allowlist.d").exists()                  # NOT CWD-relative
    assert not (ad / "domains_extra").exists()             # reset the RIGHT dir
    assert (ad / "domains_user").exists()                  # reseeded under default root


def test_allowlist_resolver_absent_root_defaults_explicit_empty_is_cwd(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """The init allowlist resolver mirrors cfg.load: an ABSENT root resolves the
    default allowlist.d/ under ~/.sigwood; an explicit root = "" stays CWD-
    relative (the user chose CWD)."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))

    cfg_absent = tmp_path / "absent.toml"
    cfg_absent.write_text('[sigwood]\nzeek_dir = "/x"\n', encoding="utf-8")
    assert cli._resolve_allowlist_dir_from_config(cfg_absent) == (
        tmp_path / ".sigwood" / "allowlist.d"
    )

    cfg_empty = tmp_path / "empty.toml"
    cfg_empty.write_text('[sigwood]\nroot = ""\n', encoding="utf-8")
    assert cli._resolve_allowlist_dir_from_config(cfg_empty) == Path("allowlist.d")


def test_inline_comment_respects_quoting() -> None:
    assert cli._inline_comment('zeek_dir = "/x"  # my box') == "# my box"
    assert cli._inline_comment('zeek_dir = "/a#b"') == ""          # # inside quotes
    assert cli._inline_comment("zeek_dir = '/x' # legacy") == "# legacy"
    assert cli._inline_comment('zeek_dir = "/x"') == ""


def test_upsert_preserves_inline_comment_on_active_line() -> None:
    """A keep/change rewrite (re-quoting single→double) preserves a user's inline
    comment on the active managed-key line; uncommenting a sample appends none."""
    base = '[sigwood]\nzeek_dir = "/x"  # my zeek box\n'
    kept = cli._upsert_sigwood_key(base, "zeek_dir", "/x", fresh=False)
    assert 'zeek_dir = "/x"  # my zeek box' in kept          # keep retains comment
    changed = cli._upsert_sigwood_key(base, "zeek_dir", "/y", fresh=False)
    assert 'zeek_dir = "/y"  # my zeek box' in changed       # change retains comment
    # An active line with NO comment never gets a fabricated one.
    plain = '[sigwood]\nzeek_dir = "/x"\nsyslog_dir = "/v"\n'
    out = cli._upsert_sigwood_key(plain, "zeek_dir", "/y", fresh=False)
    assert 'zeek_dir = "/y"\n' in out


def test_effective_root_with_default_absent_empty_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The shared init root-default owner: absent root → default; explicit "" →
    CWD; explicit value honored; env SIGWOOD_ROOT wins over all."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    assert cli._effective_root_with_default({"zeek_dir": "/x"}) == cli._DEFAULT_ROOT
    assert cli._effective_root_with_default({"root": ""}) == ""
    assert cli._effective_root_with_default({"root": "/custom"}) == "/custom"
    monkeypatch.setenv("SIGWOOD_ROOT", "/envroot")
    assert cli._effective_root_with_default({}) == "/envroot"            # env over default
    assert cli._effective_root_with_default({"root": "/custom"}) == "/envroot"  # env over config


def test_merge_rootless_relative_source_profiles_under_default_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    """A configured RELATIVE source on a ROOTLESS config is previewed under the
    default ~/.sigwood (where cfg.load resolves it), so the prompt shows a real
    profile - never a "nothing there now" lie about a populated dir."""
    monkeypatch.delenv("SIGWOOD_ROOT", raising=False)
    home = _isolated_home(monkeypatch, tmp_path)   # ~/.sigwood == home
    home.mkdir(parents=True)
    # Rootless config, RELATIVE zeek_dir; the real logs live under ~/.sigwood.
    (home / "config.toml").write_text(
        '[sigwood]\nzeek_dir = "logs/zeek"\n', encoding="utf-8",
    )
    populated = home / "logs" / "zeek"
    _make_file(populated / "conn.log")
    _make_file(populated / "dns.log")

    _stub_candidates(monkeypatch)
    # merge, zeek Enter (keep VERBATIM - relative stays relative), pihole/syslog/
    # cloudtrail skip, root unset → HOME MENU Enter (writes default), accept.
    _stage_inputs(monkeypatch, ["", "", "", "", "", "", ""])
    cli._run_init([])

    out = capsys.readouterr().out
    assert "Found Zeek at logs/zeek - conn + dns" in out      # profiled, not empty
    assert "nothing there now" not in out
    parsed = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert parsed["sigwood"]["zeek_dir"] == "logs/zeek"     # kept verbatim, not CWD-abs


def test_typed_relative_source_stored_absolute(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """A typed RELATIVE source is normalized to a CWD-absolute path and stored
    that way - never reinterpreted under SIGWOOD_ROOT. (A split root is not
    expressible in the FRESH flow - the location answer IS the root;
    split-root coverage lives in the reset-config path.)"""
    home = _isolated_home(monkeypatch, tmp_path)
    _stub_candidates(monkeypatch)  # nothing detected
    # fresh: zeek skip, pihole typed RELATIVE, syslog/cloudtrail skip, location
    # Enter (~/.sigwood - the home IS the root), accept.
    _stage_inputs(monkeypatch, ["", "relpihole", "", "", "", ""])
    cli._run_init([])

    parsed = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert parsed["sigwood"]["pihole_dir"] == os.path.abspath("relpihole")
    assert parsed["sigwood"]["root"] == "~/.sigwood"       # location token = root


# ════════════════════════════════════════════════════════════════════════════
# init polish ROUND 3 - universal `-` drop sentinel (no readline / capability) ·
# HOME MENU · profiler recursion/glob
# ════════════════════════════════════════════════════════════════════════════


def _one_input(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: value)


def test_prompt_source_configured_keep_change_remove(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """configured: Enter keeps VERBATIM (relative stays relative), a typed path
    changes (normalized), `-` removes."""
    _one_input(monkeypatch, "")
    assert cli._prompt_source("Zeek", "logs/zeek", None, None, ("n",)) == \
        cli._set("logs/zeek")                          # keep verbatim, NOT abspath
    _one_input(monkeypatch, "/new/zeek")
    assert cli._prompt_source("Zeek", "/old", None, None, ("n",)) == \
        cli._set("/new/zeek")                          # change → normalized
    _one_input(monkeypatch, "-")
    assert cli._prompt_source("Zeek", "/old", None, None, ("n",)) == cli._REMOVE


def test_prompt_source_detected_keep_change_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """detected: Enter uses it VERBATIM, a typed path changes, `-` skips."""
    _one_input(monkeypatch, "")
    assert cli._prompt_source("Zeek", None, "/det", None, ("n",)) == cli._set("/det")
    _one_input(monkeypatch, "/typed")
    assert cli._prompt_source("Zeek", None, "/det", None, ("n",)) == cli._set("/typed")
    _one_input(monkeypatch, "-")
    assert cli._prompt_source("Zeek", None, "/det", None, ("n",)) == cli._SKIP


def test_prompt_source_nothing_skip_or_dash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """nothing: Enter or `-` skips; a typed path sets it."""
    _one_input(monkeypatch, "")
    assert cli._prompt_source("Zeek", None, None, None, ("n",)) == cli._SKIP
    _one_input(monkeypatch, "-")
    assert cli._prompt_source("Zeek", None, None, None, ("n",)) == cli._SKIP
    _one_input(monkeypatch, "/x")
    assert cli._prompt_source("Zeek", None, None, None, ("n",)) == cli._set("/x")


def test_prompt_source_dash_escape_is_a_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`./-` is a PATH (normalized), NOT the drop sentinel - the escape for a dir
    literally named `-` (mirrors the HOME MENU's `./a`)."""
    _one_input(monkeypatch, "./-")
    assert cli._prompt_source("Zeek", "/old", None, None, ("n",)) == \
        cli._set(os.path.abspath("-"))
    _one_input(monkeypatch, "./-")
    assert cli._prompt_source("Zeek", None, "/det", None, ("n",)) == \
        cli._set(os.path.abspath("-"))


def _journal_result(
    code: cli.journal_probe.JournalProbeCode,
    *,
    stderr: bytes = b"",
) -> cli.journal_probe.JournalProbeResult:
    return cli.journal_probe.JournalProbeResult(code, stderr=stderr)


def _system_state(
    monkeypatch: pytest.MonkeyPatch,
    existing: dict,
    *,
    fresh: bool,
    code: cli.journal_probe.JournalProbeCode,
    detected: str | None = None,
) -> tuple[cli._SystemLogsState, cli.journal_probe.JournalProbeResult]:
    monkeypatch.setattr(cli, "_detect_syslog", lambda: detected)
    monkeypatch.setattr(cli, "_profile_dir", lambda *_a, **_k: None)
    probe = _journal_result(code)
    state = cli._system_logs_state(
        existing,
        fresh_install=fresh,
        probe=probe,
        root="",
    )
    return state, probe


@pytest.mark.parametrize(
    ("code", "detected", "mode", "dir_action"),
    [
        ("READY", "/logs", "auto", cli._set("/logs")),
        ("READY", None, "auto", cli._set("")),
        ("EMPTY", "/logs", "files", cli._set("/logs")),
        ("EMPTY", None, "off", cli._set("")),
        ("EXECUTABLE_MISSING", "/logs", "files", cli._set("/logs")),
        ("EXIT_NONZERO", None, "off", cli._set("")),
    ],
)
def test_system_logs_fresh_recommendation_table(
    monkeypatch: pytest.MonkeyPatch,
    code: str,
    detected: str | None,
    mode: str,
    dir_action: object,
) -> None:
    probe_code = getattr(cli.journal_probe.JournalProbeCode, code)
    state, probe = _system_state(
        monkeypatch, {}, fresh=True, code=probe_code, detected=detected,
    )
    _one_input(monkeypatch, "")
    assert cli._prompt_system_logs(state, probe) == (cli._set(mode), dir_action)


@pytest.mark.parametrize("mode", ["auto", "journal", "files", "off"])
@pytest.mark.parametrize(
    ("dir_shape", "expected_dir"),
    [
        ({"syslog_dir": "logs/system"}, cli._set("logs/system")),
        ({"syslog_dir": ""}, cli._set("")),
        ({}, cli._REMOVE),
    ],
)
def test_system_logs_explicit_mode_enter_preserves_raw_dir(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    dir_shape: dict,
    expected_dir: object,
) -> None:
    state, probe = _system_state(
        monkeypatch,
        {"syslog_source": mode, **dir_shape},
        fresh=False,
        code=cli.journal_probe.JournalProbeCode.EXECUTABLE_MISSING,
    )
    _one_input(monkeypatch, "")
    assert cli._prompt_system_logs(state, probe) == (
        cli._set(mode), expected_dir,
    )


@pytest.mark.parametrize(
    ("existing", "mode", "dir_action", "migrated"),
    [
        ({"syslog_dir": "/var/log"}, "auto", cli._set("/var/log"), True),
        ({"syslog_dir": ""}, "off", cli._set(""), False),
        ({}, "auto", cli._REMOVE, True),
    ],
)
def test_system_logs_legacy_enter_transition_table(
    monkeypatch: pytest.MonkeyPatch,
    existing: dict,
    mode: str,
    dir_action: object,
    migrated: bool,
) -> None:
    state, probe = _system_state(
        monkeypatch,
        existing,
        fresh=False,
        code=cli.journal_probe.JournalProbeCode.EMPTY,
    )
    assert state.migrated is migrated
    _one_input(monkeypatch, "")
    assert cli._prompt_system_logs(state, probe) == (cli._set(mode), dir_action)


def test_system_logs_explicit_selections_and_typed_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, probe = _system_state(
        monkeypatch,
        {"syslog_source": "auto", "syslog_dir": "logs/system"},
        fresh=False,
        code=cli.journal_probe.JournalProbeCode.READY,
    )
    _one_input(monkeypatch, "journal")
    assert cli._prompt_system_logs(state, probe) == (
        cli._set("journal"), cli._set("logs/system"),
    )
    _one_input(monkeypatch, "auto")
    assert cli._prompt_system_logs(state, probe) == (
        cli._set("auto"), cli._set("logs/system"),
    )
    _one_input(monkeypatch, "-")
    assert cli._prompt_system_logs(state, probe) == (
        cli._set("off"), cli._set(""),
    )
    _one_input(monkeypatch, "relative-system")
    assert cli._prompt_system_logs(state, probe) == (
        cli._set("files"), cli._set(os.path.abspath("relative-system")),
    )


def test_system_logs_selection_fallback_edge_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fresh, fresh_probe = _system_state(
        monkeypatch,
        {},
        fresh=True,
        code=cli.journal_probe.JournalProbeCode.READY,
        detected="/detected-system",
    )
    _one_input(monkeypatch, "journal")
    assert cli._prompt_system_logs(fresh, fresh_probe) == (
        cli._set("journal"), cli._set(""),
    )
    _one_input(monkeypatch, "auto")
    assert cli._prompt_system_logs(fresh, fresh_probe) == (
        cli._set("auto"), cli._set("/detected-system"),
    )
    _one_input(monkeypatch, "files")
    assert cli._prompt_system_logs(fresh, fresh_probe) == (
        cli._set("files"), cli._set("/detected-system"),
    )

    absent, absent_probe = _system_state(
        monkeypatch,
        {"syslog_source": "journal"},
        fresh=False,
        code=cli.journal_probe.JournalProbeCode.READY,
    )
    _one_input(monkeypatch, "auto")
    assert cli._prompt_system_logs(absent, absent_probe) == (
        cli._set("auto"), cli._set(""),
    )
    _one_input(monkeypatch, "files")
    assert cli._prompt_system_logs(absent, absent_probe) == (
        cli._set("files"), cli._REMOVE,
    )


def test_system_logs_files_requires_path_when_fallback_explicit_empty(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    state, probe = _system_state(
        monkeypatch,
        {"syslog_source": "auto", "syslog_dir": ""},
        fresh=False,
        code=cli.journal_probe.JournalProbeCode.EMPTY,
    )
    _stage_inputs(monkeypatch, ["files", "", "typed-system"])
    assert cli._prompt_system_logs(state, probe) == (
        cli._set("files"), cli._set(os.path.abspath("typed-system")),
    )
    assert capsys.readouterr().out.count(
        "files needs a non-empty system-log directory"
    ) == 2


def test_system_logs_probe_copy_ignores_child_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    token = "HOSTILE_CHILD_DETAIL"
    state, _ = _system_state(
        monkeypatch,
        {},
        fresh=True,
        code=cli.journal_probe.JournalProbeCode.EXIT_NONZERO,
    )
    probe = _journal_result(
        cli.journal_probe.JournalProbeCode.EXIT_NONZERO,
        stderr=f"{token}\x1b[31m".encode(),
    )
    _one_input(monkeypatch, "")
    cli._prompt_system_logs(state, probe)
    out = capsys.readouterr().out
    assert "unavailable, journal query failed" in out
    assert token not in out


def test_system_logs_probe_copy_covers_every_reason_code() -> None:
    assert set(cli._JOURNAL_PROBE_COPY) == set(cli.journal_probe.JournalProbeCode)


def test_prompt_root_present_keep_change_remove(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """present non-empty root: Enter keeps VERBATIM (~ preserved), a typed path
    changes, `-` removes (reverts to default)."""
    _one_input(monkeypatch, "")
    assert cli._prompt_root(present=True, default="~/data") == cli._set("~/data")
    _one_input(monkeypatch, "/new")
    assert cli._prompt_root(present=True, default="/old") == cli._set("/new")
    _one_input(monkeypatch, "-")
    assert cli._prompt_root(present=True, default="/old") == cli._REMOVE


def test_prompt_root_present_empty_keeps_and_removes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """present root="" (current directory): Enter keeps "" verbatim; `-` removes."""
    _one_input(monkeypatch, "")
    assert cli._prompt_root(present=True, default="") == cli._set("")
    _one_input(monkeypatch, "-")
    assert cli._prompt_root(present=True, default="") == cli._REMOVE


def test_prompt_root_present_dash_escape_is_a_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`./-` on a present root is a PATH (normalized), not the remove sentinel."""
    _one_input(monkeypatch, "./-")
    assert cli._prompt_root(present=True, default="/old") == \
        cli._set(os.path.abspath("-"))


def test_prompt_root_unset_uses_home_menu(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """unset root routes through the HOME MENU (Enter → default token)."""
    _one_input(monkeypatch, "")
    assert cli._prompt_root(present=False, default=None) == cli._set("~/.sigwood")


def test_source_and_root_hints_are_universal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """ONE hint per state - no capability fork, no clear-clause."""
    _one_input(monkeypatch, "")
    cli._prompt_source("Zeek", "/z", None, None, ("n",))
    assert "[Enter to keep  ·  type a path to change  ·  - to remove]" in \
        capsys.readouterr().out
    _one_input(monkeypatch, "")
    cli._prompt_source("Zeek", None, "/d", None, ("n",))
    assert "[Enter to use it  ·  type a path  ·  - to skip]" in \
        capsys.readouterr().out
    _one_input(monkeypatch, "")
    cli._prompt_root(present=True, default="/r")
    assert "[Enter to keep  ·  type a path to change  ·  - to remove]" in \
        capsys.readouterr().out


def test_home_menu_presets_typed_and_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HOME MENU: Enter/'a' → ~/.sigwood; 'b' → /etc/sigwood (literal tokens);
    a typed path → normalized absolute; the ./a escape reaches a dir named 'a'."""
    for ans, expected in [
        ("", "~/.sigwood"), ("a", "~/.sigwood"), ("A", "~/.sigwood"),
        ("b", "/etc/sigwood"), ("B", "/etc/sigwood"),
    ]:
        monkeypatch.setattr("builtins.input", lambda *_a, _v=ans, **_k: _v)
        assert cli._home_menu("lead") == expected
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "/srv/sigwood")
    assert cli._home_menu("lead") == "/srv/sigwood"          # typed absolute
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "./a")
    assert cli._home_menu("lead") == os.path.abspath("a")  # escape → dir named 'a'


def test_profile_zeek_dated_subdirs_use_loader_depth(tmp_path: Path) -> None:
    """Zeek profiles use the loader-depth flat/dated walk, not unbounded recursion."""
    zeek = tmp_path / "zeek"
    _make_file(zeek / "2026-06-19" / "conn.2026-06-19.log.gz", size=4096)
    assert cli._profile_dir(str(zeek), cli._ZEEK_GLOBS, logs_label=None) is None
    p = cli._profile_dir(
        str(zeek), cli._ZEEK_GLOBS, logs_label=None, zeek_layout=True,
    )
    assert p is not None and p["logs"] == "conn"


def test_profile_zeek_does_not_count_deeper_nested_logs(tmp_path: Path) -> None:
    """Dated Zeek profiling matches loader discovery: one-level date/non-date
    children count, grandchild date layouts do not."""
    from sigwood.common.loader.discovery import discover_zeek_files

    zeek = tmp_path / "zeek"
    in_loader_scope = zeek / "2026-06-19" / "conn.log"
    too_deep = zeek / "host-a" / "2026-06-19" / "conn.log"
    _make_file(in_loader_scope, size=8)
    _make_file(too_deep, size=4096)

    p = cli._profile_dir(
        str(zeek), cli._ZEEK_GLOBS, logs_label=None, zeek_layout=True,
    )
    discovered = discover_zeek_files(zeek, "conn*.log*")

    assert [f.resolve() for f in discovered] == [in_loader_scope.resolve()]
    assert p is not None
    assert p["logs"] == "conn"
    assert p["size_bytes"] == 8


def test_profile_pihole_dated_files_glob(tmp_path: Path) -> None:
    """The Pi-hole profile glob (pihole*.log*) must match dated/exported names
    like pihole_20260619_1d.log - a bare pihole.log* glob would miss them."""
    d = tmp_path / "pihole"
    _make_file(d / "pihole_20260619_1d.log", size=2048)
    p = cli._profile_dir(str(d), (cli._PIHOLE_GLOB,), logs_label="query logs")
    assert p is not None
    assert p["logs"] == "query logs"


def test_pihole_glob_mirrors_dns_detector_pattern() -> None:
    """Drift tripwire: the profile's Pi-hole glob must equal the runtime pattern
    OWNED by the DNS detector (dns.OPTIONAL_LOGS, the pihole_dir entry)."""
    from sigwood.detectors import dns
    expected = next(
        e["pattern"] for e in dns.OPTIONAL_LOGS if e["source"] == "pihole_dir"
    )
    assert cli._PIHOLE_GLOB == expected


def test_detect_pihole_directory_probe_uses_runtime_prefix_glob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The conventional Pi-hole directory probe is narrowed to the runtime
    prefix glob instead of any sibling ``*.log`` file."""
    d = tmp_path / "pihole"
    d.mkdir()
    (d / "other.log").write_text("not pihole\n", encoding="utf-8")
    monkeypatch.setattr(
        cli,
        "_PIHOLE_CANDIDATES",
        ((str(d / "pihole*.log*"), str(d)),),
    )
    assert cli._detect_pihole() is None

    (d / "pihole.log").write_text("query log\n", encoding="utf-8")
    assert cli._detect_pihole() == str(d)


def test_fresh_asks_home_once_no_separate_root_prompt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    """Fresh asks for the home ONCE - the location lead appears once and there
    is no separate root prompt (the location answer IS the root). A leftover root
    prompt would consume an extra input and StopIteration."""
    home = _isolated_home(monkeypatch, tmp_path)
    _stub_candidates(monkeypatch)
    _stage_inputs(monkeypatch, ["", "", "", "", "", ""])  # 4 skip, location, accept
    cli._run_init([])
    out = capsys.readouterr().out
    assert out.count(cli._FRESH_LOCATION_LEAD) == 1
    assert "root is set to" not in out
    parsed = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert parsed["sigwood"]["root"] == "~/.sigwood"


# ════════════════════════════════════════════════════════════════════════════
# Compound system-log flow boundaries
# ════════════════════════════════════════════════════════════════════════════


def test_reset_explicit_mode_preserves_raw_absent_fallback_and_backup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    original = (
        b'[sigwood]\r\nroot = "~/.sigwood"\r\n'
        b'syslog_source = "journal"\r\n'
    )
    (home / "config.toml").write_bytes(original)
    _stub_candidates(monkeypatch)
    _stage_inputs(
        monkeypatch,
        ["r", "c", "reset", "", "", "", "", "", ""],
    )

    cli._run_init([])

    parsed = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert parsed["sigwood"]["syslog_source"] == "journal"
    assert "syslog_dir" not in parsed["sigwood"]
    assert (home / "config.toml.bak").read_bytes() == original


def test_fresh_off_writes_both_compatibility_keys(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    _stub_candidates(monkeypatch)
    _stage_inputs(monkeypatch, ["", "", "", "", "", ""])

    cli._run_init([])

    parsed = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert parsed["sigwood"]["syslog_source"] == "off"
    assert parsed["sigwood"]["syslog_dir"] == ""


def test_summary_counts_system_logs_once_and_separates_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolated_home(monkeypatch, tmp_path)
    _stub_candidates(
        monkeypatch,
        journal_code=cli.journal_probe.JournalProbeCode.READY,
    )
    _stage_inputs(monkeypatch, ["", "", "", "", "", ""])

    cli._run_init([])

    out = capsys.readouterr().out
    assert "No sources set" not in out
    assert re.search(r"system logs\s+auto\s+added", out)
    assert "reading:  system logs (auto)" in out
    assert "file fallback: (none)" in out
    assert "journal probe: available" in out
    assert "journal (/" not in out


@pytest.mark.parametrize(
    "answers",
    [
        [""],
        ["r", "c", "reset"],
    ],
)
def test_invalid_explicit_mode_fails_before_probe_and_source_prompts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    answers: list[str],
) -> None:
    from sigwood import cli as public_cli

    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    original = b'[sigwood]\nsyslog_source = "automatic"\n'
    (home / "config.toml").write_bytes(original)
    _stub_candidates(monkeypatch)
    monkeypatch.setattr(
        cli.journal_probe,
        "probe_journal",
        lambda: (_ for _ in ()).throw(AssertionError("probe must not run")),
    )
    _stage_inputs(monkeypatch, answers)

    with pytest.raises(SystemExit) as exc:
        public_cli.main(["init"])

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert (
        "sigwood: syslog_source must be one of auto, journal, files, or off"
        in captured.err
    )
    assert "run 'sigwood --help' for usage" not in captured.err
    assert "Traceback" not in captured.err
    assert "System logs:" not in captured.out
    assert (home / "config.toml").read_bytes() == original
    assert not (home / "config.toml.bak").exists()


def test_invalid_mode_does_not_block_allowlist_only_reset(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    original = '[sigwood]\nsyslog_source = "automatic"\n'
    (home / "config.toml").write_text(original, encoding="utf-8")
    allowlist_d = home / "allowlist.d"
    allowlist_d.mkdir()
    (allowlist_d / "domains_extra").write_text(
        "*.placeholder.example\n", encoding="utf-8",
    )
    _stub_candidates(monkeypatch)
    _stage_inputs(monkeypatch, ["r", "a", "reset"])

    cli._run_init([])

    assert (home / "config.toml").read_text(encoding="utf-8") == original
    assert not (allowlist_d / "domains_extra").exists()
    assert (allowlist_d / "domains_user").exists()


def test_import_boundary_allows_only_three_pure_common_leaves() -> None:
    source_path = Path("sigwood/cli_init.py")
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    project_imports: set[tuple[str, tuple[str, ...]]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("sigwood"):
                    project_imports.add((alias.name, ()))
        elif (
            isinstance(node, ast.ImportFrom)
            and (node.module or "").startswith("sigwood")
        ):
            project_imports.add(
                (node.module or "", tuple(sorted(alias.name for alias in node.names)))
            )

    assert project_imports == {
        ("sigwood.common.journal_probe", ()),
        ("sigwood.common.syslog_mode", ()),
        (
            "sigwood.common.paths",
            (
                "effective_root",
                "private_mkdir",
                "private_open",
                "private_write_bytes",
                "private_write_text",
                "resolve_path",
            ),
        ),
    }


def test_init_uses_shared_probe_once_and_creates_no_capture_before_abort(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    _stub_candidates(monkeypatch)
    calls = 0

    def _probe() -> cli.journal_probe.JournalProbeResult:
        nonlocal calls
        calls += 1
        return _journal_result(cli.journal_probe.JournalProbeCode.EMPTY)

    monkeypatch.setattr(cli.journal_probe, "probe_journal", _probe)
    _stage_inputs(monkeypatch, ["", "", "", "", "", "a"])

    cli._run_init([])

    assert calls == 1
    assert not home.exists()
    assert not list(tmp_path.rglob("sigwood-journal-*"))
    source = Path("sigwood/cli_init.py").read_text(encoding="utf-8")
    assert "prepare_journal_capture" not in source
    assert "build_journal_argv" not in source


# ════════════════════════════════════════════════════════════════════════════
# End-of-input (Ctrl-D / closed stdin) aborts the wizard cleanly
# ════════════════════════════════════════════════════════════════════════════
#
# EOF at ANY prompt must behave like the explicit abort choices: the standard
# abort line, a clean return (exit 0), and nothing written - truthful because
# no filesystem mutation happens before the summary accept and no prompt
# exists after it.


def test_eof_at_first_prompt_aborts_nothing_written(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    home = _isolated_home(monkeypatch, tmp_path)
    _stub_candidates(monkeypatch)
    _stage_inputs_then_eof(monkeypatch, [])

    cli._run_init([])

    assert "Aborted - nothing changed." in capsys.readouterr().out
    assert not home.exists()


def test_eof_mid_flow_aborts_nothing_written(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    """EOF at the third source prompt (two sources already answered)."""
    home = _isolated_home(monkeypatch, tmp_path)
    _stub_candidates(monkeypatch)
    _stage_inputs_then_eof(monkeypatch, ["", ""])

    cli._run_init([])

    assert "Aborted - nothing changed." in capsys.readouterr().out
    assert not home.exists()


def test_eof_at_summary_accept_aborts_nothing_written(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    """EOF at the accept prompt itself - the last prompt in the fresh flow."""
    home = _isolated_home(monkeypatch, tmp_path)
    _stub_candidates(monkeypatch)
    # fresh: 4 source skips + location Enter; EOF arrives at the accept prompt.
    _stage_inputs_then_eof(monkeypatch, ["", "", "", "", ""])

    cli._run_init([])

    out = capsys.readouterr().out
    assert "About to write" in out
    assert "Aborted - nothing changed." in out
    assert not home.exists()


def test_eof_at_merge_entry_aborts_config_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    """EOF at the merge/reset menu - the ``_entry_for_config`` dispatch arm."""
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    original = '[sigwood]\nroot = "~/.sigwood"\n'
    (home / "config.toml").write_text(original, encoding="utf-8")
    _stub_candidates(monkeypatch)
    _stage_inputs_then_eof(monkeypatch, [])

    cli._run_init([])

    assert "Aborted - nothing changed." in capsys.readouterr().out
    assert (home / "config.toml").read_text(encoding="utf-8") == original
    assert not (home / "config.toml.bak").exists()


def test_eof_abort_blank_line_on_tty(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    """Ctrl-D does not echo a newline, so on a TTY the abort line gets one
    leading blank line to leave the '> ' prompt row; non-TTY output (the other
    EOF tests) stays byte-clean."""
    _isolated_home(monkeypatch, tmp_path)
    _stub_candidates(monkeypatch)
    _stage_inputs_then_eof(monkeypatch, [])
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)

    cli._run_init([])

    assert capsys.readouterr().out.endswith("\n\nAborted - nothing changed.\n")


def test_init_closed_stdin_subprocess_exit_0_no_traceback(tmp_path: Path) -> None:
    """`sigwood init < /dev/null` end-to-end: clean abort, no traceback on
    either stream, exit 0, nothing written under the isolated HOME."""
    env = dict(os.environ, HOME=str(tmp_path))
    proc = subprocess.run(
        [sys.executable, "-c", "from sigwood.cli import main; main(['init'])"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=env,
        cwd=str(Path(__file__).resolve().parent.parent),
    )

    assert proc.returncode == 0
    assert "Traceback" not in proc.stderr
    assert "Traceback" not in proc.stdout
    assert "Aborted - nothing changed." in proc.stdout
    assert not (tmp_path / ".sigwood").exists()


def test_classify_dropin_mirrors_allowlist() -> None:
    """Drift tripwire: the wizard's dot-rule classifier must agree with
    allowlist._classify_dropin over a shared table (cli_init mirrors it - it cannot
    import common/allowlist across the stdlib-only boundary). A prefixed head ending
    in ~ is in the table so a prefix-only mirror fails."""
    from sigwood.common import allowlist as al
    names = [
        "domains_user", "connections_local", "hosts_lab",
        "domains", "connections", "hosts",
        "domains_user.txt", "connections.txt", "hosts.bak",
        "domains_user.bak", "x.toml", "hosts.toml",
        "domains_user.toml", ".hidden", "domains_user~", "domains_user~.bak",
        "hosts~", "notes", "legacy.txt", "domains_readme", "domains_x.toml~",
    ]
    for n in names:
        assert cli._classify_dropin(n) == al._classify_dropin(n), n


def test_reset_allowlist_deletes_only_dotfree_prefixed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """The destructive guard that must never regress. reset-allowlist unlinks ONLY
    dot-free prefixed drop-ins (domains* / connections* / hosts*), INCLUDING a reserved-
    namespace domains_readme. Everything else survives: a *.toml stanza, a dotted
    backup, a legacy dotted connections.txt, a dot-free UNPREFIXED file, a hidden
    file, a ~ backup, and a subdirectory. The two seed templates are re-created."""
    home = _isolated_home(monkeypatch, tmp_path)
    home.mkdir(parents=True)
    (home / "config.toml").write_text("[sigwood]\nroot = \"~/.sigwood\"\n", encoding="utf-8")
    ad = home / "allowlist.d"
    ad.mkdir()
    # deleted - dot-free prefixed (the last one is the reserved-namespace edge):
    (ad / "domains_extra").write_text("x.example.com\n", encoding="utf-8")
    (ad / "connections_local").write_text("192.0.2.1\n", encoding="utf-8")
    (ad / "hosts_lab").write_text("lab-*\n", encoding="utf-8")
    (ad / "domains_readme").write_text("*.example\n", encoding="utf-8")
    # preserved:
    (ad / "keep.toml").write_text("[[allowlist.entry]]\nmatch = 'example.com'\n", encoding="utf-8")
    (ad / "domains_user.bak").write_text("x.example.com\n", encoding="utf-8")
    (ad / "connections.txt").write_text("192.0.2.9\n", encoding="utf-8")   # legacy dotted survives
    (ad / "hosts.bak").write_text("lab-*\n", encoding="utf-8")
    (ad / "hosts~").write_text("lab-*\n", encoding="utf-8")
    (ad / "hosts.toml").write_text(
        "[[allowlist.entry]]\nmatch = 'dst_port'\nvalue = 22\n", encoding="utf-8",
    )
    (ad / "notes").write_text("dot-free unprefixed\n", encoding="utf-8")
    (ad / ".hidden").write_text("hidden\n", encoding="utf-8")
    (ad / "backup~").write_text("editor backup\n", encoding="utf-8")
    (ad / "domains_sub").mkdir()
    (ad / "hosts_x").mkdir()

    _stub_candidates(monkeypatch)
    _stage_inputs(monkeypatch, ["r", "a", "reset"])
    cli._run_init([])

    for gone in ("domains_extra", "connections_local", "hosts_lab", "domains_readme"):
        assert not (ad / gone).exists(), gone
    for kept in ("keep.toml", "domains_user.bak", "connections.txt", "notes",
                 "hosts.bak", "hosts~", "hosts.toml", ".hidden", "backup~"):
        assert (ad / kept).exists(), kept
    assert (ad / "domains_sub").is_dir()          # subdir untouched
    assert (ad / "hosts_x").is_dir()
    assert (ad / "domains_user").exists()         # re-seeded blank
    assert (ad / "connections").exists()
    assert (ad / "hosts").exists()
