"""The ``allowlist`` verb - readout / show / enable / disable / copy + CLI boundary.

Every test is isolated to a tmp home/root; enable/disable ALWAYS pass an explicit
tmp ``config_path`` (or monkeypatch ``cfg.SEARCH_PATHS``) so the developer's real
``~/.sigwood/config.toml`` is never read or mutated.

Fixtures use example.com / RFC 5737 only.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sigwood import cli, cli_allowlist
from sigwood.common import allowlist as al
from sigwood.common import config as cfg
from sigwood.common.errors import UsageError


def _config(tmp_path: Path, body: str = "") -> Path:
    p = tmp_path / "config.toml"
    p.write_text(f'[sigwood]\nroot = "{tmp_path}"\n[allowlist]\nenabled = true\n{body}',
                 encoding="utf-8")
    return p


def _allowlist_d(tmp_path: Path) -> Path:
    d = tmp_path / "allowlist.d"
    d.mkdir(exist_ok=True)
    return d


# ── readout ───────────────────────────────────────────────────────────────────


def test_readout_renders_plan(tmp_path: Path, capsys) -> None:
    cli_allowlist.run_allowlist([], config_path=str(_config(tmp_path)))
    out = capsys.readouterr().out
    assert "suppression: on" in out
    assert "shipped lists" in out
    assert "common" in out and "devices" in out and "homelab" in out
    assert "off" in out                       # homelab default off
    assert "classification: 0 stanza entries" in out


def test_readout_config_path_list_shows_resolved_path(tmp_path: Path, capsys) -> None:
    # An explicit domain_patterns entry OUTSIDE allowlist.d must render under its
    # OWN section with the compacted RESOLVED PATH - never mislabeled as a bare
    # filename under the allowlist.d header.
    outside = tmp_path / "etc" / "outside.txt"
    outside.parent.mkdir()
    outside.write_text("vendor.example.net\n", encoding="utf-8")
    cfg_path = _config(tmp_path, body=f'domain_patterns = ["{outside}"]\n')

    cli_allowlist.run_allowlist([], config_path=str(cfg_path))
    out = capsys.readouterr().out

    assert "config lists" in out
    assert str(outside) in out                 # full resolved path, not a phantom name
    assert "your lists" not in out             # no allowlist.d section here


def test_readout_legacy_universal_nudge(tmp_path: Path, capsys) -> None:
    (_allowlist_d(tmp_path) / "domains_universal").write_text(
        "x.example.com\n", encoding="utf-8")
    cli_allowlist.run_allowlist([], config_path=str(_config(tmp_path)))
    out = capsys.readouterr().out
    assert "the shipped list is 'common' - disable common to replace" in out


def test_readout_and_show_host_dropin(tmp_path: Path, capsys) -> None:
    (_allowlist_d(tmp_path) / "hosts_lab").write_text(
        "# local\nlab-*\nre:^kiosk-[0-9]+$ # narrow\n", encoding="utf-8",
    )
    config_path = str(_config(tmp_path))

    cli_allowlist.run_allowlist([], config_path=config_path)
    out = capsys.readouterr().out
    assert "your lists" in out
    assert "hosts_lab" in out
    assert "2 patterns" in out

    cli_allowlist.run_allowlist(["show", "hosts_lab"], config_path=config_path)
    assert capsys.readouterr().out.strip().splitlines() == [
        "lab-*", "re:^kiosk-[0-9]+$",
    ]


# ── show ──────────────────────────────────────────────────────────────────────


def test_show_strips_comments_blanks(tmp_path: Path, capsys) -> None:
    d = _allowlist_d(tmp_path)
    (d / "domains_site").write_text(
        "# a comment\n\nkept.example.com  # inline\n", encoding="utf-8")
    cli_allowlist.run_allowlist(["show", "domains_site"], config_path=str(_config(tmp_path)))
    out = capsys.readouterr().out.strip()
    assert out == "kept.example.com"          # one line, comments + blanks stripped


def test_show_works_on_disabled_list(tmp_path: Path, capsys) -> None:
    # homelab is default-off - show must still print its patterns.
    cli_allowlist.run_allowlist(["show", "homelab"], config_path=str(_config(tmp_path)))
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == next(
        rl.pattern_count for rl in al.resolve_allowlist_plan({}).lists if rl.name == "homelab"
    )


def test_show_unknown_name_is_operational_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError) as exc:
        cli_allowlist.run_allowlist(["show", "bogus"], config_path=str(_config(tmp_path)))
    assert not isinstance(exc.value, UsageError)   # operational, no usage hint


# ── enable / disable ──────────────────────────────────────────────────────────


def test_enable_writes_lists_table_and_bak(tmp_path: Path, capsys) -> None:
    cfg_path = _config(tmp_path)
    raw_before = cfg_path.read_bytes()
    cli_allowlist.run_allowlist(["enable", "homelab"], config_path=str(cfg_path))
    assert "enabled homelab" in capsys.readouterr().out

    text = cfg_path.read_text(encoding="utf-8")
    assert "[allowlist.lists]" in text and "homelab = true" in text
    # Raw-bytes .bak of the pre-write file.
    assert cfg_path.with_suffix(".toml.bak").read_bytes() == raw_before


def test_enable_then_disable_is_idempotent_single_key(tmp_path: Path) -> None:
    cfg_path = _config(tmp_path)
    cli_allowlist.run_allowlist(["enable", "homelab"], config_path=str(cfg_path))
    cli_allowlist.run_allowlist(["disable", "homelab"], config_path=str(cfg_path))
    cli_allowlist.run_allowlist(["disable", "homelab"], config_path=str(cfg_path))
    text = cfg_path.read_text(encoding="utf-8")
    assert text.count("homelab =") == 1          # upsert, not append-duplicate
    assert "homelab = false" in text


def test_enable_unknown_name_is_operational_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError) as exc:
        cli_allowlist.run_allowlist(["enable", "bogus"], config_path=str(_config(tmp_path)))
    assert not isinstance(exc.value, UsageError)


def test_enable_no_config_is_operational_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No --config AND no file on the (monkeypatched, empty) search path.
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [tmp_path / "nope.toml"])
    with pytest.raises(ValueError) as exc:
        cli_allowlist.run_allowlist(["enable", "homelab"], config_path=None)
    assert "no config found" in str(exc.value)
    assert not isinstance(exc.value, UsageError)


# ── copy ──────────────────────────────────────────────────────────────────────


def test_copy_seeds_file_with_header_additive(tmp_path: Path, capsys) -> None:
    cli_allowlist.run_allowlist(["copy", "common"], config_path=str(_config(tmp_path)))
    out = capsys.readouterr().out
    dest = _allowlist_d(tmp_path) / "domains_common_local"
    assert dest.exists()
    text = dest.read_text(encoding="utf-8")
    assert text.startswith("# forked from sigwood shipped 'common' on ")
    assert "sigwood allowlist disable common" in text
    # The shipped content rode along (additive fork).
    shipped = al._shipped_path(next(s for s in al._SHIPPED_LISTS if s.name == "common"))
    assert al.load_pattern_file(shipped)[0] in text
    assert "copied common" in out


def test_copy_as_newname(tmp_path: Path) -> None:
    cli_allowlist.run_allowlist(["copy", "common", "as", "mine"], config_path=str(_config(tmp_path)))
    assert (_allowlist_d(tmp_path) / "domains_mine").exists()


@pytest.mark.parametrize("bad", ["a/b", "../x", "..", ".", "sub/", ""])
def test_copy_rejects_path_like_newname(tmp_path: Path, bad: str) -> None:
    # `as <newname>` is a bare token - a separator / `..` is a UsageError, never a
    # confusing ENOENT or an incidental near-escape. The guard fires BEFORE any
    # mkdir/write, so nothing is created.
    with pytest.raises(UsageError):
        cli_allowlist.run_allowlist(
            ["copy", "common", "as", bad], config_path=str(_config(tmp_path)))
    assert not (tmp_path / "allowlist.d").exists()


def test_copy_refuses_existing(tmp_path: Path) -> None:
    cli_allowlist.run_allowlist(["copy", "common"], config_path=str(_config(tmp_path)))
    with pytest.raises(ValueError) as exc:
        cli_allowlist.run_allowlist(["copy", "common"], config_path=str(_config(tmp_path)))
    assert "already exists" in str(exc.value)
    assert not isinstance(exc.value, UsageError)


def test_copy_errors_when_allowlist_dir_disabled(tmp_path: Path) -> None:
    # An explicit allowlist_dir="" disables drop-in discovery - copy must REFUSE
    # rather than seed a file the resolver will never load.
    cfg_path = _config(tmp_path, body='allowlist_dir = ""\n')
    with pytest.raises(ValueError) as exc:
        cli_allowlist.run_allowlist(["copy", "devices"], config_path=str(cfg_path))
    assert "allowlist_dir is empty" in str(exc.value)
    assert not isinstance(exc.value, UsageError)


def test_copy_no_config_under_isolated_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    # copy writes a FILE, not config keys - it must work with NO config, seeding
    # into the resolved allowlist_dir under the effective root.
    monkeypatch.setenv("SIGWOOD_ROOT", str(tmp_path))
    monkeypatch.setattr(cfg, "SEARCH_PATHS", [tmp_path / "nope.toml"])
    cli_allowlist.run_allowlist(["copy", "devices"], config_path=None)
    assert (tmp_path / "allowlist.d" / "domains_devices_local").exists()


# ── bad subcommand ────────────────────────────────────────────────────────────


def test_unknown_subcommand_is_usage_error(tmp_path: Path) -> None:
    with pytest.raises(UsageError):
        cli_allowlist.run_allowlist(["frobnicate"], config_path=str(_config(tmp_path)))


# ── CLI boundary ──────────────────────────────────────────────────────────────


def test_allowlist_help_is_side_effect_light(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    # `allowlist -h` must NOT compute a plan (help short-circuits before dispatch).
    def _boom(*a, **k):
        raise AssertionError("resolve_allowlist_plan must not run on -h")
    monkeypatch.setattr(al, "resolve_allowlist_plan", _boom)
    rc = cli._main(["allowlist", "-h"])
    assert rc == 0
    assert "allowlist" in capsys.readouterr().out


def test_global_help_lists_allowlist_verb() -> None:
    assert "allowlist" in cli._global_usage_text()


# ── copy: kind-equality validation (the dot rule) ─────────────────────────────


@pytest.mark.parametrize("bad", ["my.list", "backup~", "my.toml"])
def test_copy_rejects_names_the_loader_would_not_read(tmp_path: Path, bad: str) -> None:
    """copy seeds ONLY a flat list of the SAME KIND: reject unless
    _classify_dropin(dest) == spec.kind. `my.list` -> a dot (None); `backup~` -> ~
    (None); `my.toml` -> stanza (!= domain). Each kills a different weak predicate,
    and `my.toml` is the one a bare `is not None` check would wrongly accept (into
    the TOMLDecodeError crash). Nothing is written on rejection."""
    with pytest.raises(UsageError):
        cli_allowlist.run_allowlist(
            ["copy", "common", "as", bad], config_path=str(_config(tmp_path)))
    assert not (tmp_path / "allowlist.d").exists()   # reject fires before any mkdir/write


def test_copy_accepts_only_names_classifying_as_spec_kind(tmp_path: Path) -> None:
    """Every name copy ACCEPTS composes a dest classifying AS spec.kind (not merely
    non-None) - the composed file is one the resolver will load as that kind."""
    cli_allowlist.run_allowlist(
        ["copy", "common", "as", "sites"], config_path=str(_config(tmp_path)))
    dest = _allowlist_d(tmp_path) / "domains_sites"
    assert dest.exists()
    assert al._classify_dropin(dest.name) == "domain"


def test_copy_has_no_shipped_host_list_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A synthetic shipped host list cannot cross the kind-equality gate."""
    spec = al.ShippedList(
        "synthetic-hosts", "host", True, "hosts_synthetic", "test",
    )
    source = tmp_path / "hosts_synthetic"
    source.write_text("lab-*\n", encoding="utf-8")
    monkeypatch.setattr(al, "_SHIPPED_LISTS", (spec,))
    monkeypatch.setattr(al, "_shipped_path", lambda item: source)

    with pytest.raises(UsageError):
        cli_allowlist.run_allowlist(
            ["copy", "synthetic-hosts"], config_path=str(_config(tmp_path)),
        )
    assert not (tmp_path / "allowlist.d").exists()


def test_readout_nudges_ignored_dotted_dropin_silent_on_unprefixed(
    tmp_path: Path, capsys,
) -> None:
    """A dotted prefixed file (domains_user.txt) does NOT load but earns the readout
    rename nudge; an unprefixed dotted file (notes.txt) stays SILENT - nudging its
    rename would train the user wrong."""
    d = _allowlist_d(tmp_path)
    (d / "domains_user.txt").write_text("x.example.com\n", encoding="utf-8")
    (d / "notes.txt").write_text("nothing\n", encoding="utf-8")

    cli_allowlist.run_allowlist([], config_path=str(_config(tmp_path)))
    out = capsys.readouterr().out
    assert ("domains_user.txt: not loaded - drop-ins carry no extension; "
            "rename to domains_user") in out
    assert "notes.txt" not in out


def test_readout_dotted_universal_earns_extension_nudge_not_shadow(
    tmp_path: Path, capsys,
) -> None:
    """Under the dot rule a dotted domains_universal.txt is IGNORED - it earns the
    extension/rename nudge, NOT the legacy shipped-shadow nudge (only the dot-free
    domains_universal shadows)."""
    (_allowlist_d(tmp_path) / "domains_universal.txt").write_text(
        "x.example.com\n", encoding="utf-8")
    cli_allowlist.run_allowlist([], config_path=str(_config(tmp_path)))
    out = capsys.readouterr().out
    assert "domains_universal.txt: not loaded" in out
    assert "rename to domains_universal" in out
    assert "disable common to replace" not in out    # NOT the shadow nudge


def test_readout_ignored_nudge_neutralizes_control_bytes(tmp_path: Path, capsys) -> None:
    """A hostile allowlist.d filename carrying terminal control bytes is neutralized
    in the ignored-file nudge - it cannot inject an escape sequence into the analyst's
    terminal (the output control-byte hygiene rail). Strip is a no-op on clean names."""
    d = _allowlist_d(tmp_path)
    (d / "domains_\x1b[2Jx.txt").write_text("x.example.com\n", encoding="utf-8")
    cli_allowlist.run_allowlist([], config_path=str(_config(tmp_path)))
    out = capsys.readouterr().out
    assert "\x1b" not in out                              # ESC stripped from the sink
    assert "domains_[2Jx.txt: not loaded" in out          # name shown, control byte gone
    assert "rename to domains_[2Jx" in out


# ── readout / show control-byte neutralization (the whole verb surface) ────────


def test_readout_your_lists_neutralizes_control_bytes_in_filename(tmp_path: Path, capsys) -> None:
    """A hostile drop-in FILENAME carrying ESC + BEL renders in `your lists` with
    neither byte reaching stdout (a shared allowlist repo / cloned tree is the vector)."""
    d = _allowlist_d(tmp_path)
    (d / "domains_a\x1b[31mb\x07").write_text("*.example.com\n", encoding="utf-8")
    cli_allowlist.run_allowlist([], config_path=str(_config(tmp_path)))
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    assert "your lists" in out
    assert "domains_a[31mb" in out                 # inert printable residue, no ESC


def test_show_neutralizes_control_bytes_in_content(tmp_path: Path, capsys) -> None:
    """`show` renders FILE CONTENT by design - a hostile pattern line carrying C0
    (ESC, BEL) AND the single-byte C1 CSI (\\x9b) is stripped at the emit seam."""
    d = _allowlist_d(tmp_path)
    (d / "domains_site").write_text(
        "PWN\x1b[31m\x07\x9bmid.example.com\n", encoding="utf-8")
    cli_allowlist.run_allowlist(["show", "domains_site"], config_path=str(_config(tmp_path)))
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out and "\x9b" not in out   # C0 + C1 witnessed
    assert "PWN[31m" in out                         # inert residue only


def test_readout_config_derived_values_neutralized_at_emit_seam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    """The dir_label (allowlist_dir) and an explicit config-path list's path reach
    the readout sink but a raw TOML value cannot carry a control byte - inject via a
    crafted plan so the proof is the emit seam, not the loader. Both are stripped."""
    dropin = al.ResolvedList(
        "domains_d\x1b[31mx\x07", "domain", "dropin", Path("/x/domains_dx"), True, "drop-in", 1)
    cfgpath = al.ResolvedList(
        "l", "domain", "config-path", Path("/etc\x1b[32mp\x07/list.txt"), True, "config path", 2)
    plan = al.AllowlistPlan(master_enabled=True, lists=[dropin, cfgpath], entries=())
    monkeypatch.setattr(al, "resolve_allowlist_plan", lambda config: plan)
    monkeypatch.setattr(al, "resolve_allowlist_dir", lambda config: Path("/home\x1b[33mald\x07"))
    cli_allowlist.run_allowlist([], config_path=str(_config(tmp_path)))
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    assert "your lists" in out and "config lists" in out


def test_readout_your_lists_alignment_survives_sanitize(tmp_path: Path, capsys) -> None:
    """Sanitize BEFORE the width calc. Two drop-ins with UNEQUAL sanitized name
    lengths, the shorter carrying an embedded control byte (one char longer raw): the
    shorter must be padded (`.ljust`) to the SANITIZED max, so the rows come out equal
    length. Fails two ways - if the width derives from raw values / the line is
    stripped after `.ljust` (the control row renders short and misaligns), or if the
    sanitized value is never padded (the shorter row stays short)."""
    d = _allowlist_d(tmp_path)
    (d / "domains_x\x1by").write_text("*.a.example.com\n", encoding="utf-8")    # sanitized "domains_xy" (10)
    (d / "domains_pqrst").write_text("*.b.example.com\n", encoding="utf-8")     # "domains_pqrst" (13)
    cli_allowlist.run_allowlist([], config_path=str(_config(tmp_path)))
    out = capsys.readouterr().out
    assert "\x1b" not in out
    rows = [ln for ln in out.splitlines() if ln.startswith("  domains_")]
    assert len(rows) == 2
    assert len(rows[0]) == len(rows[1])             # identical column alignment


def test_show_shipped_lists_byte_identical(tmp_path: Path, capsys) -> None:
    """The sanitizer is a no-op on the pure-ASCII shipped lists: `show <shipped>`
    equals the loaded patterns verbatim (proves no shipped-data regression without a
    hand-copied golden)."""
    for name in ("common", "devices", "homelab"):
        cli_allowlist.run_allowlist(["show", name], config_path=str(_config(tmp_path)))
        out = capsys.readouterr().out.rstrip("\n")
        spec = next(s for s in al._SHIPPED_LISTS if s.name == name)
        expected = "\n".join(al.load_pattern_file(al._shipped_path(spec)))
        assert out == expected
