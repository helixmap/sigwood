"""allowlist.d auto-discovery by filename convention + case-insensitive matching.

``build_matcher`` (via ``resolve_allowlist_plan`` + ``matcher_from_plan``)
discovers flat suppression files in the resolved allowlist_dir by the dot rule -
dot-free ``domains*`` (domain globs), ``connections*`` (numeric rules), and
``hosts*`` (system-log host patterns) -
alongside the long-standing ``*.toml`` classification stanzas. The shipped curated
lists form a base; EVERY drop-in is ADDITIVE (there is no same-basename
shadow - replacing a shipped list is ``allowlist disable <name>``). Explicit
``domain_patterns`` / ``connection_rules`` config keys remain an escape hatch for
files OUTSIDE allowlist.d. Domain matching is case-insensitive (DNS is, by spec)
on every platform.

Fixtures use example.com / RFC 5737 (192.0.2.x) only.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sigwood.common import allowlist


def _config(tmp_path: Path, **allow: object) -> dict:
    """A config rooting allowlist_dir under tmp_path via [sigwood].root."""
    base = {"allowlist_dir": "allowlist.d/", "domain_patterns": [], "connection_rules": []}
    base.update(allow)
    return {"sigwood": {"root": str(tmp_path)}, "allowlist": base}


def _mk_allowlist_d(tmp_path: Path) -> Path:
    d = tmp_path / "allowlist.d"
    d.mkdir()
    return d


def _isolate_shipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty the shipped registry - isolate a test from the curated base."""
    monkeypatch.setattr(allowlist, "_SHIPPED_LISTS", ())


def _one_shipped(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    """Register a single shipped domain list backed by ``path`` (a tmp file).
    Patches ``_shipped_path`` so the registry filename resolves to it."""
    spec = allowlist.ShippedList("common", "domain", True, "domains_common", "test")
    monkeypatch.setattr(allowlist, "_SHIPPED_LISTS", (spec,))
    monkeypatch.setattr(allowlist, "_shipped_path", lambda s: path)


def test_all_three_flat_dropin_kinds_auto_load(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _isolate_shipped(monkeypatch)
    d = _mk_allowlist_d(tmp_path)
    (d / "domains_site").write_text("*.internal.example.com\n", encoding="utf-8")
    (d / "connections_local").write_text("192.0.2.10  :443/tcp\n", encoding="utf-8")
    (d / "hosts_lab").write_text("lab-*\n", encoding="utf-8")

    matcher = allowlist.build_matcher(_config(tmp_path))

    assert matcher.is_domain_allowed("host.internal.example.com")
    assert len(matcher._numeric_rules) == 1
    assert matcher._host_patterns == ["lab-*"]


def test_dropin_basename_is_now_additive_to_shipped_list(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """A domains_* drop-in named exactly after a shipped list is ADDITIVE
    (drop-ins are always additive) - the shipped patterns SURVIVE alongside
    the drop-in's. Replacing a shipped list is ``allowlist disable <name>``."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    shipped = pkg / "domains_common"
    shipped.write_text("alpha.example.com\nbeta.example.com\n", encoding="utf-8")
    _one_shipped(monkeypatch, shipped)

    d = _mk_allowlist_d(tmp_path)
    # Same basename, with beta REMOVED from the drop-in - additive means beta
    # STILL suppressed (it survives on the shipped base).
    (d / "domains_common").write_text("alpha.example.com\n", encoding="utf-8")

    matcher = allowlist.build_matcher(_config(tmp_path))

    assert matcher.is_domain_allowed("alpha.example.com")
    assert matcher.is_domain_allowed("beta.example.com")  # shipped base survives


def test_new_domains_dropin_is_additive_to_shipped_base(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    shipped = pkg / "domains_common"
    shipped.write_text("alpha.example.com\n", encoding="utf-8")
    _one_shipped(monkeypatch, shipped)

    d = _mk_allowlist_d(tmp_path)
    (d / "domains_user").write_text("gamma.example.com\n", encoding="utf-8")

    matcher = allowlist.build_matcher(_config(tmp_path))

    assert matcher.is_domain_allowed("alpha.example.com")  # base survives
    assert matcher.is_domain_allowed("gamma.example.com")  # drop-in adds on top


def test_non_matching_txt_ignored(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _isolate_shipped(monkeypatch)
    d = _mk_allowlist_d(tmp_path)
    (d / "notes.txt").write_text("not.a.pattern.example.com\n", encoding="utf-8")

    matcher = allowlist.build_matcher(_config(tmp_path))

    assert matcher._domain_patterns == []
    assert not matcher.is_domain_allowed("not.a.pattern.example.com")


def test_absent_allowlist_dir_harmless(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _isolate_shipped(monkeypatch)
    # allowlist.d never created under root - must not raise.
    matcher = allowlist.build_matcher(_config(tmp_path))
    assert matcher._domain_patterns == []
    assert matcher._numeric_rules == []


def test_explicit_path_outside_allowlist_d_still_loads(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _isolate_shipped(monkeypatch)
    outside = tmp_path / "etc" / "extra.txt"
    outside.parent.mkdir()
    outside.write_text("vendor.example.net\n", encoding="utf-8")

    matcher = allowlist.build_matcher(_config(tmp_path, domain_patterns=[str(outside)]))

    assert matcher.is_domain_allowed("vendor.example.net")


def test_path_in_both_glob_and_explicit_key_loads_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _isolate_shipped(monkeypatch)
    d = _mk_allowlist_d(tmp_path)
    dup = d / "domains_dup"
    dup.write_text("dup.example.com\n", encoding="utf-8")

    matcher = allowlist.build_matcher(_config(tmp_path, domain_patterns=[str(dup)]))

    # Discovered by the glob AND named explicitly - dedup by resolved path → once.
    assert matcher._domain_patterns.count("dup.example.com") == 1


def test_absent_optional_explicit_file_does_not_raise(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _isolate_shipped(monkeypatch)
    missing = str(tmp_path / "does_not_exist.txt")
    matcher = allowlist.build_matcher(_config(tmp_path, domain_patterns=[missing]))
    assert matcher._domain_patterns == []


def test_allowlist_dir_relative_resolves_under_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _isolate_shipped(monkeypatch)
    d = _mk_allowlist_d(tmp_path)
    (d / "domains_site").write_text("rooted.example.com\n", encoding="utf-8")

    # Relative allowlist_dir + root=tmp_path → tmp_path/allowlist.d.
    matcher = allowlist.build_matcher(_config(tmp_path))
    assert matcher.is_domain_allowed("rooted.example.com")


def test_case_insensitive_domain_matching(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    _isolate_shipped(monkeypatch)
    # Construct WITH the patterns - the match engine is compiled in __init__, so
    # mutating the raw _domain_patterns list post-construction does not rebuild
    # it (scalar and vector paths share the same compiled objects by design).
    matcher = allowlist.AllowlistMatcher(
        domain_patterns=["*.example.com", r"re:\.allowed\.test$"]
    )

    assert matcher.is_domain_allowed("FOO.EXAMPLE.COM")        # glob, uppercased input
    assert matcher.is_domain_allowed("Host.Allowed.Test")      # regex, mixed case
    assert not matcher.is_domain_allowed("foo.notlisted.test")


# ── the dot rule: classifier + ignored advisory + reserved namespace ──────────


def test_classify_dropin_table() -> None:
    c = allowlist._classify_dropin
    assert c("domains_user") == "domain"
    assert c("domains") == "domain"              # bare prefix classifies
    assert c("connections_local") == "numeric"
    assert c("connections") == "numeric"
    assert c("hosts_lab") == "host"
    assert c("hosts") == "host"
    assert c("domains_user.txt") is None         # any other dot: ignored
    assert c("domains_user.bak") is None
    assert c("hosts.bak") is None
    assert c("x.toml") == "stanza"
    assert c("domains_user.toml") == "stanza"    # clause 3 precedes the prefix clauses
    assert c("hosts.toml") == "stanza"
    assert c(".hidden") is None                  # hidden
    assert c("domains_user~") is None            # editor backup
    assert c("hosts~") is None
    assert c("notes") is None                    # dot-free unprefixed
    assert c("legacy.txt") is None


def test_ignored_suggestion_table() -> None:
    s = allowlist._ignored_suggestion
    assert s("domains_user.txt") == "domains_user"
    assert s("connections.txt") == "connections"
    assert s("domains_user.bak") == "domains_user"
    assert s("hosts.bak") == "hosts"
    # recognized-AS-the-branch, not merely prefixed: a prefixed head that ends in ~,
    # or a ~-terminated name whose head classifies, stays silent - a prefix-only
    # implementation would wrongly suggest an inert name.
    assert s("domains_user~.bak") is None        # head "domains_user~" -> None
    assert s("domains_x.toml~") is None          # ~-terminated name, head classifies
    assert s("domains_user") is None             # loads as a list, not ignored
    assert s("domains_user.toml") is None        # loads as a stanza
    assert s("hosts.toml") is None
    assert s("legacy.txt") is None               # head unprefixed
    assert s("notes") is None
    assert s(".hidden") is None
    assert s("backup~") is None


def test_prefixed_toml_loads_as_stanza_not_domain_dropin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """domains_user.toml is a classification STANZA (clause 3 precedes the prefix
    clauses), never a domain suppression drop-in - so a later clause reorder cannot
    silently turn a stanza into a suppression list."""
    _isolate_shipped(monkeypatch)
    d = _mk_allowlist_d(tmp_path)
    (d / "domains_user.toml").write_text(
        '[[allowlist.entry]]\nmatch = "192.0.2.5"\n', encoding="utf-8")

    plan = allowlist.resolve_allowlist_plan(_config(tmp_path))
    assert [rl for rl in plan.lists if rl.origin == "dropin"] == []   # no domain drop-in
    assert len(plan.entries) == 1                                      # loaded as a stanza


def test_reserved_namespace_prefixed_dotfree_loads(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """A dot-free prefixed file is CLAIMED by the reserved namespace whatever the
    user meant by it: domains_readme loads as a domain list (and reset deletes it -
    see test_init_wizard). The rule, not the extension, is the discriminator."""
    _isolate_shipped(monkeypatch)
    d = _mk_allowlist_d(tmp_path)
    (d / "domains_readme").write_text("*.example\n", encoding="utf-8")   # valid pattern, not prose

    assert allowlist._classify_dropin("domains_readme") == "domain"
    matcher = allowlist.build_matcher(_config(tmp_path))
    assert matcher.is_domain_allowed("host.example")


def test_directory_named_hosts_never_loads(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Classification is name-only, but discovery gates regular files."""
    _isolate_shipped(monkeypatch)
    d = _mk_allowlist_d(tmp_path)
    (d / "hosts_x").mkdir()

    plan = allowlist.resolve_allowlist_plan(_config(tmp_path))
    assert not any(item.kind == "host" for item in plan.lists)
    assert allowlist.build_matcher(_config(tmp_path))._host_patterns == []


def test_packaged_hosts_template_has_no_active_patterns() -> None:
    path = Path(allowlist.__file__).parent.parent / "data" / "allowlist" / "hosts"
    assert allowlist.load_pattern_file(path) == []
    text = path.read_text(encoding="utf-8")
    assert "ENTIRE system-log story" in text
    assert "rarity is relative to the loaded corpus" in text


def test_stale_dotted_dropin_does_not_suppress(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """The security-critical direction: a stale domains_user.bak / domains_user.txt
    is dotted, so it does NOT load and does NOT suppress - a backup must never
    silently blind the hunt."""
    _isolate_shipped(monkeypatch)
    d = _mk_allowlist_d(tmp_path)
    (d / "domains_user.bak").write_text("*.bad.example\n", encoding="utf-8")
    (d / "domains_user.txt").write_text("*.also-bad.example\n", encoding="utf-8")

    matcher = allowlist.build_matcher(_config(tmp_path))
    assert matcher._domain_patterns == []
    assert not matcher.is_domain_allowed("host.bad.example")
    assert not matcher.is_domain_allowed("host.also-bad.example")


def test_explicit_path_any_extension_still_loads(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """The dot rule governs allowlist.d discovery ONLY. An explicit domain_patterns
    path OUTSIDE allowlist.d may carry ANY extension - a .txt file still loads and
    suppresses (load_pattern_file never classifies by name)."""
    _isolate_shipped(monkeypatch)
    outside = tmp_path / "etc" / "whatever.txt"
    outside.parent.mkdir()
    outside.write_text("vendor.example.net\n", encoding="utf-8")

    matcher = allowlist.build_matcher(_config(tmp_path, domain_patterns=[str(outside)]))
    assert matcher.is_domain_allowed("vendor.example.net")
