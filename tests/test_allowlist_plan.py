"""Resolver + matcher spine + scope-blind count helpers.

The single spine: ``resolve_allowlist_plan`` returns the COMPLETE resolved state
(even master-off); ``matcher_from_plan`` is where master-off / force-off becomes
an empty matcher. Count helpers mirror the filter exactly, scope-blind.

Fixtures use example.com / RFC 5737 only.
"""

from __future__ import annotations

import pandas as pd
import pytest

from sigwood.common import allowlist as al


# ── resolver ──────────────────────────────────────────────────────────────────


def test_plan_shape_default() -> None:
    plan = al.resolve_allowlist_plan({})
    assert plan.master_enabled is True
    names = {rl.name for rl in plan.lists if rl.origin == "shipped"}
    assert names == {spec.name for spec in al._SHIPPED_LISTS}
    # entries is a tuple (carried for classification / future detectors).
    assert isinstance(plan.entries, tuple)


def test_homelab_default_off_not_loaded() -> None:
    plan = al.resolve_allowlist_plan({})
    homelab = next(rl for rl in plan.lists if rl.name == "homelab")
    assert homelab.enabled is False
    # pattern_count is INDEPENDENT of enabled - a disabled list still reads its size.
    assert homelab.pattern_count == len(al.load_pattern_file(homelab.path))
    assert homelab.pattern_count > 0

    matcher = al.matcher_from_plan(plan)
    common = next(rl for rl in plan.lists if rl.name == "common")
    devices = next(rl for rl in plan.lists if rl.name == "devices")
    assert len(matcher._domain_patterns) == common.pattern_count + devices.pattern_count


def test_homelab_toggle_on_loads() -> None:
    plan = al.resolve_allowlist_plan({"allowlist": {"lists": {"homelab": True}}})
    homelab = next(rl for rl in plan.lists if rl.name == "homelab")
    assert homelab.enabled is True
    assert homelab.state_reason == "config"

    matcher = al.matcher_from_plan(plan)
    base = al.matcher_from_plan(al.resolve_allowlist_plan({}))
    assert len(matcher._domain_patterns) == len(base._domain_patterns) + homelab.pattern_count


def test_resolve_allowlist_dir_preserves_empty_value() -> None:
    # An explicit allowlist_dir="" is PRESERVED (drop-ins disabled) → None, NOT
    # silently defaulted to allowlist.d/.
    assert al.resolve_allowlist_dir({"allowlist": {"allowlist_dir": ""}}) is None


def test_resolve_allowlist_dir_defaults_when_absent(tmp_path) -> None:
    d = al.resolve_allowlist_dir({"sigwood": {"root": str(tmp_path)}, "allowlist": {}})
    assert d == tmp_path / "allowlist.d"


def test_master_off_resolver_returns_complete_plan() -> None:
    plan = al.resolve_allowlist_plan({"allowlist": {"enabled": False}})
    # Resolver does NOT empty out - the readout still works under master-off.
    assert plan.master_enabled is False
    assert {rl.name for rl in plan.lists if rl.origin == "shipped"} == {
        spec.name for spec in al._SHIPPED_LISTS
    }


def test_host_dropins_resolve_sorted_deduped_after_numeric(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(al, "_SHIPPED_LISTS", ())
    dropins = tmp_path / "allowlist.d"
    dropins.mkdir()
    (dropins / "domains_z").write_text("z.example\n", encoding="utf-8")
    (dropins / "connections_z").write_text(":443\n", encoding="utf-8")
    first = dropins / "hosts_a"
    first.write_text("lab-*\n# note\nre:^kiosk-[0-9]+$\n", encoding="utf-8")
    (dropins / "hosts_b").symlink_to(first)
    config = {
        "sigwood": {"root": str(tmp_path)},
        "allowlist": {
            "allowlist_dir": "allowlist.d", "domain_patterns": [],
            "connection_rules": [],
        },
    }

    plan = al.resolve_allowlist_plan(config)
    dropin_lists = [item for item in plan.lists if item.origin == "dropin"]
    assert [(item.name, item.kind) for item in dropin_lists] == [
        ("domains_z", "domain"),
        ("connections_z", "numeric"),
        ("hosts_a", "host"),
    ]
    host = dropin_lists[-1]
    assert host.enabled is True
    assert host.state_reason == "drop-in"
    assert host.pattern_count == 2


def test_master_and_force_off_leave_host_rules_inert(tmp_path) -> None:
    dropins = tmp_path / "allowlist.d"
    dropins.mkdir()
    (dropins / "hosts_lab").write_text("lab-*\n", encoding="utf-8")
    base = {
        "sigwood": {"root": str(tmp_path)},
        "allowlist": {"allowlist_dir": "allowlist.d"},
    }
    off_config = {
        **base,
        "allowlist": {"allowlist_dir": "allowlist.d", "enabled": False},
    }
    plan = al.resolve_allowlist_plan(off_config)
    assert any(item.kind == "host" for item in plan.lists)
    assert al.matcher_from_plan(plan)._host_patterns == []

    on_plan = al.resolve_allowlist_plan(base)
    assert al.matcher_from_plan(on_plan, force_off=True)._host_patterns == []


def test_host_count_short_circuits_without_patterns_or_column() -> None:
    matcher = al.AllowlistMatcher()
    assert matcher.count_host_suppressed(pd.DataFrame({"host": ["lab-a"]})) == (0, set())
    matcher = al.AllowlistMatcher(host_patterns=["lab-*"])
    assert matcher.count_host_suppressed(pd.DataFrame({"message": ["x"]})) == (0, set())


# ── matcher_from_plan ─────────────────────────────────────────────────────────


def _stanza_config() -> dict:
    return {
        "allowlist": {
            "entry": [
                {"match": "dst_port", "value": 9999, "comment": "test"},
            ],
        }
    }


def test_master_off_matcher_is_empty_and_drops_stanza_rules() -> None:
    plan = al.resolve_allowlist_plan({**_stanza_config(), "allowlist": {
        "enabled": False, "entry": [{"match": "dst_port", "value": 9999}]}})
    matcher = al.matcher_from_plan(plan)
    assert matcher._domain_patterns == []
    assert matcher._numeric_rules == []          # stanza-derived rule dropped too


def test_force_off_matcher_is_empty_and_drops_stanza_rules() -> None:
    plan = al.resolve_allowlist_plan({"allowlist": {
        "entry": [{"match": "dst_port", "value": 9999}]}})
    # force_off is a MATCHER param, never a resolver input - the plan still has entries.
    assert len(plan.entries) == 1
    matcher = al.matcher_from_plan(plan, force_off=True)
    assert matcher._domain_patterns == []
    assert matcher._numeric_rules == []


def test_stanzas_convert_when_enabled() -> None:
    plan = al.resolve_allowlist_plan({"allowlist": {
        "entry": [{"match": "dst_port", "value": 9999}]}})
    matcher = al.matcher_from_plan(plan)
    assert any(r.port == 9999 for r in matcher._numeric_rules)


# ── scope-blind count helpers ─────────────────────────────────────────────────


def test_count_domain_parity_with_filter() -> None:
    matcher = al.AllowlistMatcher(domain_patterns=[r"re:\.example\.com$"])
    df = pd.DataFrame({"query": [
        "host.example.com",        # matches via "x." + q (parent)
        "example.com",             # matches direct
        "other.example.net",       # no match
    ]})
    filtered = matcher.filter_df(df, "dns")
    expected = len(df) - len(filtered)
    assert matcher.count_domain_suppressed(df) == expected == 2


def test_count_numeric_includes_stanza_and_ignores_scope() -> None:
    # A rule scoped to ONE detector - scope-blind count must still count it.
    scoped = al.NumericRule(port=9999, detectors=["duration"])
    matcher = al.AllowlistMatcher(numeric_rules=[scoped])
    df = pd.DataFrame({
        "src": ["192.0.2.10", "192.0.2.11"],
        "dst": ["198.51.100.20", "198.51.100.21"],
        "port": [9999, 443],
        "proto": ["tcp", "tcp"],
    })
    # filter_df under a DIFFERENT detector suppresses nothing (scope), but the
    # scope-blind coverage count sees the rule.
    assert len(matcher.filter_df(df, "beacon")) == 2
    assert matcher.count_numeric_suppressed(df) == 1


def test_count_helpers_short_circuit_when_empty() -> None:
    empty = al.AllowlistMatcher()
    df = pd.DataFrame({"query": ["x.example.com"]})
    conn = pd.DataFrame({"src": ["192.0.2.10"], "dst": ["198.51.100.20"],
                         "port": [443], "proto": ["tcp"]})
    assert empty.count_domain_suppressed(df) == 0
    assert empty.count_numeric_suppressed(conn) == 0


# ── stanza shape errors - actionable, never a bare KeyError ──────────────────


def test_stanza_file_missing_match_raises_actionable(tmp_path) -> None:
    """A *.toml stanza without a 'match' key is a user-config mistake and must
    surface as an actionable message naming the file - never KeyError."""
    roles = tmp_path / "roles.toml"
    roles.write_text(
        '[[allowlist.entry]]\nrole = "nameserver"\nip = "192.0.2.53"\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError) as excinfo:
        al.load_stanza_file(roles)
    msg = str(excinfo.value)
    assert "roles.toml" in msg
    assert "'match'" in msg
    assert "ip_pair" in msg  # the message teaches the fix


def test_inline_stanza_missing_match_raises_actionable() -> None:
    """The inline [[allowlist.entry]] path gets the same guard, naming the
    config origin instead of a file."""
    with pytest.raises(ValueError) as excinfo:
        al.resolve_allowlist_plan(
            {"allowlist": {"entry": [{"role": "nameserver"}]}}
        )
    assert "[[allowlist.entry]] in config" in str(excinfo.value)


def test_malformed_stanza_toml_names_the_file(tmp_path) -> None:
    """A drop-in that fails TOML parsing points the operator at the offending
    file, not an anonymous parse error."""
    bad = tmp_path / "bad.toml"
    bad.write_text("not = valid = toml\n", encoding="utf-8")
    with pytest.raises(ValueError) as excinfo:
        al.load_stanza_file(bad)
    msg = str(excinfo.value)
    assert "bad.toml" in msg
    assert "not valid TOML" in msg
