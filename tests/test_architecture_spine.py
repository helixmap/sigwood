"""Focused tests for detector discovery and output plumbing."""

from __future__ import annotations

import ast
import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pandas as pd

from sigwood.common.allowlist import AllowlistMatcher, build_matcher
from sigwood.common.finding import Finding, RunSummary, Severity
from sigwood.common.output import Reporter, get_handler
from sigwood.runner import (
    build_run_plan,
    discover_detectors,
    resolve_detect,
    select_detectors,
)


def _summary() -> RunSummary:
    now = datetime(2026, 5, 30, tzinfo=timezone.utc)
    return RunSummary(
        data_window=(now, now),
        record_counts={"conn*.log*": 1},
        data_size_bytes=0,
        detectors_run=["beacon"],
        detectors_skipped={},
    )


def _finding() -> Finding:
    now = datetime(2026, 5, 30, tzinfo=timezone.utc)
    return Finding(
        detector="beacon",
        severity=Severity.MEDIUM,
        title="periodic flow",
        description="A periodic flow was observed.",
        evidence={"beacon_score": 0.61, "conn_count": 20},
        next_steps=["Review the source host."],
        ts_generated=now,
        data_window=(now, now),
    )


class ArchitectureSpineTests(unittest.TestCase):
    """Small checks for the app's detector and output boundaries."""

    def test_discover_detectors_excludes_planned_stubs(self) -> None:
        detectors = discover_detectors()

        self.assertIn("beacon", detectors)
        self.assertIn("dns", detectors)
        self.assertIn("duration", detectors)
        for planned in ("auth", "ssl", "protocol", "weird", "dnsblock"):
            self.assertNotIn(planned, detectors)

    def test_html_splitter_is_the_sole_outputs_to_parsers_import(self) -> None:
        """Pin the one approved presentation dependency on parser grammar."""
        outputs_root = Path(__file__).resolve().parent.parent / "sigwood" / "outputs"
        imports = []
        for source_path in outputs_root.rglob("*.py"):
            tree = ast.parse(
                source_path.read_text(encoding="utf-8"), filename=str(source_path)
            )
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    if node.module and node.module.startswith("sigwood.parsers"):
                        imports.append(
                            (
                                source_path.name,
                                node.module,
                                tuple(alias.name for alias in node.names),
                            )
                        )
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("sigwood.parsers"):
                            imports.append((source_path.name, alias.name, ()))

        self.assertEqual(
            imports,
            [("html.py", "sigwood.parsers.syslog", ("split_header",))],
        )

    def test_resolve_detect_all_uses_available_detectors_only(self) -> None:
        available = sorted(discover_detectors())

        self.assertEqual(resolve_detect("all", available), available)
        self.assertIn("duration", resolve_detect("all", available))

    def test_default_selection_uses_explicit_curated_membership(self) -> None:
        selection = select_detectors(None)

        self.assertEqual(
            selection.selected,
            ["aws", "beacon", "dns", "scan", "syslog"],
        )
        self.assertTrue(selection.used_default)
        self.assertNotIn("duration", selection.selected)

    def test_default_keyword_is_additive_and_exclusions_apply_last(self) -> None:
        available = ["aws", "beacon", "dns", "duration", "scan", "syslog"]
        curated = ["aws", "beacon", "dns", "scan", "syslog"]

        self.assertEqual(
            resolve_detect("default", available, default_members=curated),
            curated,
        )
        self.assertEqual(
            resolve_detect(
                "default,duration", available, default_members=curated,
            ),
            curated + ["duration"],
        )
        self.assertEqual(
            resolve_detect(
                "default,!beacon", available, default_members=curated,
            ),
            ["aws", "dns", "scan", "syslog"],
        )

    def test_detector_without_membership_does_not_join_default(self) -> None:
        detectors = {
            "included": SimpleNamespace(IN_DEFAULT_HUNT=True),
            "future": SimpleNamespace(),
        }

        selection = select_detectors(None, detectors)

        self.assertEqual(selection.selected, ["included"])
        self.assertTrue(selection.used_default)

    def test_used_default_tracks_effective_spec_tokens(self) -> None:
        detectors = {"alpha": SimpleNamespace(IN_DEFAULT_HUNT=True)}

        self.assertTrue(select_detectors(None, detectors).used_default)
        self.assertTrue(select_detectors("", detectors).used_default)
        self.assertTrue(select_detectors("default", detectors).used_default)
        self.assertFalse(select_detectors("all", detectors).used_default)
        self.assertFalse(select_detectors("alpha", detectors).used_default)
        self.assertFalse(select_detectors(" ", detectors).used_default)

    def test_resolve_detect_unknown_inclusion_raises(self) -> None:
        available = ["aws", "beacon", "dns", "duration", "scan", "syslog"]

        with self.assertRaises(ValueError) as ctx:
            resolve_detect("beacn", available)
        self.assertEqual(
            str(ctx.exception),
            "unknown detector 'beacn' - available: "
            "aws, beacon, dns, duration, scan, syslog",
        )

    def test_resolve_detect_unknown_exclusion_raises(self) -> None:
        """A typo'd exclusion silently running a detector is the inverse
        coverage bug - exclusions validate exactly like inclusions."""
        available = ["aws", "beacon", "dns", "duration", "scan", "syslog"]

        with self.assertRaises(ValueError) as ctx:
            resolve_detect("all,!syslgo", available)
        self.assertEqual(
            str(ctx.exception),
            "unknown detector 'syslgo' - available: "
            "aws, beacon, dns, duration, scan, syslog",
        )

    def test_resolve_detect_multiple_unknowns_first_seen_deduped(self) -> None:
        available = ["aws", "beacon", "dns", "duration", "scan", "syslog"]

        with self.assertRaises(ValueError) as ctx:
            resolve_detect("beacn,!syslgo,beacn", available)
        self.assertEqual(
            str(ctx.exception),
            "unknown detectors 'beacn', 'syslgo' - available: "
            "aws, beacon, dns, duration, scan, syslog",
        )

    def test_resolve_detect_valid_specs_unchanged(self) -> None:
        available = ["aws", "beacon", "dns", "duration", "scan", "syslog"]

        self.assertEqual(resolve_detect("dns, beacon", available), ["dns", "beacon"])
        self.assertEqual(
            resolve_detect("all, !syslog", available),
            ["aws", "beacon", "dns", "duration", "scan"],
        )
        self.assertEqual(
            resolve_detect("all,!dns,!syslog", available),
            ["aws", "beacon", "duration", "scan"],
        )

    def test_resolve_detect_whitespace_only_spec_empty_no_raise(self) -> None:
        """A spec that tokenises to nothing is a legal empty selection, not an
        error - the caller-side default-spec fallback catches the
        EMPTY string before this function ever sees it, so whitespace-only is
        the one nothing-shaped spec that reaches resolution."""
        available = ["aws", "beacon", "dns", "duration", "scan", "syslog"]

        self.assertEqual(resolve_detect(" ", available), [])

    def test_reporter_delivers_to_registered_json_handler(self) -> None:
        stream = io.StringIO()
        handler_cls = get_handler("json")
        handler = handler_cls(stream=stream)

        Reporter([handler]).run([_finding()], _summary())

        payload = json.loads(stream.getvalue())
        self.assertEqual(payload["run_summary"]["detectors_run"], ["beacon"])
        self.assertEqual(payload["findings"][0]["detector"], "beacon")
        self.assertEqual(payload["findings"][0]["evidence"]["beacon_score"], 0.61)

    def test_csv_handler_emits_fixed_worklist_columns(self) -> None:
        """csv is a fixed worklist: a stable header (no dynamic ``evidence.*``
        columns) with curated evidence folded into the ``signals`` cell."""
        stream = io.StringIO()
        handler_cls = get_handler("csv")
        handler = handler_cls(stream=stream)

        Reporter([handler]).run([_finding()], _summary())

        output = stream.getvalue()
        header = output.splitlines()[0]
        self.assertEqual(
            header,
            "severity,detector,finding,next_steps,description,signals,"
            "data_window_start,data_window_end,status,notes",
        )
        self.assertNotIn("evidence.", header)
        # curated evidence rides the signals cell as k=v (no JSON brackets)
        self.assertIn("beacon_score=0.61", output)

    def test_connection_rules_are_local_only_by_default(self) -> None:
        matcher = build_matcher({"allowlist": {"domain_patterns": []}})

        self.assertEqual(matcher._numeric_rules, [])

    def test_configured_connection_rule_file_still_filters_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rules_path = Path(tmp) / "connections.txt"
            rules_path.write_text("192.0.2.10  198.51.100.20  :443/tcp\n", encoding="utf-8")
            matcher = build_matcher({
                "allowlist": {
                    "domain_patterns": [],
                    "connection_rules": [str(rules_path)],
                }
            })

        df = pd.DataFrame([
            {"src": "192.0.2.10", "dst": "198.51.100.20", "port": 443, "proto": "tcp"},
            {"src": "192.0.2.11", "dst": "203.0.113.20", "port": 443, "proto": "tcp"},
        ])

        filtered = matcher.filter_df(df, "beacon")

        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered.iloc[0]["src"], "192.0.2.11")

    def test_configured_connection_rule_file_filters_duration_rows(self) -> None:
        """Unscoped flat-file rule suppresses duration the same way it suppresses beacon.

        Locks the filter-before-analyze pass-through for duration: omission of
        scope is permission for every connection detector that groups on the
        canonical (src, dst, port, proto) tuple, not just beacon.
        """
        with tempfile.TemporaryDirectory() as tmp:
            rules_path = Path(tmp) / "connections.txt"
            rules_path.write_text("192.0.2.10  198.51.100.20  :443/tcp\n", encoding="utf-8")
            matcher = build_matcher({
                "allowlist": {
                    "domain_patterns": [],
                    "connection_rules": [str(rules_path)],
                }
            })

        df = pd.DataFrame([
            {"src": "192.0.2.10", "dst": "198.51.100.20", "port": 443, "proto": "tcp"},
            {"src": "192.0.2.11", "dst": "203.0.113.20", "port": 443, "proto": "tcp"},
        ])

        filtered = matcher.filter_df(df, "duration")

        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered.iloc[0]["src"], "192.0.2.11")

    def test_scoped_stanza_filters_duration_and_gates_unlisted_detector(self) -> None:
        """A stanza scoped to duration suppresses duration and only duration.

        Locks the scoping half of the contract: a stanza with
        ``detectors = ["duration", "beacon"]`` drops the matching row when
        called for "duration", and the same matcher leaves the row in place
        when called for a detector outside the scope.
        """
        matcher = build_matcher({
            "allowlist": {
                "domain_patterns": "",
                "entry": [
                    {
                        "match": "ip_pair",
                        "src": "192.0.2.10",
                        "dst_port": 443,
                        "comment": "Example scoped flow",
                        "detectors": ["duration", "beacon"],
                    }
                ],
            }
        })

        df = pd.DataFrame([
            {"src": "192.0.2.10", "dst": "198.51.100.20", "port": 443, "proto": "tcp"},
            {"src": "192.0.2.11", "dst": "203.0.113.20", "port": 443, "proto": "tcp"},
        ])

        filtered_duration = matcher.filter_df(df, "duration")
        self.assertEqual(len(filtered_duration), 1)
        self.assertEqual(filtered_duration.iloc[0]["src"], "192.0.2.11")

        # Same matcher, same frame, a detector outside the scope - the rule
        # must NOT fire. (filter_df routes by column shape, so a connection
        # frame still flows through _filter_numeric_df for "dns"; what we are
        # asserting is that the scope check gates suppression, not the shape.)
        filtered_dns = matcher.filter_df(df, "dns")
        self.assertEqual(len(filtered_dns), 2)

    def test_connection_rule_path_can_be_operator_friendly_string(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rules_path = Path(tmp) / "connections.txt"
            rules_path.write_text("192.0.2.10  :443/tcp\n", encoding="utf-8")
            matcher = build_matcher({
                "allowlist": {
                    "domain_patterns": "",
                    "connection_rules": str(rules_path),
                }
            })

        assert len(matcher._numeric_rules) == 1
        assert matcher._numeric_rules[0].ip1 == "192.0.2.10"

    def test_stanza_detector_scope_can_be_comma_string(self) -> None:
        matcher = build_matcher({
            "allowlist": {
                "domain_patterns": "",
                "entry": [
                    {
                        "match": "dst_port",
                        "value": 443,
                        "comment": "Example scoped service",
                        "detectors": "beacon, scan",
                    }
                ],
            }
        })

        assert matcher._numeric_rules[-1].detectors == ["beacon", "scan"]

    def test_domain_patterns_filter_dns_rows_before_detection(self) -> None:
        # Construct WITH the patterns - the match engine compiles in __init__, so
        # mutating _domain_patterns post-construction does not rebuild it.
        matcher = AllowlistMatcher(domain_patterns=["*.example.test", "re:\\.allowed\\.test$"])
        df = pd.DataFrame([
            {"src": "192.0.2.10", "query": "updates.example.test"},
            {"src": "192.0.2.11", "query": "allowed.test"},
            {"src": "192.0.2.12", "query": "suspicious.invalid"},
        ])

        filtered = matcher.filter_df(df, "dns")

        self.assertEqual(filtered["query"].tolist(), ["suspicious.invalid"])

    def test_shipped_common_domains_filter_dns_infrastructure(self) -> None:
        matcher = build_matcher({"allowlist": {"domain_patterns": []}})
        df = pd.DataFrame([
            {"src": "192.0.2.10", "query": "2.0.192.in-addr.arpa"},
            {"src": "192.0.2.11", "query": "suspicious.invalid"},
        ])

        filtered = matcher.filter_df(df, "dns")

        self.assertEqual(filtered["query"].tolist(), ["suspicious.invalid"])


def test_build_run_plan_records_skips_and_needed_logs(tmp_path: Path) -> None:
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "conn.log").write_text("", encoding="utf-8")
    # Optional log must exist for the satisfiable-only filter to include it in needed_logs.
    (zeek_dir / "conn_summary.log").write_text("", encoding="utf-8")
    detectors = {
        "beacon": SimpleNamespace(
            REQUIRED_LOGS=[{"source": "zeek_dir", "pattern": "conn*.log*"}],
            OPTIONAL_LOGS=[{"source": "zeek_dir", "pattern": "conn_summary*.log*"}],
        ),
        "dns": SimpleNamespace(
            REQUIRED_LOGS=[{"source": "zeek_dir", "pattern": "dns*.log*"}],
            OPTIONAL_LOGS=[],
        ),
    }

    plan = build_run_plan("all", zeek_dir=zeek_dir, syslog_dir=None, detectors=detectors)

    assert plan.selected == ["beacon", "dns"]
    assert plan.will_run == ["beacon"]
    assert plan.skipped == {"dns": f"dns*.log* not found in {zeek_dir}"}
    assert plan.needed_logs == {
        "conn*.log*": "zeek_dir",
        "conn_summary*.log*": "zeek_dir",
    }


def test_build_run_plan_honors_exclusion_syntax(tmp_path: Path) -> None:
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "conn.log").write_text("", encoding="utf-8")
    detectors = {
        "beacon": SimpleNamespace(
            REQUIRED_LOGS=[{"source": "zeek_dir", "pattern": "conn*.log*"}],
            OPTIONAL_LOGS=[],
        ),
        "dns": SimpleNamespace(
            REQUIRED_LOGS=[{"source": "zeek_dir", "pattern": "dns*.log*"}],
            OPTIONAL_LOGS=[],
        ),
    }

    plan = build_run_plan("all,!dns", zeek_dir=zeek_dir, syslog_dir=None, detectors=detectors)

    assert plan.selected == ["beacon"]
    assert plan.will_run == ["beacon"]
    assert plan.skipped == {}


def test_allowlist_filter_tolerates_pihole_query_none_rows() -> None:
    """Domain filter must not crash on query=None rows (unknown/validation events from pihole)."""
    matcher = AllowlistMatcher(domain_patterns=["bad.example.test"])
    df = pd.DataFrame([
        {"src": "192.0.2.1", "query": "bad.example.test"},      # matches pattern - filtered out
        {"src": "192.0.2.2", "query": "harmless.example.test"},  # no match - survives
        {"src": "192.0.2.3", "query": None},                     # unknown/validation - survives
    ])
    filtered = matcher.filter_df(df, "dns")
    assert len(filtered) == 2
    surviving_queries = filtered["query"].tolist()
    assert any(pd.isna(q) for q in surviving_queries)
    assert "bad.example.test" not in surviving_queries


if __name__ == "__main__":
    unittest.main()
