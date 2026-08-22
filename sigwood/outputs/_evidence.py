"""Shared reading-level policy for the human render surfaces (text + html).

``curated_evidence`` / ``is_empty`` / ``cap_evidence_list`` were MOVED here from
``text.py`` byte-identical so text and html cannot drift on *what* shows at a
level. ``evidence_at_level`` is the shared reading-depth dial.

This is output-OWNED render policy (the only shared behavioural coupling between
the human formats). It is never imported by ``detectors/`` or ``common/`` - the
detector result set stays verbosity-invariant; tiering happens here at render.
"""

from __future__ import annotations

from operator import index
from typing import Any

from sigwood.common.display import plural
from sigwood.common.finding import Finding, Severity

# Curated (level-1) cap for long evidence LISTS. The full list still appears at
# level 2 (the debug tail renders the raw evidence dict); this only keeps `-v`
# readable when a burst touches dozens of actions/services.
_CURATED_LIST_CAP = 12
EXFIL_MEMBER_DISPLAY_CAP = 10


def cap_evidence_list(values: "list | tuple") -> str:
    """First N items comma-joined, then a ``… (+K more)`` overflow marker.

    Returns a STRING (the renderer prints evidence values via ``f"{v}"``, so a
    raw list would dump its Python repr - the 90-action wall this replaces)."""
    items = [str(v) for v in values]
    if len(items) <= _CURATED_LIST_CAP:
        return ", ".join(items)
    shown = ", ".join(items[:_CURATED_LIST_CAP])
    return f"{shown}, … (+{len(items) - _CURATED_LIST_CAP} more)"


def sample_bound_note(
    total: object,
    shown: object,
    noun: object = "rare line",
) -> str | None:
    """Describe a positive integral sample shortfall, or vanish defensively."""
    if (
        isinstance(total, bool)
        or isinstance(shown, bool)
        or not isinstance(noun, str)
        or not noun
    ):
        return None
    try:
        total_int = int(index(total))
        shown_int = int(index(shown))
    except TypeError:
        return None
    if total_int <= 0 or shown_int <= 0 or total_int <= shown_int:
        return None
    return (
        f"showing {shown_int} of {total_int} "
        f"{plural(total_int, noun)}"
    )


def exfil_members_at_level(
    finding: Finding,
    level: int,
) -> tuple[list[dict[str, Any]], str | None]:
    """Return the shared human member slice for a destination-pool rollup."""
    if (
        finding.detector != "exfil"
        or finding.evidence.get("tier") != "destination_pool"
    ):
        return [], None
    raw_members = finding.evidence.get("members")
    if not isinstance(raw_members, (list, tuple)):
        return [], None
    members = [member for member in raw_members if isinstance(member, dict)]
    shown = members if level >= 2 else members[:EXFIL_MEMBER_DISPLAY_CAP]
    return shown, sample_bound_note(len(members), len(shown), "destination")


# Per-detector curated-evidence subsets for level 1 - tolerant: omit absent
# keys rather than printing ``None``. Per-variant lookup uses existing
# evidence keys (scan's scan_type, dns's source, aws's tier, syslog's tier).
def curated_evidence(finding: Finding) -> dict[str, Any]:
    """Return ONLY the keys present on this Finding from the curated set for
    its detector (and variant where applicable)."""
    ev = finding.evidence
    keys: tuple[str, ...] = ()
    always_keys: tuple[str, ...] = ()
    det = finding.detector

    if det == "beacon":
        keys = (
            "beacon_score", "spectral_ratio", "prominence_norm",
            "jitter_cv", "conn_count", "period_str",
            "first_seen", "span_seconds",
        )
    elif det == "dns":
        # An empty basis is meaningful: it says no behavioral severity leg
        # fired. Keep that DNS-specific signal visible at the curated level.
        always_keys = ("severity_basis",)
        src = ev.get("source")
        if "subdomain_count" in ev:  # group
            base = (
                "severity_basis", "sample_domains", "unique_sources",
                "min_label_score", "max_label_score",
            )
            extra = (
                ("was_blocked", "block_ratio", "qtype_counts")
                if src == "pihole"
                else ("nxdomain_fraction", "nxdomain_count")
            )
            keys = base + extra
        elif src == "pihole":  # pihole singleton
            keys = (
                "severity_basis",
                "unique_sources", "querier_ips",
                "was_blocked", "block_ratio",
                "cache_ratio", "forward_ratio", "qtype_counts",
            )
        else:  # zeek singleton (and both-mode Zeek with pihole enrichment)
            base = (
                "severity_basis", "nxdomain_fraction", "nxdomain_count",
                "rcode_distribution", "unique_sources", "querier_ips",
            )
            extra = ("was_blocked", "block_ratio") if "was_blocked" in ev else ()
            keys = base + extra
    elif det == "dnsblock":
        kind = ev.get("kind")
        if kind == "arrival":
            keys = (
                "coverage_lane", "qualifying_name_count", "attributed_query_count",
                "active_periods", "eligible_periods", "first_associated_period",
                "history_seconds",
                "prior_other_address_count", "prior_other_address_count_at_cap",
            )
        elif kind == "burst":
            keys = (
                "coverage_lane", "peak_count", "peak_period_start",
                "baseline_median_twice", "active_periods", "eligible_periods",
                "attributed_query_count", "arrival_qualified",
            )
        elif kind == "arrival_fold":
            keys = (
                "coverage_lane", "member_count", "earliest_first_associated_period",
                "history_seconds",
                "members_omitted", "distinct_report_addresses", "shares_available",
            )
        elif kind == "prior_handling_exclusions":
            keys = ("withheld_name_count", "withheld_membership_count")
        elif kind == "recurring_activity":
            keys = (
                "coverage_lane", "pair_count", "family_count", "address_count",
                "periods_required", "periods_total",
            )
    elif det == "syslog":
        tier = ev.get("tier")
        if tier == "burst":
            keys = (
                "line_count", "host_total", "span_seconds", "first_seen",
                "program_mix", "label",
            )
        elif tier == "family":
            keys = (
                "program", "line_count", "program_total", "span_seconds", "first_seen",
            )
        elif tier == "reboot":
            keys = ("label", "signal_count", "host_total")
        elif tier == "transaction":
            keys = (
                "label", "member_count", "represented_line_count",
                "host_total", "span_seconds", "first_seen", "program_mix",
            )
        else:  # isolated rare row
            keys = (
                "template_str", "host", "program_total", "count", "threshold",
                "first_seen",
            )
    elif det == "auth":
        keys = (
            "severity_basis",
            "decision_record_count",
            "denial_count",
            "host_count",
            "first_seen",
            "span_seconds",
            "window_coverage_pct",
            "window_spanning",
        )
    elif det == "scan":
        keys = ("scan_state_ratio", "top_states", "direction", "pattern_tag")
    elif det == "exfil":
        keys = (
            "destination_count",
            "orig_bytes_total", "resp_bytes_total", "orig_share",
            "connection_count", "span_seconds", "max_duration_seconds",
            "port_mix", "first_seen", "last_seen",
        )
    elif det == "ssl":
        # severity_basis is ALWAYS carried: it is never empty on an ssl finding
        # (a finding exists because a leg fired), and it is what a machine
        # consumer keys on instead of sniffing severity.
        keys = (
            "severity_basis", "conn_count", "validation_status", "tuple",
            "port_mix", "first_seen",
        )
        always_keys = ("severity_basis",)
    elif det == "aws":
        tier = ev.get("tier")
        if tier == "burst":
            keys = ("new_actions", "new_services", "error_rate", "mean_rarity")
        else:  # ranked / ranked_summary
            keys = (
                "composite_z", "z_error_rate", "event_count",
                "top_actions", "distinct_event_source",
            )

    out = {
        k: ev[k]
        for k in keys
        if k in ev and (k in always_keys or not is_empty(ev[k]))
    }
    if det == "dnsblock":
        if ev.get("kind") == "arrival_fold" and ev.get("shares_available"):
            ordered: dict[str, Any] = {}
            for key, value in out.items():
                ordered[key] = value
                if key == "member_count":
                    ordered["attributed_share"] = (
                        f"{ev['attributed_share_num']}/{ev['attributed_share_den']}"
                    )
                    ordered["query_share"] = (
                        f"{ev['query_share_num']}/{ev['query_share_den']}"
                    )
            out = ordered
        block = int(ev.get("gravity_blocked", 0)) + int(ev.get("regex_blocked", 0))
        total = block + int(ev.get("forwarded", 0)) + int(ev.get("cached", 0))
        if ev.get("kind") in ("arrival", "burst", "arrival_fold") and total > 0:
            out["block_ratio"] = round(block / total, 4)
    # Cap the burst action/service lists at level 1 so a broad sweep (dozens of
    # actions across dozens of services) stays readable; -vv keeps the full list.
    if det == "aws" and ev.get("tier") == "burst":
        for key in ("new_actions", "new_services"):
            if isinstance(out.get(key), (list, tuple)):
                out[key] = cap_evidence_list(out[key])
    # syslog aggregate program_mix is list[[name, count]] (lossless json shape); the
    # human worklist / verbose cell stringifies it so it reads "sshd (12), …"
    # instead of a flattened "sshd,12,…" - mirrors the aws list post-step above.
    if (
        det == "syslog"
        and ev.get("tier") in ("burst", "transaction")
        and isinstance(out.get("program_mix"), (list, tuple))
    ):
        out["program_mix"] = ", ".join(
            f"{name} ({count})" for name, count in out["program_mix"]
        )
    return out


def is_empty(value: Any) -> bool:
    """numpy-safe emptiness test for curated evidence values.

    The naive ``value not in (None, [], {})`` idiom evaluates ``value == []``
    which a numpy scalar broadcasts into an empty boolean array; ``bool()`` of
    that array raises ``ValueError`` and propagates straight out through
    ``reporter.write``. ``aws`` burst ``error_rate``, ``scan``
    ``scan_state_ratio`` (a rounded pandas mean), and beacon's spectral
    scores all reach this path as numpy scalars under real data -
    ``sigwood aws -v`` / ``scan -v`` died on every run.

    Guard explicitly on the container types we want to omit (None / empty
    str/list/tuple/dict). Anything else - including numpy scalars and
    arrays - is treated as "has content" for display purposes; the renderer
    formats them via the default ``f"{value}"`` path downstream.
    """
    if value is None:
        return True
    if isinstance(value, (list, tuple, dict, str)) and len(value) == 0:
        return True
    return False


def evidence_at_level(finding: Finding, level: int) -> dict[str, Any]:
    """The level-tiered evidence dict shared by text and html.

    level 0 -> ``{}`` (no evidence); level 1 -> ``curated_evidence``;
    level >= 2 -> the full ``finding.evidence``.
    """
    if level <= 0:
        return {}
    if level >= 2:
        if (
            finding.detector == "syslog"
            and finding.evidence.get("tier") == "transaction"
        ):
            # Human surfaces render transaction members as a structured
            # drilldown. Keep the same evidence full at the detector/JSON seam,
            # but do not also dump its nested list as a generic value here.
            return {
                key: value
                for key, value in finding.evidence.items()
                if key != "members"
            }
        if (
            finding.detector == "exfil"
            and finding.evidence.get("tier") == "destination_pool"
        ):
            return {
                key: value
                for key, value in finding.evidence.items()
                if key != "members"
            }
        return finding.evidence
    out = curated_evidence(finding)
    if (
        finding.detector == "syslog"
        and finding.evidence.get("tier") in ("family", "burst")
        and isinstance(finding.evidence.get("sample_raw"), (list, tuple))
    ):
        # Reading-level sample: enough to skim at -v. CSV deliberately calls
        # curated_evidence() directly and therefore never inherits raw members.
        out["sample_raw"] = list(finding.evidence["sample_raw"][:3])
    return out
