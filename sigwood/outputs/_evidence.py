"""Shared reading-level policy for the human render surfaces (text + html).

``curated_evidence`` / ``is_empty`` / ``cap_evidence_list`` were MOVED here from
``text.py`` byte-identical so text and html cannot drift on *what* shows at a
level. ``evidence_at_level`` + ``level_visible`` are the two level dials both
surfaces consume.

This is output-OWNED render policy (the only shared behavioural coupling between
the human formats). It is never imported by ``detectors/`` or ``common/`` - the
detector result set stays verbosity-invariant; tiering happens here at render.
"""

from __future__ import annotations

from typing import Any

from sigwood.common.finding import Finding, Severity

# Curated (level-1) cap for long evidence LISTS. The full list still appears at
# level 2 (the debug tail renders the raw evidence dict); this only keeps `-v`
# readable when a burst touches dozens of actions/services.
_CURATED_LIST_CAP = 12


def cap_evidence_list(values: "list | tuple") -> str:
    """First N items comma-joined, then a ``… (+K more)`` overflow marker.

    Returns a STRING (the renderer prints evidence values via ``f"{v}"``, so a
    raw list would dump its Python repr - the 90-action wall this replaces)."""
    items = [str(v) for v in values]
    if len(items) <= _CURATED_LIST_CAP:
        return ", ".join(items)
    shown = ", ".join(items[:_CURATED_LIST_CAP])
    return f"{shown}, … (+{len(items) - _CURATED_LIST_CAP} more)"


# Per-detector curated-evidence subsets for level 1 - tolerant: omit absent
# keys rather than printing ``None``. Per-variant lookup uses existing
# evidence keys (scan's scan_type, dns's source, aws's tier, syslog's tier).
def curated_evidence(finding: Finding) -> dict[str, Any]:
    """Return ONLY the keys present on this Finding from the curated set for
    its detector (and variant where applicable)."""
    ev = finding.evidence
    keys: tuple[str, ...] = ()
    det = finding.detector

    if det == "beacon":
        keys = (
            "beacon_score", "spectral_ratio", "prominence_norm",
            "jitter_cv", "conn_count", "period_str",
        )
    elif det == "dns":
        src = ev.get("source")
        if "subdomain_count" in ev:  # group
            base = ("sample_domains", "unique_sources", "min_label_score", "max_label_score")
            extra = ("was_blocked", "block_ratio", "qtype_counts") if src == "pihole" else ()
            keys = base + extra
        elif src == "pihole":  # pihole singleton
            keys = (
                "unique_sources", "querier_ips",
                "was_blocked", "block_ratio",
                "cache_ratio", "forward_ratio", "qtype_counts",
            )
        else:  # zeek singleton (and both-mode Zeek with pihole enrichment)
            base = ("rcode_distribution", "unique_sources", "querier_ips")
            extra = ("was_blocked", "block_ratio") if "was_blocked" in ev else ()
            keys = base + extra
    elif det == "syslog":
        tier = ev.get("tier")
        if tier == "burst":
            keys = ("line_count", "span_seconds", "program_mix", "label")
        elif tier == "family":
            keys = ("program", "line_count", "span_seconds")
        elif tier == "reboot":
            keys = ("label", "signal_count")
        else:  # isolated rare row
            keys = ("template_str", "host", "count", "threshold")
    elif det == "scan":
        keys = ("scan_state_ratio", "top_states", "direction", "pattern_tag")
    elif det == "duration":
        keys = ("avg_bytes_per_second", "conn_states", "connection_count")
    elif det == "aws":
        tier = ev.get("tier")
        if tier == "burst":
            keys = ("new_actions", "new_services", "error_rate", "mean_rarity")
        else:  # ranked / ranked_summary
            keys = (
                "composite_z", "z_error_rate", "event_count",
                "top_actions", "distinct_event_source",
            )

    out = {k: ev[k] for k in keys if k in ev and not is_empty(ev[k])}
    # Cap the burst action/service lists at level 1 so a broad sweep (dozens of
    # actions across dozens of services) stays readable; -vv keeps the full list.
    if det == "aws" and ev.get("tier") == "burst":
        for key in ("new_actions", "new_services"):
            if isinstance(out.get(key), (list, tuple)):
                out[key] = cap_evidence_list(out[key])
    # syslog burst program_mix is list[[name, count]] (lossless json shape); the
    # human worklist / verbose cell stringifies it so it reads "sshd (12), …"
    # instead of a flattened "sshd,12,…" - mirrors the aws list post-step above.
    if det == "syslog" and ev.get("tier") == "burst" and isinstance(out.get("program_mix"), (list, tuple)):
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
        return finding.evidence
    return curated_evidence(finding)


def level_visible(finding: Finding, level: int) -> bool:
    """The one finding-visibility-by-level rule, per-finding.

    Duration hides LOW findings at level 0 - this lives in the render seam,
    not the detector's ``run()``. Every other detector / finding is a
    no-op. Default ``True``.
    """
    if finding.detector == "duration" and level == 0:
        return finding.severity != Severity.LOW
    return True
