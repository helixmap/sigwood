"""Expected-port and newly-unlabeled protocol evidence from Zeek conn logs."""

from __future__ import annotations

import math
import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from importlib import resources
from numbers import Integral, Real
from types import MappingProxyType
from typing import Any

import pandas as pd

from sigwood.common.finding import DetectorContext, Finding, MethodTag, Severity
from sigwood.parsers.zeek import parse_service

DETECTOR_NAME = "protocol"
STATUS = "available"
IN_DEFAULT_HUNT = False
REQUIRED_LOGS = [{"source": "zeek_dir", "pattern": "conn*.log*"}]
OPTIONAL_LOGS: list[dict] = []
DEFAULT_CONFIG = {"min_connections": 3}
DETECTOR_METHOD = MethodTag("expectation", named=False)
DETECTOR_MISSION = (
    "Looks for a connection whose protocol does not match the port it used, and for a port "
    "that is normally labeled starting to carry traffic Zeek could not label. You decide how "
    "many connections a pair needs before it counts."
)

_PROTOCOL_FOLD_COUNT = 4
_RARE_SHARE = 0.001
_RARE_DAYS = 2
_REFERENCE_FLOOR = 100
_REFERENCE_LABELED_SHARE = 0.999
_TABLE_VERSION = "v8.2.1"
_TABLE_SHA256 = "ee151e5313b8ba7711e56d3209ce3157b14bbe65ceaffa953fa6159290ec590a"
_QUALITY_FLAGS = (
    "_source_has_service",
    "_source_has_history",
    "_source_has_missed_bytes",
    "_source_has_orig_pkts",
    "_source_has_resp_pkts",
    "_source_has_orig_ip_bytes",
    "_source_has_resp_ip_bytes",
)
_EXCLUDED_HISTORY = frozenset("gGcCxX")
_REQUIRED_HISTORY = frozenset("ShDd")
_ENTRY_RE = re.compile(
    r"^(?P<service>[a-z0-9_-]+)\s+(?P<port>[1-9][0-9]*)/"
    r"(?P<proto>tcp|udp)\s+# tier=(?P<tier>registered|conventional)"
    r"(?: reason=(?P<reason>.+))?$"
)
_FLAG_RE = re.compile(
    r"^# flag service=(?P<service>[a-z0-9_-]+) "
    r"kind=(?P<kind>negotiated|encapsulation|dependent_on)"
    r"(?: values=(?P<values>[a-z0-9_,-]+))?$"
)


def validate_config(cfg: dict) -> None:
    if not isinstance(cfg, dict):
        raise ValueError("[detectors.protocol] must be a table")
    value = cfg.get("min_connections", DEFAULT_CONFIG["min_connections"])
    if isinstance(value, bool) or not isinstance(value, Integral) or value < 1:
        raise ValueError("[detectors.protocol].min_connections must be a positive integer")


@dataclass(frozen=True)
class ServiceTable:
    registered: Mapping[tuple[str, str], frozenset[int]]
    conventional: Mapping[tuple[str, str], frozenset[int]]
    reasons: Mapping[tuple[str, str, int], str]
    flags: Mapping[str, Mapping[str, tuple[str, ...]]]


@dataclass(slots=True)
class PreparedRow:
    identity: tuple[str, str, int, str] | None
    ts: datetime | None
    confirmed: tuple[str, ...]
    removed: tuple[str, ...]
    outcomes: dict[str, str]
    position: int
    orig_bytes: object
    resp_bytes: object
    history: str
    quality: bool


def _table_text() -> str:
    return (resources.files("sigwood") / "data" / "services").read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def load_service_table() -> ServiceTable:
    text = _table_text()
    registered: dict[tuple[str, str], set[int]] = {}
    conventional: dict[tuple[str, str], set[int]] = {}
    reasons: dict[tuple[str, str, int], str] = {}
    flags: dict[str, dict[str, tuple[str, ...]]] = {}
    seen: set[tuple[str, str, int, str]] = set()
    port_tiers: dict[tuple[str, str, int], str] = {}
    for line in text.splitlines():
        if not line or line.startswith("# sigwood") or line.startswith("# zeek_tag=") or \
                line.startswith("# generated_on=") or line.startswith("# generator=") or \
                line.startswith("# fields:") or line.startswith("# flags:"):
            continue
        flag = _FLAG_RE.fullmatch(line)
        if flag:
            values = tuple(filter(None, (flag.group("values") or "").split(",")))
            service, kind = flag.group("service"), flag.group("kind")
            prior = flags.setdefault(service, {}).get(kind)
            if prior is not None and prior != values:
                raise ValueError(f"contradictory protocol service-table flag: {line!r}")
            flags[service][kind] = values
            continue
        entry = _ENTRY_RE.fullmatch(line)
        if not entry:
            raise ValueError(f"invalid protocol service-table line: {line!r}")
        service, proto = entry.group("service"), entry.group("proto")
        port, tier = int(entry.group("port")), entry.group("tier")
        identity = (service, proto, port, tier)
        if identity in seen:
            raise ValueError(f"duplicate protocol service-table row: {line!r}")
        seen.add(identity)
        port_identity = (service, proto, port)
        prior_tier = port_tiers.get(port_identity)
        if prior_tier is not None and prior_tier != tier:
            raise ValueError(f"contradictory protocol service-table row: {line!r}")
        port_tiers[port_identity] = tier
        target = registered if tier == "registered" else conventional
        target.setdefault((service, proto), set()).add(port)
        reason = entry.group("reason")
        if tier == "conventional":
            if not reason:
                raise ValueError(f"conventional protocol row lacks a reason: {line!r}")
            reasons[(service, proto, port)] = reason
        elif reason:
            raise ValueError(f"registered protocol row carries a reason: {line!r}")
    return ServiceTable(
        MappingProxyType({key: frozenset(value) for key, value in registered.items()}),
        MappingProxyType({key: frozenset(value) for key, value in conventional.items()}),
        MappingProxyType(reasons),
        MappingProxyType({key: MappingProxyType(value) for key, value in flags.items()}),
    )


def _true(value: object) -> bool:
    return value is True or (type(value).__name__ == "bool_" and bool(value))


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _number(value: object, *, positive: bool = False) -> float | None:
    if isinstance(value, bool) or not isinstance(value, Real):
        return None
    result = float(value)
    if not math.isfinite(result) or result < 0 or (positive and result <= 0):
        return None
    return result


def _port(value: object) -> int | None:
    number = _number(value)
    if number is None or not number.is_integer():
        return None
    result = int(number)
    return result if 0 < result <= 65535 else None


def _timestamp(value: object) -> datetime | None:
    if isinstance(value, Real) and not isinstance(value, bool):
        numeric = float(value)
        if not math.isfinite(numeric):
            return None
        try:
            return datetime.fromtimestamp(numeric, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    try:
        stamp = pd.to_datetime(value, utc=True, errors="coerce")
    except (TypeError, ValueError, OverflowError):
        return None
    if pd.isna(stamp):
        return None
    return stamp.to_pydatetime()


def _identity(row: dict[str, Any]) -> tuple[str, str, int, str] | None:
    src, dst = _text(row.get("src")), _text(row.get("dst"))
    port, proto = _port(row.get("port")), _text(row.get("proto"))
    if src is None or dst is None or port is None or proto not in {"tcp", "udp"}:
        return None
    return src, dst, port, proto


def _expected(table: ServiceTable, label: str, proto: str) -> tuple[frozenset[int], frozenset[int]]:
    key = (label, proto)
    return table.registered.get(key, frozenset()), table.conventional.get(key, frozenset())


def classify_labels(
    confirmed: tuple[str, ...], row: dict[str, Any], table: ServiceTable | None = None
) -> tuple[dict[str, str], str | None]:
    """Classify each confirmed label or return one structural non-evaluable reason."""
    table = table or load_service_table()
    identity = _identity(row)
    if identity is None:
        return {}, "service-not-supplied"
    _src, _dst, responder_port, proto = identity
    history = _text(row.get("history")) or ""
    if "^" in history and confirmed:
        originator_port = _port(row.get("orig_port"))
        if originator_port is None:
            return {}, "role-inversion-unavailable"
        for label in confirmed:
            registered, conventional = _expected(table, label, proto)
            expected = registered | conventional
            if originator_port in expected and responder_port not in expected:
                return {}, "role-inverted"

    outcomes: dict[str, str] = {}
    confirmed_set = set(confirmed)
    for label in confirmed:
        registered, conventional = _expected(table, label, proto)
        if responder_port in registered:
            outcomes[label] = "registered"
            continue
        if responder_port in conventional:
            outcomes[label] = "conventional-only"
            continue
        label_flags = table.flags.get(label, {})
        carriers = label_flags.get("dependent_on", ())
        carrier_matches = False
        for carrier in carriers:
            if carrier not in confirmed_set:
                continue
            carrier_registered, carrier_conventional = _expected(table, carrier, proto)
            if responder_port in carrier_registered | carrier_conventional:
                carrier_matches = True
                break
        if carrier_matches:
            outcomes[label] = "dependent-exempt"
            continue
        if (not registered and not conventional) or any(
            key in label_flags for key in ("negotiated", "encapsulation")
        ):
            outcomes[label] = "unavailable"
            continue
        carrier_ports: set[int] = set()
        for carrier in carriers:
            carrier_registered, carrier_conventional = _expected(table, carrier, proto)
            carrier_ports.update(carrier_registered | carrier_conventional)
        if carriers and not confirmed_set.intersection(carriers) and responder_port in carrier_ports:
            outcomes[label] = "ambiguous"
            continue
        outcomes[label] = "off-expectation"
    return outcomes, None


def _leg_b_quality(row: dict[str, Any]) -> tuple[bool, bool]:
    """Return (quality-clean, all measurement inputs source-supplied)."""
    supplied = all(_true(row.get(flag)) for flag in _QUALITY_FLAGS)
    if not supplied:
        return False, False
    history = _text(row.get("history")) or ""
    quality = (
        row.get("proto") == "tcp"
        and row.get("conn_state") == "SF"
        and _number(row.get("bytes"), positive=True) is not None
        and _number(row.get("resp_bytes"), positive=True) is not None
        and _number(row.get("missed_bytes")) == 0
        and _number(row.get("orig_pkts")) is not None
        and _number(row.get("resp_pkts")) is not None
        and _number(row.get("orig_ip_bytes")) is not None
        and _number(row.get("resp_ip_bytes")) is not None
        and _REQUIRED_HISTORY.issubset(history)
        and not _EXCLUDED_HISTORY.intersection(history)
        and not row.get("_removed", ())
    )
    return quality, True


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _severity_for(*, conventional: bool = False, rare: bool = False, unlabeled: bool = False) -> tuple[Severity, str]:
    if unlabeled:
        return Severity.MEDIUM, "unlabeled-payload"
    return (Severity.MEDIUM if rare and not conventional else Severity.LOW), "port-mismatch"


def _next_steps(dst: str, port: int, proto: str, *, low: bool) -> list[str]:
    steps = [f"Check what listens on {port}/{proto} at {shlex.quote(dst)}"]
    if low:
        steps.append(
            'If this pair is yours, add a scoped allowlist stanza: `[[allowlist.entry]]` with '
                '`match = "ip_pair"` (or `"dst_port"`) and `detectors = ["protocol"]`, which '
                'suppresses it for this detector only; a flat `connections` line would remove it '
                'from every detector'
        )
    return steps


def _leg_a_findings(rows: list[PreparedRow], context: DetectorContext, minimum: int) -> tuple[list[Finding], int]:
    eligible = [row for row in rows if row.outcomes]
    norm_port: dict[tuple[tuple[str, ...], str, int], int] = {}
    norm_total: dict[tuple[tuple[str, ...], str], int] = {}
    norm_days: dict[tuple[tuple[str, ...], str, int], set] = {}
    for row in eligible:
        _src, _dst, port, proto = row.identity  # type: ignore[misc]
        service_set = row.confirmed
        norm_port[(service_set, proto, port)] = norm_port.get((service_set, proto, port), 0) + 1
        norm_total[(service_set, proto)] = norm_total.get((service_set, proto), 0) + 1
        norm_days.setdefault((service_set, proto, port), set()).add(row.ts.date())  # type: ignore[union-attr]

    groups: dict[tuple, list[dict[str, Any]]] = {}
    for row in eligible:
        outcomes = row.outcomes
        off = tuple(sorted(label for label, outcome in outcomes.items() if outcome == "off-expectation"))
        conventional = tuple(sorted(label for label, outcome in outcomes.items() if outcome == "conventional-only"))
        surfaced = off or conventional
        if not surfaced:
            continue
        src, dst, port, proto = row.identity  # type: ignore[misc]
        key = (src, dst, port, proto, row.confirmed, row.removed)
        groups.setdefault(key, []).append(row)

    findings: list[Finding] = []
    below = 0
    now = datetime.now(tz=timezone.utc)
    table = load_service_table()
    for key, members in groups.items():
        if len(members) < minimum:
            below += 1
            continue
        src, dst, port, proto, confirmed, removed = key
        outcomes = members[0].outcomes
        off = tuple(sorted(label for label, outcome in outcomes.items() if outcome == "off-expectation"))
        conventional_labels = tuple(sorted(label for label, outcome in outcomes.items() if outcome == "conventional-only"))
        mismatched = off or conventional_labels
        conventional_pair = not off and bool(conventional_labels)
        port_count = norm_port[(confirmed, proto, port)]
        share = port_count / norm_total[(confirmed, proto)]
        days = len(norm_days[(confirmed, proto, port)])
        rare = share < _RARE_SHARE and days < _RARE_DAYS
        severity, basis = _severity_for(conventional=conventional_pair, rare=rare)
        expected_ports: dict[str, list[int]] = {}
        conventional_ports: dict[str, list[int]] = {}
        descriptions: list[str] = []
        for label in confirmed:
            registered, conventional = _expected(table, label, proto)
            if registered:
                expected_ports[label] = sorted(registered)
            if conventional:
                conventional_ports[label] = sorted(conventional)
        for label in mismatched:
            registered, _conventional = _expected(table, label, proto)
            named_ports = sorted(registered)
            descriptions.append(
                f"Connections labeled {label} used {port}/{proto}, where Zeek expects "
                f"{', '.join(map(str, named_ports))}."
            )
        descriptions.append(
            f"This pairing is {'rare in' if rare else 'part of'} this window's own traffic "
            f"for {','.join(confirmed)}."
        )
        first = min(member.ts for member in members)  # type: ignore[type-var]
        last = max(member.ts for member in members)  # type: ignore[type-var]
        evidence: dict[str, Any] = {
            "kind": "mismatch",
            "src": src,
            "dst": dst,
            "services": list(confirmed),
            "removed_services": list(removed),
            "mismatched_services": list(mismatched),
            "label_outcomes": dict(sorted(outcomes.items())),
            "port": port,
            "proto": proto,
            "expected_ports": expected_ports,
            "conventional_ports": conventional_ports,
            "norm_class": "rare" if rare else "routine",
            "conns": len(members),
            "orig_bytes_total": sum(_number(member.orig_bytes) or 0 for member in members),
            "resp_bytes_total": sum(_number(member.resp_bytes) or 0 for member in members),
            "window_share": share,
            "first_seen": _iso(first),
            "last_seen": _iso(last),
            "span_seconds": (last - first).total_seconds(),
            "severity_basis": basis,
        }
        if context.data_window[0].date() != context.data_window[1].date():
            evidence["days_present"] = days
        findings.append(Finding(
            detector=DETECTOR_NAME,
            severity=severity,
            title=f"{src} -> {dst}:{port}/{proto}",
            description=" ".join(descriptions),
            evidence=evidence,
            next_steps=_next_steps(dst, port, proto, low=severity is Severity.LOW),
            ts_generated=now,
            data_window=context.data_window,
        ))
    return findings, below


def _leg_b_findings(rows: list[PreparedRow], context: DetectorContext) -> list[Finding]:
    ordered = sorted(
        (row for row in rows if row.identity and row.ts),
        key=lambda row: (row.ts, row.position),
    )
    pairs_seen: set[tuple[str, str, int, str]] = set()
    reference: dict[tuple[str, int], list[int]] = {}
    findings: list[Finding] = []
    now = datetime.now(tz=timezone.utc)
    index = 0
    while index < len(ordered):
        timestamp = ordered[index].ts
        stop = index
        while stop < len(ordered) and ordered[stop].ts == timestamp:
            stop += 1
        batch = ordered[index:stop]
        candidates: dict[tuple[str, str, int, str], list[dict[str, Any]]] = {}
        for row in batch:
            identity = row.identity  # type: ignore[assignment]
            if row.quality and not row.confirmed and not row.removed and "^" not in row.history:
                candidates.setdefault(identity, []).append(row)
        for identity, members in candidates.items():
            if identity in pairs_seen:
                continue
            src, dst, port, proto = identity
            total, labeled = reference.get((proto, port), [0, 0])
            share = labeled / total if total else 0.0
            if total < _REFERENCE_FLOOR or share < _REFERENCE_LABELED_SHARE:
                continue
            severity, basis = _severity_for(unlabeled=True)
            first = min(member.ts for member in members)  # type: ignore[type-var]
            last = max(member.ts for member in members)  # type: ignore[type-var]
            evidence = {
                "kind": "unlabeled",
                "src": src,
                "dst": dst,
                "services": [],
                "removed_services": [],
                "port": port,
                "proto": proto,
                "conns": len(members),
                "eligible_unlabeled_conns": len(members),
                "eligible_first_seen": _iso(first),
                "eligible_last_seen": _iso(last),
                "reference_size": total,
                "reference_labeled_share": share,
                "first_seen": _iso(first),
                "last_seen": _iso(last),
                "span_seconds": (last - first).total_seconds(),
                "severity_basis": basis,
            }
            findings.append(Finding(
                detector=DETECTOR_NAME,
                severity=severity,
                title=f"{src} -> {dst}:{port}/{proto}",
                description=(
                    f"Connections on {port}/{proto}, a port this window labels {share:.1%} of "
                    "the time, began carrying traffic Zeek could not label, from a pair not "
                    "seen earlier in the window."
                ),
                evidence=evidence,
                next_steps=_next_steps(dst, port, proto, low=False),
                ts_generated=now,
                data_window=context.data_window,
            ))
        for row in batch:
            identity = row.identity  # type: ignore[assignment]
            pairs_seen.add(identity)
            if row.quality:
                key = (identity[3], identity[2])
                counts = reference.setdefault(key, [0, 0])
                counts[0] += 1
                if row.confirmed:
                    counts[1] += 1
        index = stop
    return findings


def _fold(findings: list[Finding], context: DetectorContext) -> list[Finding]:
    groups: dict[tuple, list[Finding]] = {}
    for finding in findings:
        ev = finding.evidence
        key = (
            tuple(ev.get("mismatched_services", ())), ev.get("port"), ev.get("proto"),
            frozenset({ev.get("severity_basis")}), finding.severity,
        )
        groups.setdefault(key, []).append(finding)
    folded: list[Finding] = []
    consumed: set[int] = set()
    now = datetime.now(tz=timezone.utc)
    for key, members in groups.items():
        if len(members) < _PROTOCOL_FOLD_COUNT:
            continue
        consumed.update(id(member) for member in members)
        services, port, proto, bases, severity = key
        label = ",".join(services) if services else "unlabeled traffic"
        folded.append(Finding(
            detector=DETECTOR_NAME,
            severity=severity,
            title=f"{label} on {port}/{proto}",
            description=(
                "These findings share one port and one basis; the count and the members are in "
                "the evidence."
            ),
            evidence={
                "kind": "rollup", "mismatched_services": list(services), "port": port,
                "proto": proto, "severity_basis": sorted(bases), "member_count": len(members),
                "members": [member.evidence for member in members],
            },
            next_steps=[], ts_generated=now, data_window=context.data_window,
        ))
    folded.extend(finding for finding in findings if id(finding) not in consumed)
    return folded


def _context_description(evidence: dict[str, Any], entity_count: int) -> str:
    if entity_count:
        return (
            f"Evaluated {evidence['labeled_rows']} labeled rows and "
            f"{evidence['unlabeled_rows']} unlabeled rows; {evidence['not_evaluable_rows']} rows "
            f"were not evaluable and {evidence['pairs_below_floor']} pair shapes were below the "
            "connection floor."
        )
    phrases: list[str] = []
    if evidence["labeled_rows"] + evidence["unlabeled_rows"] == 0:
        phrases.append("no eligible rows after filtering")
    if evidence.get("not_evaluable_reasons", {}).get("identity-invalid", 0):
        phrases.append("invalid connection identity")
    if evidence["leg_b"] == "service-not-supplied":
        phrases.append("service not supplied by this input")
    if evidence["labeled_rows"] == 0:
        phrases.append("no labeled rows")
    if evidence["labeled_rows"] and evidence["unavailable_rows"] + evidence["ambiguous_rows"] == evidence["labeled_rows"]:
        phrases.append("only unavailable or ambiguous labels")
    if evidence["labeled_rows"] and not evidence["unavailable_rows"] and not evidence["ambiguous_rows"]:
        phrases.append("all conformant")
    if evidence["leg_b"] != "evaluated":
        phrases.append("leg B not evaluable")
    description = "; ".join(phrases or ["all conformant"])
    return description[:1].upper() + description[1:] + "."


def run(context: DetectorContext) -> list[Finding]:
    cfg = {**DEFAULT_CONFIG, **context.config}
    validate_config(cfg)
    frame = context.logs.get("conn*.log*")
    if not isinstance(frame, pd.DataFrame):
        return []
    rows: list[PreparedRow] = []
    reasons = {key: 0 for key in (
        "identity-invalid", "quality-not-supplied", "role-inversion-unavailable",
        "role-inverted", "service-not-supplied",
    )}
    unavailable_rows = ambiguous_rows = labeled_rows = unlabeled_rows = 0
    affected: set[int] = set()
    any_service_supplied = any_quality_supplied = False
    table = load_service_table()
    columns = tuple(map(str, frame.columns))
    service_cache: dict[object, tuple[tuple[str, ...], tuple[str, ...]]] = {}
    class_cache: dict[tuple, tuple[dict[str, str], str | None]] = {}
    for position, values in enumerate(frame.itertuples(index=False, name=None)):
        row = dict(zip(columns, values, strict=True))
        identity = _identity(row)
        stamp = _timestamp(row.get("ts"))
        service_supplied = _true(row.get("_source_has_service"))
        any_service_supplied |= service_supplied
        service_value = row.get("service")
        cache_key = service_value if isinstance(service_value, (str, type(None))) else None
        if service_supplied:
            confirmed, removed = service_cache.setdefault(cache_key, parse_service(service_value))
        else:
            confirmed, removed = (), ()
        row["_confirmed"], row["_removed"] = confirmed, removed
        row_eligible = identity is not None and stamp is not None
        if not service_supplied:
            reasons["service-not-supplied"] += 1
            affected.add(position)
        elif row_eligible:
            if confirmed:
                labeled_rows += 1
            else:
                unlabeled_rows += 1
        else:
            reasons["identity-invalid"] += 1
            affected.add(position)
        quality, quality_supplied = _leg_b_quality(row)
        any_quality_supplied |= quality_supplied
        if not quality_supplied:
            reasons["quality-not-supplied"] += 1
            affected.add(position)
        outcomes: dict[str, str] = {}
        if service_supplied and confirmed and identity and stamp:
            history = _text(row.get("history")) or ""
            class_key = (
                confirmed, identity[2], identity[3], history,
                row.get("orig_port") if "^" in history else None,
            )
            outcomes, structural = class_cache.setdefault(
                class_key, classify_labels(confirmed, row, table)
            )
            if structural:
                reasons[structural] += 1
                affected.add(position)
            else:
                unavailable_rows += int("unavailable" in outcomes.values())
                ambiguous_rows += int("ambiguous" in outcomes.values())
        rows.append(PreparedRow(
            identity, stamp, confirmed, removed, outcomes, position,
            row.get("bytes"), row.get("resp_bytes"), _text(row.get("history")) or "", quality,
        ))

    leg_a, below = _leg_a_findings(rows, context, int(cfg["min_connections"]))
    leg_b = _leg_b_findings(rows, context) if any_service_supplied and any_quality_supplied else []
    entities = _fold(leg_a + leg_b, context)
    leg_b_state = (
        "service-not-supplied" if not any_service_supplied
        else "quality-not-supplied" if not any_quality_supplied
        else "evaluated"
    )
    evidence = {
        "kind": "context",
        "labeled_rows": labeled_rows,
        "unlabeled_rows": unlabeled_rows,
        "unavailable_rows": unavailable_rows,
        "ambiguous_rows": ambiguous_rows,
        "not_evaluable_rows": len(affected),
        "not_evaluable_reasons": reasons,
        "table_version": _TABLE_VERSION,
        "leg_b": leg_b_state,
        "pairs_below_floor": below,
    }
    entities.append(Finding(
        detector=DETECTOR_NAME,
        severity=Severity.INFO,
        title="what this run could evaluate",
        description=_context_description(evidence, len(entities)),
        evidence=evidence,
        next_steps=[],
        ts_generated=datetime.now(tz=timezone.utc),
        data_window=context.data_window,
    ))
    return entities
