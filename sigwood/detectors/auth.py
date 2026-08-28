"""Authentication anomaly detection over the canonical system-log lane."""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pandas as pd

from sigwood.common.finding import (
    DetectorContext,
    Finding,
    MethodTag,
    Severity,
)
from sigwood.detectors import auth_core as core


DETECTOR_NAME = "auth"
STATUS = "available"
IN_DEFAULT_HUNT: bool = False
DETECTOR_METHOD = MethodTag("heuristics", named=False)
DETECTOR_MISSION: str = (
    "Finds failed logins concentrated around a source, account, service, or set "
    "of hosts, including a success after a sustained run of failures."
)

REQUIRED_LOGS: list[dict] = []

OPTIONAL_LOGS = [
    {"source": "syslog_dir", "pattern": "*.log*"},
    {"source": "journal", "pattern": "*.log*"},
    {"source": "zeek_dir", "pattern": "syslog*.log*"},
]

REQUIRES_ONE_OF_OPTIONAL = True
REQUIRES_ONE_OF_OPTIONAL_REASON = (
    "no syslog source found (need a readable system journal, syslog files, "
    "or Zeek syslog.log)"
)

DEFAULT_CONFIG: dict = {}


_LANE_ORDER = ("*.log*", "syslog*.log*")
_REQUIRED_COLUMNS = frozenset({"ts", "host", "program", "raw", "message"})
_ENTITY_SIGNAL = {
    core.EntityLens.SOURCE_VOLUME: "source_volume",
    core.EntityLens.ACCOUNT_VOLUME: "account_volume",
    core.EntityLens.HOST_SPREAD: "host_spread",
}
_SIGNAL_ORDER = {
    "concentration": 0,
    "source_volume": 1,
    "account_volume": 2,
    "host_spread": 3,
    "landing": 4,
}


@dataclass(frozen=True, slots=True)
class AuthSummaryFacts:
    """Count-only facts for runner-owned auth disclosure notes."""

    observation_count: int
    eligible_count: int
    identity_group_count: int
    service_count: int
    remote_source_count: int
    positive_window: bool


@dataclass(frozen=True, slots=True)
class _PreparedAuth:
    """Private extraction result shared by runner disclosure and detector work."""

    canonical_rows: tuple[core.CanonicalRow, ...]
    decisions: tuple[core.DecisionRow, ...]
    window: core.Window


def _text(value: Any) -> str:
    if value is None or pd.isna(value):
        return ""
    return str(value)


def _canonical_rows(context: DetectorContext) -> tuple[core.CanonicalRow, ...]:
    """Adapt normalized frames to stable in-run core rows in fixed lane order."""
    rows: list[core.CanonicalRow] = []
    for pattern in _LANE_ORDER:
        frame = context.logs.get(pattern)
        if frame is None or frame.empty:
            continue
        missing = _REQUIRED_COLUMNS - set(frame.columns)
        if missing:
            missing_text = ", ".join(sorted(missing))
            raise ValueError(f"system-log frame missing columns: {missing_text}")
        positions = {
            name: int(frame.columns.get_loc(name))
            for name in _REQUIRED_COLUMNS
        }
        for ordinal, record in enumerate(frame.itertuples(index=False, name=None)):
            try:
                timestamp = float(record[positions["ts"]])
            except (TypeError, ValueError):
                continue
            if not math.isfinite(timestamp):
                continue
            rows.append(
                core.CanonicalRow(
                    record_id=("auth", pattern, ordinal),
                    ts=timestamp,
                    host=_text(record[positions["host"]]),
                    program=_text(record[positions["program"]]),
                    raw=_text(record[positions["raw"]]),
                    message=_text(record[positions["message"]]),
                )
            )
    return tuple(rows)


def _prepare(context: DetectorContext) -> _PreparedAuth:
    """Extract once without running lenses; safe to carry into ``run`` briefly."""
    canonical_rows = _canonical_rows(context)
    window = core.Window(
        context.data_window[0].timestamp(),
        context.data_window[1].timestamp(),
        right_closed=True,
    )
    projected = core.project_decisions(canonical_rows)
    return _PreparedAuth(canonical_rows, projected, window)


def _facts(prepared: _PreparedAuth) -> AuthSummaryFacts:
    """Count disclosure magnitudes from an extracted analysis population."""
    counted = core.counted_decisions(prepared.decisions)
    eligible_count = 0
    identities: set[core.EpisodeKey] = set()
    services: set[str] = set()
    remote_sources: set[str] = set()
    for decision in counted:
        if not prepared.window.contains(decision.ts):
            continue
        eligible_count += 1
        key = core.episode_key(decision)
        if key is not None:
            identities.add(key)
        services.add(core.canonical_service(decision.gate))
        if decision.source is not None:
            remote_sources.add(decision.source)
    facts = AuthSummaryFacts(
        observation_count=sum(
            prepared.window.contains(row.ts) for row in prepared.canonical_rows
        ),
        eligible_count=eligible_count,
        identity_group_count=len(identities),
        service_count=len(services),
        remote_source_count=len(remote_sources),
        positive_window=prepared.window.end > prepared.window.start,
    )
    return facts


def summary_facts(
    context: DetectorContext,
    *,
    _prepared: _PreparedAuth | None = None,
) -> AuthSummaryFacts:
    """Return count-only post-allowlist magnitudes without running auth lenses."""
    prepared = _prepare(context) if _prepared is None else _prepared
    return _facts(prepared)


def _iso_utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def _common_evidence(
    result: core.EntityResult | core.EpisodeResult,
    signal: str,
    severity_basis: list[str],
) -> dict[str, Any]:
    return {
        "signal": signal,
        "decision_record_count": int(result.decision_record_count),
        "denial_count": int(result.denial_count),
        "host_count": int(result.host_count),
        "real_account_count": int(result.real_account_count),
        "nonexistent_account_count": int(result.nonexistent_account_count),
        "unknown_account_count": int(result.unknown_account_count),
        "live_account_count": int(result.live_account_count),
        "first_seen": _iso_utc(result.first_ts),
        "last_seen": _iso_utc(result.last_ts),
        "span_seconds": float(result.span_seconds),
        "window_coverage_pct": (
            None
            if result.window_coverage_pct is None
            else float(result.window_coverage_pct)
        ),
        "window_spanning": bool(result.window_spanning),
        "severity_basis": list(severity_basis),
    }


def _episode_identity(key: core.EpisodeKey) -> dict[str, Any]:
    host, service, fidelity = key[:3]
    evidence: dict[str, Any] = {
        "host": host,
        "service": service,
    }
    axes = ["host", "service"]
    if fidelity == "edge":
        evidence.update(
            {
                "account_namespace": key[3],
                "account": key[4],
                "source": key[5],
            }
        )
        axes.extend(("account", "source"))
    elif fidelity == "source":
        evidence["source"] = key[3]
        axes.append("source")
    elif fidelity == "actor":
        evidence.update(
            {
                "account_namespace": key[3],
                "account": key[4],
            }
        )
        axes.append("account")
    evidence["identity_axes"] = axes
    return evidence


def _edge_identity(key: core.EpisodeKey) -> tuple[str, str, str] | None:
    if len(key) == 6 and key[2] == "edge":
        return key[5], key[3], key[4]
    return None


def _landing_payload(
    episodes: list[core.EpisodeResult] | tuple[core.EpisodeResult, ...],
) -> list[dict[str, Any]]:
    payload: list[dict[str, Any]] = []
    for episode in episodes:
        host, service = episode.key[:2]
        for transition in episode.transitions:
            payload.append(
                {
                    "transition_id": transition.transition_id,
                    "host": host,
                    "service": service,
                    "failure_count": int(transition.failure_count),
                    "first_failure_at": _iso_utc(transition.first_failure_ts),
                    "success_at": _iso_utc(transition.success_ts),
                    "failure_run_ended": bool(transition.failure_run_ended),
                }
            )
    payload.sort(
        key=lambda item: (
            item["host"],
            item["service"],
            item["success_at"],
            item["transition_id"],
        )
    )
    return payload


def _account_titleable(
    namespace: str | None,
    result: core.EntityResult | core.EpisodeResult,
    *,
    has_landing: bool = False,
) -> bool:
    return bool(
        has_landing
        or result.live_account_count > 0
        or namespace == "unix_auid"
    )


def _episode_title(result: core.EpisodeResult) -> str:
    identity = _episode_identity(result.key)
    account = identity.get("account")
    namespace = identity.get("account_namespace")
    if account is not None and _account_titleable(
        namespace,
        result,
        has_landing=result.lens is core.EpisodeLens.LANDING,
    ):
        return str(account)
    if identity.get("source") is not None:
        return str(identity["source"])
    return f"{identity['host']} · {identity['service']}"


def _entity_title(
    result: core.EntityResult,
    *,
    has_landing: bool = False,
) -> str:
    if result.lens is core.EntityLens.SOURCE_VOLUME:
        return result.key[0]
    if result.lens is core.EntityLens.ACCOUNT_VOLUME:
        namespace, account = result.key
        if _account_titleable(namespace, result):
            return account
        return "high-volume authentication failures"
    source, namespace, account = result.key
    if _account_titleable(namespace, result, has_landing=has_landing):
        return account
    return source


def _description(signal: str) -> str:
    return {
        "concentration": (
            "A concentrated run of authentication failures was observed for one service."
        ),
        "source_volume": (
            "A source produced an unusually high volume of authentication failures."
        ),
        "account_volume": (
            "An account name appeared in an unusually high volume of authentication failures."
        ),
        "host_spread": (
            "The same source and account name appeared in authentication failures "
            "across multiple hosts."
        ),
        "landing": (
            "A successful authentication followed a sustained run of failures for "
            "the same service identity."
        ),
    }[signal]


def _finding(
    *,
    result: core.EntityResult | core.EpisodeResult,
    signal: str,
    severity: Severity,
    title: str,
    evidence: dict[str, Any],
    now: datetime,
    data_window: tuple[datetime, datetime],
) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        severity=severity,
        title=title,
        description=_description(signal),
        evidence=evidence,
        next_steps=[
            "Review the affected hosts and service logs",
            "Confirm whether the authentication pattern is expected",
        ],
        ts_generated=now,
        data_window=data_window,
    )


def _episode_finding(
    result: core.EpisodeResult,
    *,
    now: datetime,
    data_window: tuple[datetime, datetime],
) -> Finding:
    signal = result.lens.value
    evidence = _common_evidence(result, signal, [signal])
    evidence.update(_episode_identity(result.key))
    if result.lens is core.EpisodeLens.LANDING:
        evidence["landing_episodes"] = _landing_payload([result])
    return _finding(
        result=result,
        signal=signal,
        severity=Severity.MEDIUM,
        title=_episode_title(result),
        evidence=evidence,
        now=now,
        data_window=data_window,
    )


def _entity_finding(
    result: core.EntityResult,
    *,
    now: datetime,
    data_window: tuple[datetime, datetime],
    landings: list[core.EpisodeResult] | None = None,
) -> Finding:
    signal = _ENTITY_SIGNAL[result.lens]
    has_landing = bool(landings)
    evidence = _common_evidence(result, signal, [signal])
    if result.lens is core.EntityLens.SOURCE_VOLUME:
        evidence["source"] = result.key[0]
    elif result.lens is core.EntityLens.ACCOUNT_VOLUME:
        evidence.update(
            {
                "account_namespace": result.key[0],
                "account": result.key[1],
            }
        )
    else:
        evidence.update(
            {
                "source": result.key[0],
                "account_namespace": result.key[1],
                "account": result.key[2],
            }
        )
        if landings:
            evidence["landing_episodes"] = _landing_payload(landings)
    return _finding(
        result=result,
        signal=signal,
        severity=Severity.MEDIUM,
        title=_entity_title(result, has_landing=has_landing),
        evidence=evidence,
        now=now,
        data_window=data_window,
    )


def _add_overlap_evidence(findings: list[Finding]) -> None:
    """Cross-link co-reportable volume/spread findings at exact identities."""
    sources: dict[str, list[Finding]] = defaultdict(list)
    accounts: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    spreads: list[Finding] = []
    for finding in findings:
        evidence = finding.evidence
        signal = evidence.get("signal")
        if signal == "source_volume" and evidence.get("source") is not None:
            sources[str(evidence["source"])].append(finding)
        elif signal == "account_volume":
            namespace = evidence.get("account_namespace")
            account = evidence.get("account")
            if namespace is not None and account is not None:
                accounts[(str(namespace), str(account))].append(finding)
        elif signal == "host_spread":
            spreads.append(finding)

    related: dict[int, list[Finding]] = defaultdict(list)
    for spread in spreads:
        evidence = spread.evidence
        source = evidence.get("source")
        namespace = evidence.get("account_namespace")
        account = evidence.get("account")
        siblings = [
            *sources.get(str(source), ()),
            *accounts.get((str(namespace), str(account)), ()),
        ]
        for sibling in siblings:
            related[id(spread)].append(sibling)
            related[id(sibling)].append(spread)

    for finding in findings:
        siblings = related.get(id(finding), ())
        if not siblings:
            continue
        finding.evidence["overlaps"] = [
            {
                "signal": str(sibling.evidence["signal"]),
                "title": sibling.title,
            }
            for sibling in sorted(
                siblings,
                key=lambda item: (
                    _SIGNAL_ORDER[str(item.evidence["signal"])],
                    item.title,
                ),
            )
        ]


def _sort_key(finding: Finding) -> tuple[Any, ...]:
    severity = 0 if finding.severity is Severity.HIGH else 1
    signal = str(finding.evidence["signal"])
    identity = tuple(
        str(finding.evidence.get(key, ""))
        for key in ("host", "service", "source", "account_namespace", "account")
    )
    return severity, _SIGNAL_ORDER[signal], identity, finding.title


def run(
    context: DetectorContext,
    *,
    _prepared: _PreparedAuth | None = None,
) -> list[Finding]:
    """Project normalized system logs into reconciled authentication findings."""
    prepared = _prepare(context) if _prepared is None else _prepared
    canonical_rows = prepared.canonical_rows
    if not canonical_rows:
        return []

    decisions = prepared.decisions
    if not decisions:
        return []
    window = prepared.window
    result = core.run_lenses(decisions, canonical_rows, window)
    now = datetime.now(timezone.utc)

    landings = tuple(
        episode
        for episode in result.episode_results
        if episode.lens is core.EpisodeLens.LANDING
    )
    landing_keys = {episode.key for episode in landings}
    landings_by_identity: dict[
        tuple[str, str, str], list[core.EpisodeResult]
    ] = defaultdict(list)
    for episode in landings:
        identity = _edge_identity(episode.key)
        if identity is not None:
            landings_by_identity[identity].append(episode)

    findings: list[Finding] = []
    consumed_landings: set[core.EpisodeKey] = set()
    for episode in result.episode_results:
        if episode.lens is not core.EpisodeLens.CONCENTRATION:
            continue
        if episode.key in landing_keys:
            continue
        findings.append(
            _episode_finding(
                episode,
                now=now,
                data_window=context.data_window,
            )
        )

    for entity in result.entity_results:
        matches: list[core.EpisodeResult] | None = None
        if entity.lens is core.EntityLens.HOST_SPREAD:
            matches = landings_by_identity.get(tuple(entity.key))
            if matches:
                consumed_landings.update(episode.key for episode in matches)
        findings.append(
            _entity_finding(
                entity,
                now=now,
                data_window=context.data_window,
                landings=matches,
            )
        )

    for episode in landings:
        if episode.key not in consumed_landings:
            findings.append(
                _episode_finding(
                    episode,
                    now=now,
                    data_window=context.data_window,
                )
            )

    _add_overlap_evidence(findings)
    findings.sort(key=_sort_key)
    return findings
