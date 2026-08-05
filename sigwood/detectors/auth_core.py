"""Product-owned authentication lens core for the planned auth detector.

Producer precedence ranks independent observers, not encodings. Named and
numeric Linux-audit records are sibling encodings of one observer and therefore
share a rank. A future producer belongs in the ladder only after measurement
shows that it mirrors the higher-ranked observer instead of contributing
different events.

This module is callable product code but does not activate the planned detector.
"""

from __future__ import annotations

import hashlib
import itertools
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Sequence

from sigwood.parsers import auth as auth_parser
from sigwood.parsers.auth import AuthDecision, AuthOutcome, extract_decision
from sigwood.parsers.syslog import strip_program


CONCENTRATION_FLOOR = 100
LANDING_RUN_FLOOR = 6
FANOUT_SOURCE_FLOOR = 5
FANOUT_ACCOUNT_FLOOR = 5


RecordId = tuple[str, str, int]
EpisodeKey = tuple[str, ...]


class Producer(StrEnum):
    """Measured producer dialects that can carry counted decisions."""

    SSHD_TEXT = "sshd-text"
    PAM_TEXT = "pam-text"
    AUDISP_TYPE = "audisp-type"
    AUDIT_TYPELESS = "audit-typeless"


_PRODUCER_RANK = {
    Producer.SSHD_TEXT: 0,
    Producer.PAM_TEXT: 1,
    Producer.AUDISP_TYPE: 2,
    Producer.AUDIT_TYPELESS: 2,
}


_COUNT_RECORD_TYPES = frozenset(
    {
        (Producer.AUDISP_TYPE.value, "AVC"),
        (Producer.AUDISP_TYPE.value, "USER_AUTH"),
        (Producer.AUDISP_TYPE.value, "USER_ERR"),
        (Producer.AUDISP_TYPE.value, "USER_LOGIN"),
        (Producer.AUDIT_TYPELESS.value, "AUDIT1100"),
        (Producer.AUDIT_TYPELESS.value, "AUDIT1112"),
        (Producer.PAM_TEXT.value, "authentication-failure"),
        (Producer.PAM_TEXT.value, "failed-su"),
        (Producer.PAM_TEXT.value, "root-login-grant"),
        (Producer.PAM_TEXT.value, "sudo-grant"),
        (Producer.PAM_TEXT.value, "su-grant"),
        (Producer.SSHD_TEXT.value, "accepted"),
        (Producer.SSHD_TEXT.value, "failed-invalid-user"),
        (Producer.SSHD_TEXT.value, "failed-password"),
        (Producer.SSHD_TEXT.value, "maximum-attempts"),
    }
)


@dataclass(frozen=True, slots=True)
class CanonicalRow:
    """One canonical system-log row with stable physical identity."""

    record_id: RecordId
    ts: float
    host: str
    program: str
    raw: str
    message: str


@dataclass(frozen=True, slots=True)
class DecisionRow:
    """One eligible access decision projected for product analysis."""

    record_id: RecordId
    ts: float
    host: str
    producer: Producer
    gate: str
    outcome: str
    actor_namespace: str | None
    actor: str | None
    target: str | None
    source: str | None
    audit_type: str | None


@dataclass(frozen=True, slots=True)
class Window:
    """Half-open analysis window, optionally closed at the right edge."""

    start: float
    end: float
    right_closed: bool = False

    def contains(self, ts: float) -> bool:
        """Return whether ``ts`` falls inside this window."""
        if self.right_closed:
            return self.start <= ts <= self.end
        return self.start <= ts < self.end


@dataclass(frozen=True, slots=True)
class LensResult:
    """Aggregate output from the three planned authentication lenses."""

    concentration_keys: frozenset[EpisodeKey]
    concentration_near_miss: int
    landing_keys: frozenset[EpisodeKey]
    landing_transitions: tuple[dict[str, Any], ...]
    landing_tie_unresolved: int
    fanout_entities: frozenset[tuple[str, tuple[str, ...]]]
    fanout_source_near_miss: int
    fanout_account_near_miss: int
    eligible_count: int


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def classify_structure(row: CanonicalRow) -> tuple[str, str]:
    """Return the measured producer dialect and structural record type."""
    body = strip_program(row.message)
    audit_a = auth_parser._AUDIT_A_HEAD_RE.match(body)
    if audit_a is not None:
        return Producer.AUDISP_TYPE.value, audit_a.group("audit_type")
    audit_b = auth_parser._AUDIT_B_HEAD_RE.match(body)
    if audit_b is not None:
        return Producer.AUDIT_TYPELESS.value, audit_b.group("audit_type")

    if row.program == "sshd(pam_unix)":
        if auth_parser._LEGACY_PAM_MORE_RE.fullmatch(body):
            return Producer.PAM_TEXT.value, "authentication-failure-summary"
        if auth_parser._LEGACY_PAM_AUTH_RE.fullmatch(body):
            return Producer.PAM_TEXT.value, "authentication-failure"
        return Producer.PAM_TEXT.value, "other"

    sshd_types = (
        ("accepted", auth_parser._SSH_ACCEPT_RE),
        ("failed-invalid-user", auth_parser._SSH_FAILED_INVALID_RE),
        ("failed-password", auth_parser._SSH_FAILED_RE),
        ("invalid-user", auth_parser._SSH_INVALID_RE),
        ("maximum-attempts", auth_parser._SSH_MAX_ATTEMPTS_RE),
        ("connection-closed", auth_parser._SSH_CLOSED_RE),
        ("kex-closed", auth_parser._SSH_KEX_RE),
    )
    for record_type, pattern in sshd_types:
        if pattern.fullmatch(body):
            return Producer.SSHD_TEXT.value, record_type
    if row.program in {"sshd", "sshd-session"}:
        if row.program == "sshd" and auth_parser._MODERN_PAM_MORE_RE.fullmatch(body):
            return Producer.PAM_TEXT.value, "authentication-failure-summary"
        if auth_parser._PAM_AUTH_RE.fullmatch(body):
            return Producer.PAM_TEXT.value, "authentication-failure"
        return Producer.SSHD_TEXT.value, "other"

    pam_session = auth_parser._PAM_SESSION_RE.fullmatch(body)
    if pam_session is not None:
        return Producer.PAM_TEXT.value, f"session-{pam_session.group('state')}"
    if auth_parser._PAM_AUTH_RE.fullmatch(body):
        return Producer.PAM_TEXT.value, "authentication-failure"

    sudo = auth_parser._SUDO_PREFIX_RE.fullmatch(body)
    if sudo is not None:
        preamble, values = auth_parser._semicolon_fields(sudo.group("body"))
        if preamble == "user NOT in sudoers" or auth_parser._SUDO_PASSWORD_RE.fullmatch(
            preamble
        ):
            return Producer.PAM_TEXT.value, "sudo-denial"
        if "USER" in values and "COMMAND" in values:
            return Producer.PAM_TEXT.value, "sudo-grant"
    if row.program == "su" and auth_parser._SU_GRANT_RE.fullmatch(body):
        return Producer.PAM_TEXT.value, "su-grant"
    if auth_parser._FAILED_SU_RE.fullmatch(body):
        return Producer.PAM_TEXT.value, "failed-su"
    if row.program == "--" and auth_parser._ROOT_LOGIN_RE.fullmatch(body):
        return Producer.PAM_TEXT.value, "root-login-grant"
    if row.program in {
        "sudo",
        "su",
        "runuser",
        "kscreenlocker_greet",
        "gdm-password]",
    }:
        return Producer.PAM_TEXT.value, "other"
    return "unclassified/non-auth", "other"


def _logical_service(decision: AuthDecision) -> str:
    if decision.audit_type is None:
        return decision.gate
    executable = (decision.exe or "").strip()
    service = PurePosixPath(executable).name if executable else ""
    return service or "audit"


def project_decision(row: CanonicalRow) -> DecisionRow | None:
    """Project one canonical row into the accepted counted-decision population."""
    dialect, record_type = classify_structure(row)
    if (dialect, record_type) not in _COUNT_RECORD_TYPES:
        return None
    decision = extract_decision(row.message, program=row.program)
    if decision is None or not decision.is_eligible_decision:
        return None
    return DecisionRow(
        record_id=row.record_id,
        ts=row.ts,
        host=row.host.casefold(),
        producer=Producer(dialect),
        gate=_logical_service(decision),
        outcome=decision.outcome.value,
        actor_namespace=decision.actor_namespace,
        actor=decision.actor,
        target=decision.target,
        source=decision.source,
        audit_type=decision.audit_type,
    )


def project_decisions(rows: Sequence[CanonicalRow]) -> tuple[DecisionRow, ...]:
    """Project every eligible counted decision while preserving row order."""
    projected: list[DecisionRow] = []
    for row in rows:
        decision = project_decision(row)
        if decision is not None:
            projected.append(decision)
    return tuple(projected)


def arbitrate_producers(
    decisions: Sequence[DecisionRow],
) -> tuple[DecisionRow, ...]:
    """Keep every row from the best observer rank present per host/service."""
    best_rank: dict[tuple[str, str], int] = {}
    for decision in decisions:
        key = (decision.host.casefold(), decision.gate)
        rank = _PRODUCER_RANK[decision.producer]
        best_rank[key] = min(best_rank.get(key, rank), rank)

    return tuple(
        decision
        for decision in decisions
        if _PRODUCER_RANK[decision.producer]
        == best_rank[(decision.host.casefold(), decision.gate)]
    )


def _namespaced_actor(decision: DecisionRow) -> tuple[str, str] | None:
    if decision.actor is None:
        return None
    return decision.actor_namespace or "unscoped", decision.actor


def episode_key(decision: DecisionRow) -> EpisodeKey | None:
    """Build the host/service identity edge and its degraded forms."""
    host_gate = (decision.host.casefold(), decision.gate)
    actor = _namespaced_actor(decision)
    if actor is not None and decision.source is not None:
        return (*host_gate, "edge", actor[0], actor[1], decision.source)
    if actor is None and decision.source is not None:
        return (*host_gate, "source", decision.source)
    if actor is not None and decision.source is None:
        return (*host_gate, "actor", actor[0], actor[1])
    return None


def _key_fidelity(key: EpisodeKey) -> str:
    return key[2]


def concentration(
    decisions: Sequence[DecisionRow], window: Window
) -> tuple[frozenset[EpisodeKey], int, dict[str, int]]:
    """Return denial concentrations, the largest near miss, and key fidelity."""
    counts: Counter[EpisodeKey] = Counter()
    for decision in decisions:
        if decision.outcome != AuthOutcome.DENIED.value or not window.contains(
            decision.ts
        ):
            continue
        key = episode_key(decision)
        if key is not None:
            counts[key] += 1
    findings = frozenset(
        key for key, count in counts.items() if count >= CONCENTRATION_FLOOR
    )
    near_miss = max(
        (count for count in counts.values() if count < CONCENTRATION_FLOOR),
        default=0,
    )
    fidelity = Counter(_key_fidelity(key) for key in findings)
    return findings, near_miss, dict(sorted(fidelity.items()))


def landing(
    decisions: Sequence[DecisionRow],
    canonical_rows: Sequence[CanonicalRow],
    window: Window,
) -> tuple[frozenset[EpisodeKey], tuple[dict[str, Any], ...], int]:
    """Enumerate denial-to-grant transitions and fail closed on ties."""
    grouped: dict[EpisodeKey, list[DecisionRow]] = defaultdict(list)
    for decision in decisions:
        if not window.contains(decision.ts):
            continue
        key = episode_key(decision)
        if key is not None:
            grouped[key].append(decision)

    host_times: dict[str, list[float]] = defaultdict(list)
    for row in canonical_rows:
        if window.contains(row.ts):
            host_times[row.host.casefold()].append(row.ts)
    for values in host_times.values():
        values.sort()

    finding_keys: set[EpisodeKey] = set()
    transitions: list[dict[str, Any]] = []
    tie_count = 0
    for key in sorted(grouped):
        ordered = sorted(grouped[key], key=lambda decision: decision.ts)
        denial_run: list[DecisionRow] = []
        for timestamp, batch_iter in itertools.groupby(
            ordered, key=lambda decision: decision.ts
        ):
            batch = list(batch_iter)
            denials = [
                decision
                for decision in batch
                if decision.outcome == AuthOutcome.DENIED.value
            ]
            grants = [
                decision
                for decision in batch
                if decision.outcome == AuthOutcome.GRANTED.value
            ]
            if not grants:
                denial_run.extend(denials)
                continue
            candidate_run = [*denial_run, *denials]
            if len(candidate_run) < LANDING_RUN_FLOOR:
                denial_run = []
                continue
            transition_rows = sorted(
                [*candidate_run, *grants], key=lambda item: item.record_id
            )
            transition_id = hashlib.sha256(
                _json_bytes([list(item.record_id) for item in transition_rows])
            ).hexdigest()[:20]
            record_ids = [list(item.record_id) for item in transition_rows]
            if denials:
                tie_count += 1
                transitions.append(
                    {
                        "transition_id": transition_id,
                        "status": "tie-unresolved",
                        "run_length": len(candidate_run),
                        "cessation": False,
                        "record_ids": record_ids,
                    }
                )
                denial_run = []
                continue
            finding_keys.add(key)
            later_key_denial = any(
                later.outcome == AuthOutcome.DENIED.value and later.ts > timestamp
                for later in ordered
            )
            later_host_row = any(
                ts > timestamp
                for ts in host_times.get(grants[0].host.casefold(), ())
            )
            transitions.append(
                {
                    "transition_id": transition_id,
                    "status": "established",
                    "run_length": len(candidate_run),
                    "cessation": bool(not later_key_denial and later_host_row),
                    "record_ids": record_ids,
                }
            )
            denial_run = []
    return frozenset(finding_keys), tuple(transitions), tie_count


def fanout(
    decisions: Sequence[DecisionRow], window: Window
) -> tuple[frozenset[tuple[str, tuple[str, ...]]], int, int]:
    """Return source/account fan-out entities and their largest near misses."""
    source_accounts: dict[str, set[tuple[str, str]]] = defaultdict(set)
    account_sources: dict[tuple[str, str], set[str]] = defaultdict(set)
    for decision in decisions:
        if decision.outcome != AuthOutcome.DENIED.value or not window.contains(
            decision.ts
        ):
            continue
        actor = _namespaced_actor(decision)
        if actor is None or decision.source is None:
            continue
        source_accounts[decision.source].add(actor)
        account_sources[actor].add(decision.source)

    entities: set[tuple[str, tuple[str, ...]]] = set()
    for source, actors in source_accounts.items():
        if len(actors) >= FANOUT_SOURCE_FLOOR:
            entities.add(("source", (source,)))
    for actor, sources in account_sources.items():
        if len(sources) >= FANOUT_ACCOUNT_FLOOR:
            entities.add(("account", actor))
    source_near = max(
        (
            len(actors)
            for actors in source_accounts.values()
            if len(actors) < FANOUT_SOURCE_FLOOR
        ),
        default=0,
    )
    account_near = max(
        (
            len(sources)
            for sources in account_sources.values()
            if len(sources) < FANOUT_ACCOUNT_FLOOR
        ),
        default=0,
    )
    return frozenset(entities), source_near, account_near


def run_lenses(
    decisions: Sequence[DecisionRow],
    canonical_rows: Sequence[CanonicalRow],
    window: Window,
) -> LensResult:
    """Arbitrate producers once, then run every lens on one population."""
    arbitrated = arbitrate_producers(decisions)
    concentration_keys, concentration_near, _fidelity = concentration(
        arbitrated, window
    )
    landing_keys, transitions, tie_count = landing(
        arbitrated, canonical_rows, window
    )
    fanout_entities, source_near, account_near = fanout(arbitrated, window)
    return LensResult(
        concentration_keys=concentration_keys,
        concentration_near_miss=concentration_near,
        landing_keys=landing_keys,
        landing_transitions=transitions,
        landing_tie_unresolved=tie_count,
        fanout_entities=fanout_entities,
        fanout_source_near_miss=source_near,
        fanout_account_near_miss=account_near,
        eligible_count=sum(
            1 for decision in arbitrated if window.contains(decision.ts)
        ),
    )
