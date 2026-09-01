"""Product-owned authentication lens core for the auth detector.

Counting unions the independent SSHD, PAM, and reconstructed Linux-audit
observers so one observer cannot erase another's exclusive decisions. Named
and numeric Linux-audit records remain sibling encodings of one observer and
are reconciled before that union.

The detector adapter owns finding construction; this core owns the measured lenses.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Sequence

from sigwood.parsers import auth as auth_parser
from sigwood.parsers.audit_event import extract_audit_event_id
from sigwood.parsers.auth import AuthDecision, AuthOutcome, extract_decision
from sigwood.parsers.syslog import strip_program


CONCENTRATION_FLOOR = 100
LANDING_RUN_FLOOR = 6
FANOUT_SOURCE_FLOOR = 5
FANOUT_ACCOUNT_FLOOR = 5
VOLUME_DAILY_RATE = 18
SECONDS_PER_DAY = 86_400
# Host spread detects low-volume reuse across machines; adding a volume floor
# would erase the cross-host shape this lens exists to surface.
HOST_SPREAD_FLOOR = 3


RecordId = tuple[str, str, int]
EpisodeKey = tuple[str, ...]
NamespacedActor = tuple[str, str]
LiveAccount = tuple[str, str, str]


class Producer(StrEnum):
    """Measured producer dialects that can carry counted decisions."""

    SSHD_TEXT = "sshd-text"
    PAM_TEXT = "pam-text"
    AUDISP_TYPE = "audisp-type"
    AUDIT_TYPELESS = "audit-typeless"


class EntityLens(StrEnum):
    """Entity-level authentication lenses exposed by the product core."""

    SOURCE_VOLUME = "source-volume"
    ACCOUNT_VOLUME = "account-volume"
    HOST_SPREAD = "host-spread"


class EpisodeLens(StrEnum):
    """Episode-keyed authentication lenses exposed to the detector."""

    CONCENTRATION = "concentration"
    LANDING = "landing"


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
    audit_event_id: str | None = None


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
class EntityResult:
    """One firing entity and the evidence facts needed by the detector."""

    lens: EntityLens
    key: tuple[str, ...]
    denial_count: int
    real_account_count: int
    nonexistent_account_count: int
    unknown_account_count: int
    live_account_count: int
    host_count: int
    decision_record_count: int
    first_ts: float
    last_ts: float
    span_seconds: float
    window_coverage_pct: float | None
    window_spanning: bool


@dataclass(frozen=True, slots=True)
class LandingTransition:
    """One established failure-to-success transition owned by an episode."""

    transition_id: str
    episode_key: EpisodeKey
    failure_count: int
    first_failure_ts: float
    success_ts: float
    failure_run_ended: bool


@dataclass(frozen=True, slots=True)
class EpisodeResult:
    """One firing episode and its uniform detector-facing evidence facts."""

    lens: EpisodeLens
    key: EpisodeKey
    denial_count: int
    real_account_count: int
    nonexistent_account_count: int
    unknown_account_count: int
    live_account_count: int
    host_count: int
    decision_record_count: int
    first_ts: float
    last_ts: float
    span_seconds: float
    window_coverage_pct: float | None
    window_spanning: bool
    transitions: tuple[LandingTransition, ...] = ()


@dataclass(frozen=True, slots=True)
class FiringFacts:
    """Uniform aggregate facts computed once at an exact firing grain."""

    decision_record_count: int
    denial_count: int
    real_account_count: int
    nonexistent_account_count: int
    unknown_account_count: int
    live_account_count: int
    host_count: int
    first_ts: float
    last_ts: float
    span_seconds: float
    window_coverage_pct: float | None
    window_spanning: bool


@dataclass(frozen=True, slots=True)
class LensResult:
    """Aggregate output from the authentication lenses."""

    concentration_keys: frozenset[EpisodeKey]
    concentration_near_miss: int
    landing_keys: frozenset[EpisodeKey]
    landing_transitions: tuple[dict[str, Any], ...]
    landing_tie_unresolved: int
    fanout_entities: frozenset[tuple[str, tuple[str, ...]]]
    fanout_source_near_miss: int
    fanout_account_near_miss: int
    eligible_count: int
    entity_results: tuple[EntityResult, ...] = ()
    live_accounts: frozenset[LiveAccount] = frozenset()
    episode_results: tuple[EpisodeResult, ...] = ()


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
        audit_event_id=extract_audit_event_id(row.message),
    )


def project_decisions(rows: Sequence[CanonicalRow]) -> tuple[DecisionRow, ...]:
    """Project every eligible counted decision while preserving row order."""
    projected: list[DecisionRow] = []
    for row in rows:
        decision = project_decision(row)
        if decision is not None:
            projected.append(decision)
    return tuple(projected)


def canonical_service(gate: str) -> str:
    """Return only the closed service aliases registered for reconciliation."""
    token = gate.casefold()
    if token in {"sshd", "sshd-session", "dropbear"}:
        return "ssh"
    if token in {"sudo", "su", "runuser", "login", "audit"}:
        return token
    return gate


def _canonical_audit_type(audit_type: str | None) -> str | None:
    """Reconcile the two fixed numeric/named eligible audit equivalents."""
    return {
        "AUDIT1100": "USER_AUTH",
        "AUDIT1112": "USER_LOGIN",
    }.get(audit_type, audit_type)


def _count_key(decision: DecisionRow) -> tuple[object, ...]:
    return (
        decision.host.casefold(),
        canonical_service(decision.gate),
        decision.outcome,
        decision.actor_namespace,
        decision.actor,
        decision.target,
        decision.source,
    )


def _dedupe_audit_event_ids(
    rows: Sequence[DecisionRow],
) -> tuple[DecisionRow, ...]:
    """Suppress exact host/event-id duplicates; id-less records remain distinct."""
    seen: set[tuple[str, str]] = set()
    kept: list[DecisionRow] = []
    for row in rows:
        event_id = row.audit_event_id
        if event_id is not None:
            key = (row.host.casefold(), event_id)
            if key in seen:
                continue
            seen.add(key)
        kept.append(row)
    return tuple(kept)


def _reconciled_audit_rows(
    decisions: Sequence[DecisionRow],
) -> tuple[DecisionRow, ...]:
    """Build one all-type audit observer after dialect reconciliation."""
    groups: dict[
        tuple[tuple[object, ...], str | None],
        dict[Producer, list[DecisionRow]],
    ] = defaultdict(lambda: defaultdict(list))
    for decision in decisions:
        if decision.producer not in {
            Producer.AUDISP_TYPE,
            Producer.AUDIT_TYPELESS,
        }:
            continue
        group_key = (_count_key(decision), _canonical_audit_type(decision.audit_type))
        groups[group_key][decision.producer].append(decision)

    selected_ids: set[int] = set()
    for dialects in groups.values():
        audisp = _dedupe_audit_event_ids(dialects.get(Producer.AUDISP_TYPE, ()))
        typeless = _dedupe_audit_event_ids(
            dialects.get(Producer.AUDIT_TYPELESS, ())
        )
        winner = audisp if len(audisp) >= len(typeless) else typeless
        selected_ids.update(id(row) for row in winner)
    return tuple(row for row in decisions if id(row) in selected_ids)


def _observer_streams(
    decisions: Sequence[DecisionRow],
) -> tuple[tuple[int, tuple[DecisionRow, ...]], ...]:
    """Return coherent text/PAM/audit streams in observer-rank order."""
    return (
        (
            _PRODUCER_RANK[Producer.SSHD_TEXT],
            tuple(row for row in decisions if row.producer is Producer.SSHD_TEXT),
        ),
        (
            _PRODUCER_RANK[Producer.PAM_TEXT],
            tuple(row for row in decisions if row.producer is Producer.PAM_TEXT),
        ),
        (
            _PRODUCER_RANK[Producer.AUDISP_TYPE],
            _reconciled_audit_rows(decisions),
        ),
    )


def counted_decisions(
    decisions: Sequence[DecisionRow],
) -> tuple[DecisionRow, ...]:
    """Union observer streams without dropping another observer's decisions."""
    selected_ids: set[int] = set()
    for _rank, stream in _observer_streams(decisions):
        selected_ids.update(id(row) for row in stream)
    return tuple(row for row in decisions if id(row) in selected_ids)


def _namespaced_actor(decision: DecisionRow) -> tuple[str, str] | None:
    if decision.actor is None:
        return None
    return decision.actor_namespace or "unscoped", decision.actor


def episode_key(decision: DecisionRow) -> EpisodeKey | None:
    """Build the host/service identity edge and its degraded forms."""
    host_gate = (decision.host.casefold(), canonical_service(decision.gate))
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

    # Both projections here reduce "is there a later X" to "is the greatest X
    # later". That is equivalent only for FINITE timestamps: max over a sequence
    # containing NaN can return NaN, and a NaN running maximum never updates
    # again, so the predicate would read False forever instead of skipping the
    # NaN as any() does. Non-finite stamps are dropped before a CanonicalRow
    # exists, and window.contains rejects them here as well. The system-log lane
    # deliberately KEEPS unparseable stamps as NaN, so those two guards are what
    # make this reduction correct rather than incidental hygiene - relaxing
    # either one silently flips cessation on some episodes, and a test using
    # finite stamps cannot show it.
    host_latest_ts: dict[str, float] = {}
    for row in canonical_rows:
        if window.contains(row.ts):
            host = row.host.casefold()
            latest = host_latest_ts.get(host)
            if latest is None or row.ts > latest:
                host_latest_ts[host] = row.ts

    finding_keys: set[EpisodeKey] = set()
    transitions: list[dict[str, Any]] = []
    tie_count = 0
    for key in sorted(grouped):
        ordered = sorted(grouped[key], key=lambda decision: decision.ts)
        # Finite-timestamp precondition as above: max is the equivalence
        # only while no decision carries NaN.
        last_key_denial_ts = max(
            (
                decision.ts
                for decision in ordered
                if decision.outcome == AuthOutcome.DENIED.value
            ),
            default=None,
        )
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
                        "episode_key": key,
                        "status": "tie-unresolved",
                        "run_length": len(candidate_run),
                        "first_failure_ts": min(
                            decision.ts for decision in candidate_run
                        ),
                        "success_ts": timestamp,
                        "cessation": False,
                        "record_ids": record_ids,
                    }
                )
                denial_run = []
                continue
            finding_keys.add(key)
            later_key_denial = bool(
                last_key_denial_ts is not None and last_key_denial_ts > timestamp
            )
            last_host_ts = host_latest_ts.get(grants[0].host.casefold())
            later_host_row = bool(
                last_host_ts is not None and last_host_ts > timestamp
            )
            transitions.append(
                {
                    "transition_id": transition_id,
                    "episode_key": key,
                    "status": "established",
                    "run_length": len(candidate_run),
                    "first_failure_ts": min(
                        decision.ts for decision in candidate_run
                    ),
                    "success_ts": timestamp,
                    "cessation": bool(not later_key_denial and later_host_row),
                    "record_ids": record_ids,
                }
            )
            denial_run = []
    return frozenset(finding_keys), tuple(transitions), tie_count


def _observer_coherent_landing(
    decisions: Sequence[DecisionRow],
    canonical_rows: Sequence[CanonicalRow],
    window: Window,
) -> tuple[
    frozenset[EpisodeKey],
    tuple[dict[str, Any], ...],
    int,
    tuple[DecisionRow, ...],
]:
    """Select one complete transition bundle per episode by observer rank."""
    winners: dict[
        EpisodeKey,
        tuple[int, tuple[dict[str, Any], ...], tuple[DecisionRow, ...]],
    ] = {}
    for rank, stream in _observer_streams(decisions):
        deduped_stream = _dedupe_audit_event_ids(stream)
        _keys, transitions, _tie_count = landing(
            deduped_stream, canonical_rows, window
        )
        transitions_by_key: dict[EpisodeKey, list[dict[str, Any]]] = defaultdict(list)
        rows_by_key: dict[EpisodeKey, list[DecisionRow]] = defaultdict(list)
        for transition in transitions:
            transitions_by_key[tuple(transition["episode_key"])].append(transition)
        for row in deduped_stream:
            if not window.contains(row.ts):
                continue
            key = episode_key(row)
            if key is not None:
                rows_by_key[key].append(row)
        for key, bundle in transitions_by_key.items():
            incumbent = winners.get(key)
            if incumbent is None or rank < incumbent[0]:
                winners[key] = (rank, tuple(bundle), tuple(rows_by_key[key]))

    finding_keys: set[EpisodeKey] = set()
    selected_transitions: list[dict[str, Any]] = []
    selected_row_ids: set[int] = set()
    tie_count = 0
    for key in sorted(winners):
        _rank, bundle, rows = winners[key]
        selected_transitions.extend(bundle)
        selected_row_ids.update(id(row) for row in rows)
        if any(transition["status"] == "established" for transition in bundle):
            finding_keys.add(key)
        tie_count += sum(
            transition["status"] == "tie-unresolved" for transition in bundle
        )

    owner_rows = tuple(row for row in decisions if id(row) in selected_row_ids)
    return (
        frozenset(finding_keys),
        tuple(selected_transitions),
        tie_count,
        owner_rows,
    )


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


def volume_floor(window: Window) -> int | None:
    """Return the duration-scaled denial floor, or ``None`` for no window."""
    duration = max(0.0, window.end - window.start)
    if duration <= 0.0:
        return None
    scaled = math.ceil(VOLUME_DAILY_RATE * duration / SECONDS_PER_DAY)
    return max(VOLUME_DAILY_RATE, scaled)


def live_accounts(
    decisions: Sequence[DecisionRow], window: Window
) -> frozenset[LiveAccount]:
    """Return namespaced accounts granted on a host inside the window."""
    accounts: set[LiveAccount] = set()
    for decision in decisions:
        if decision.outcome != AuthOutcome.GRANTED.value or not window.contains(
            decision.ts
        ):
            continue
        actor = _namespaced_actor(decision)
        if actor is not None:
            accounts.add((decision.host.casefold(), *actor))
    return frozenset(accounts)


def _covered_volume_identities(
    concentration_keys: frozenset[EpisodeKey],
) -> tuple[frozenset[str], frozenset[NamespacedActor]]:
    sources: set[str] = set()
    actors: set[NamespacedActor] = set()
    for key in concentration_keys:
        fidelity = _key_fidelity(key)
        if fidelity == "edge":
            actors.add((key[3], key[4]))
            sources.add(key[5])
        elif fidelity == "source":
            sources.add(key[3])
        elif fidelity == "actor":
            actors.add((key[3], key[4]))
    return frozenset(sources), frozenset(actors)


def _firing_facts(
    attempts: Sequence[DecisionRow],
    window: Window,
    live: frozenset[LiveAccount],
) -> FiringFacts:
    """Compute uniform facts once for one exact counted-record grain."""
    if not attempts:
        raise ValueError("firing facts require at least one attempt")
    denials = tuple(
        decision
        for decision in attempts
        if decision.outcome == AuthOutcome.DENIED.value
    )
    actors = {
        actor
        for decision in denials
        if (actor := _namespaced_actor(decision)) is not None
    }
    live_touched = {
        actor
        for decision in denials
        if (actor := _namespaced_actor(decision)) is not None
        and (decision.host.casefold(), *actor) in live
    }
    real = sum(actor[0] in {"unix_user", "unix_auid"} for actor in actors)
    nonexistent = sum(actor[0] == "preauth_username" for actor in actors)
    timestamps = [decision.ts for decision in attempts]
    first_ts = min(timestamps)
    last_ts = max(timestamps)
    span_seconds = max(0.0, last_ts - first_ts)
    window_width = max(0.0, window.end - window.start)
    window_coverage_pct = (
        None
        if window_width <= 0.0
        else round(min(100.0, 100.0 * span_seconds / window_width), 6)
    )
    return FiringFacts(
        decision_record_count=len(attempts),
        denial_count=len(denials),
        real_account_count=real,
        nonexistent_account_count=nonexistent,
        unknown_account_count=len(actors) - real - nonexistent,
        live_account_count=len(live_touched),
        host_count=len({decision.host.casefold() for decision in denials}),
        first_ts=first_ts,
        last_ts=last_ts,
        span_seconds=span_seconds,
        window_coverage_pct=window_coverage_pct,
        window_spanning=first_ts <= window.start and last_ts >= window.end,
    )


def _entity_result(
    lens: EntityLens,
    key: tuple[str, ...],
    attempts: Sequence[DecisionRow],
    window: Window,
    live: frozenset[LiveAccount],
) -> EntityResult:
    facts = _firing_facts(attempts, window, live)
    return EntityResult(
        lens=lens,
        key=key,
        denial_count=facts.denial_count,
        real_account_count=facts.real_account_count,
        nonexistent_account_count=facts.nonexistent_account_count,
        unknown_account_count=facts.unknown_account_count,
        live_account_count=facts.live_account_count,
        host_count=facts.host_count,
        decision_record_count=facts.decision_record_count,
        first_ts=facts.first_ts,
        last_ts=facts.last_ts,
        span_seconds=facts.span_seconds,
        window_coverage_pct=facts.window_coverage_pct,
        window_spanning=facts.window_spanning,
    )


def volume_entities(
    decisions: Sequence[DecisionRow],
    window: Window,
    *,
    concentration_keys: frozenset[EpisodeKey],
    live: frozenset[LiveAccount],
) -> tuple[EntityResult, ...]:
    """Return net-new source and account denial-volume entities."""
    threshold = volume_floor(window)
    if threshold is None:
        return ()

    source_groups: dict[str, list[DecisionRow]] = defaultdict(list)
    account_groups: dict[NamespacedActor, list[DecisionRow]] = defaultdict(list)
    for decision in decisions:
        if not window.contains(decision.ts):
            continue
        if decision.source is not None:
            source_groups[decision.source].append(decision)
        actor = _namespaced_actor(decision)
        if actor is not None:
            account_groups[actor].append(decision)

    covered_sources, covered_actors = _covered_volume_identities(concentration_keys)
    entities: list[EntityResult] = []
    for source in sorted(source_groups):
        attempts = source_groups[source]
        denial_count = sum(
            decision.outcome == AuthOutcome.DENIED.value
            for decision in attempts
        )
        if denial_count >= threshold and source not in covered_sources:
            entities.append(
                _entity_result(
                    EntityLens.SOURCE_VOLUME,
                    (source,),
                    attempts,
                    window,
                    live,
                )
            )
    for actor in sorted(account_groups):
        attempts = account_groups[actor]
        denial_count = sum(
            decision.outcome == AuthOutcome.DENIED.value
            for decision in attempts
        )
        if denial_count >= threshold and actor not in covered_actors:
            entities.append(
                _entity_result(
                    EntityLens.ACCOUNT_VOLUME,
                    actor,
                    attempts,
                    window,
                    live,
                )
            )
    return tuple(entities)


def host_spread_entities(
    decisions: Sequence[DecisionRow],
    window: Window,
    *,
    live: frozenset[LiveAccount],
) -> tuple[EntityResult, ...]:
    """Return source/account pairs denied across at least three hosts."""
    groups: dict[tuple[str, ...], list[DecisionRow]] = defaultdict(list)
    for decision in decisions:
        if not window.contains(decision.ts):
            continue
        actor = _namespaced_actor(decision)
        if actor is None or decision.source is None:
            continue
        groups[(decision.source, *actor)].append(decision)

    entities: list[EntityResult] = []
    for key in sorted(groups):
        attempts = groups[key]
        denials = [
            decision
            for decision in attempts
            if decision.outcome == AuthOutcome.DENIED.value
        ]
        host_count = len({decision.host.casefold() for decision in denials})
        if host_count >= HOST_SPREAD_FLOOR:
            entities.append(
                _entity_result(
                    EntityLens.HOST_SPREAD,
                    key,
                    attempts,
                    window,
                    live,
                )
            )
    return tuple(entities)


def _episode_results(
    decisions: Sequence[DecisionRow],
    window: Window,
    *,
    concentration_keys: frozenset[EpisodeKey],
    landing_keys: frozenset[EpisodeKey],
    landing_transitions: tuple[dict[str, Any], ...],
    live: frozenset[LiveAccount],
    landing_decisions: Sequence[DecisionRow] | None = None,
    landing_live: frozenset[LiveAccount] | None = None,
) -> tuple[EpisodeResult, ...]:
    """Build typed detector-facing results without recreating lens policy."""
    count_groups: dict[EpisodeKey, list[DecisionRow]] = defaultdict(list)
    for decision in decisions:
        if not window.contains(decision.ts):
            continue
        key = episode_key(decision)
        if key is not None and decision.outcome == AuthOutcome.DENIED.value:
            count_groups[key].append(decision)

    landing_groups: dict[EpisodeKey, list[DecisionRow]] = defaultdict(list)
    for decision in decisions if landing_decisions is None else landing_decisions:
        if not window.contains(decision.ts):
            continue
        key = episode_key(decision)
        if key is not None:
            landing_groups[key].append(decision)
    effective_landing_live = live if landing_live is None else landing_live

    transitions_by_key: dict[EpisodeKey, list[LandingTransition]] = defaultdict(list)
    for transition in landing_transitions:
        if transition["status"] != "established":
            continue
        key = tuple(transition["episode_key"])
        transitions_by_key[key].append(
            LandingTransition(
                transition_id=str(transition["transition_id"]),
                episode_key=key,
                failure_count=int(transition["run_length"]),
                first_failure_ts=float(transition["first_failure_ts"]),
                success_ts=float(transition["success_ts"]),
                failure_run_ended=bool(transition["cessation"]),
            )
        )
    for values in transitions_by_key.values():
        values.sort(key=lambda item: (item.success_ts, item.transition_id))

    results: list[EpisodeResult] = []
    for lens, keys in (
        (EpisodeLens.CONCENTRATION, concentration_keys),
        (EpisodeLens.LANDING, landing_keys),
    ):
        for key in sorted(keys):
            population = (
                count_groups[key]
                if lens is EpisodeLens.CONCENTRATION
                else landing_groups[key]
            )
            population_live = (
                live
                if lens is EpisodeLens.CONCENTRATION
                else effective_landing_live
            )
            facts = _firing_facts(population, window, population_live)
            results.append(
                EpisodeResult(
                    lens=lens,
                    key=key,
                    denial_count=facts.denial_count,
                    real_account_count=facts.real_account_count,
                    nonexistent_account_count=facts.nonexistent_account_count,
                    unknown_account_count=facts.unknown_account_count,
                    live_account_count=facts.live_account_count,
                    host_count=facts.host_count,
                    decision_record_count=facts.decision_record_count,
                    first_ts=facts.first_ts,
                    last_ts=facts.last_ts,
                    span_seconds=facts.span_seconds,
                    window_coverage_pct=facts.window_coverage_pct,
                    window_spanning=facts.window_spanning,
                    transitions=tuple(transitions_by_key.get(key, ())),
                )
            )
    return tuple(results)


def run_lenses(
    decisions: Sequence[DecisionRow],
    canonical_rows: Sequence[CanonicalRow],
    window: Window,
) -> LensResult:
    """Run count lenses on the observer union and landing on a coherent stream."""
    counted = counted_decisions(decisions)
    concentration_keys, concentration_near, _fidelity = concentration(
        counted, window
    )
    landing_keys, transitions, tie_count, landing_rows = _observer_coherent_landing(
        decisions, canonical_rows, window
    )
    fanout_entities, source_near, account_near = fanout(counted, window)
    live = live_accounts(counted, window)
    coherent_landing_live = live_accounts(landing_rows, window)
    entities = (
        *volume_entities(
            counted,
            window,
            concentration_keys=concentration_keys,
            live=live,
        ),
        *host_spread_entities(counted, window, live=live),
    )
    episodes = _episode_results(
        counted,
        window,
        concentration_keys=concentration_keys,
        landing_keys=landing_keys,
        landing_transitions=transitions,
        live=live,
        landing_decisions=landing_rows,
        landing_live=coherent_landing_live,
    )
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
            1 for decision in counted if window.contains(decision.ts)
        ),
        entity_results=entities,
        live_accounts=live,
        episode_results=episodes,
    )
